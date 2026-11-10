/*
 * wg_cookie - see wg_cookie.h. Written from the protocol description (wireguard.com/protocol,
 * whitepaper section 5.4.7); the timing follows the Linux implementation.
 */

#include "wg_cookie.h"

#include <string.h>

static const uint8_t LABEL_MAC1[8]   = { 'm', 'a', 'c', '1', '-', '-', '-', '-' };
static const uint8_t LABEL_COOKIE[8] = { 'c', 'o', 'o', 'k', 'i', 'e', '-', '-' };

/* wg_cookie_create_reply reads the sender index from one offset for both handshake messages. */
typedef char wg_cookie_sender_offsets_match[WG_INIT_OFF_SENDER == WG_RESP_OFF_SENDER ? 1 : -1];

/* HASH(label || static public key) */
static int derive_key(uint8_t out[WG_HASH_LEN], const uint8_t label[8], const wg_key* pub)
{
    return wg_hash2(out, label, 8, pub->b, WG_KEY_LEN);
}

/* --------------------------------------------------------------------- maker */

int wg_cookie_maker_init(wg_cookie_maker* m, const wg_key* peer_public)
{
    memset(m, 0, sizeof(*m));
    return derive_key(m->mac1_key, LABEL_MAC1, peer_public)
        && derive_key(m->cookie_key, LABEL_COOKIE, peer_public);
}

int wg_cookie_add_macs(wg_cookie_maker* m, uint8_t* msg, size_t len, uint64_t now_ns)
{
    uint8_t* mac1;
    uint8_t* mac2;

    if (len < WG_MACS_LEN) return 0;
    mac1 = msg + len - WG_MACS_LEN;
    mac2 = mac1 + WG_MAC_LEN;

    if (!wg_mac16(mac1, m->mac1_key, WG_HASH_LEN, msg, len - WG_MACS_LEN)) return 0;
    memcpy(m->last_mac1, mac1, WG_MAC_LEN);
    m->has_last_mac1 = 1;

    if (m->has_cookie
        && now_ns < m->cookie_birth_ns + WG_COOKIE_SECRET_MAX_AGE_NS - WG_COOKIE_SECRET_LATENCY_NS) {
        return wg_mac16(mac2, m->cookie, WG_COOKIE_LEN, msg, len - WG_MAC_LEN);
    }
    memset(mac2, 0, WG_MAC_LEN);
    return 1;
}

int wg_cookie_consume_reply(wg_cookie_maker* m, const uint8_t msg[WG_COOKIE_MSG_LEN], uint64_t now_ns)
{
    uint8_t cookie[WG_COOKIE_LEN];

    if (!m->has_last_mac1) return 0;
    if (!wg_xaead_decrypt(cookie, m->cookie_key, msg + WG_COOKIE_OFF_NONCE,
                          msg + WG_COOKIE_OFF_COOKIE, WG_COOKIE_LEN + WG_TAG_LEN,
                          m->last_mac1, WG_MAC_LEN)) {
        return 0;
    }
    memcpy(m->cookie, cookie, WG_COOKIE_LEN);
    m->cookie_birth_ns = now_ns;
    m->has_cookie = 1;
    m->has_last_mac1 = 0;       /* one reply per message sent */
    wg_wipe(cookie, sizeof(cookie));
    return 1;
}

/* --------------------------------------------------------------------- checker */

void wg_cookie_checker_init(wg_cookie_checker* c)
{
    memset(c, 0, sizeof(*c));
}

int wg_cookie_checker_set_key(wg_cookie_checker* c, const wg_key* local_public)
{
    c->has_key = derive_key(c->mac1_key, LABEL_MAC1, local_public)
              && derive_key(c->cookie_key, LABEL_COOKIE, local_public);
    return c->has_key;
}

/* cookie = MAC(secret, src), with the secret renewed once it is two minutes old */
static int make_cookie(wg_cookie_checker* c, uint8_t cookie[WG_COOKIE_LEN],
                       const void* src, size_t src_len, uint64_t now_ns)
{
    if (!c->has_secret || now_ns >= c->secret_birth_ns + WG_COOKIE_SECRET_MAX_AGE_NS) {
        if (!wg_rng_bytes(&c->rng, c->secret, WG_HASH_LEN)) {
            c->has_secret = 0;
            return 0;
        }
        c->secret_birth_ns = now_ns;
        c->has_secret = 1;
    }
    return wg_mac16(cookie, c->secret, WG_HASH_LEN, src, src_len);
}

wg_mac_state wg_cookie_validate(wg_cookie_checker* c, const uint8_t* msg, size_t len,
                                const void* src, size_t src_len, int check_mac2, uint64_t now_ns)
{
    uint8_t mac[WG_MAC_LEN], cookie[WG_COOKIE_LEN];
    wg_mac_state state = WG_MAC_INVALID;

    if (!c->has_key || len < WG_MACS_LEN) return WG_MAC_INVALID;

    if (!wg_mac16(mac, c->mac1_key, WG_HASH_LEN, msg, len - WG_MACS_LEN)) goto out;
    if (!wg_ct_equal(mac, msg + len - WG_MACS_LEN, WG_MAC_LEN)) goto out;
    state = WG_MAC_VALID_NO_COOKIE;

    if (!check_mac2) goto out;
    if (!make_cookie(c, cookie, src, src_len, now_ns)) goto out;
    if (!wg_mac16(mac, cookie, WG_COOKIE_LEN, msg, len - WG_MAC_LEN)) goto out;
    if (!wg_ct_equal(mac, msg + len - WG_MAC_LEN, WG_MAC_LEN)) goto out;
    state = WG_MAC_VALID_WITH_COOKIE;
out:
    wg_wipe(cookie, sizeof(cookie));
    return state;
}

int wg_cookie_create_reply(wg_cookie_checker* c, uint8_t out[WG_COOKIE_MSG_LEN],
                           const uint8_t* msg, size_t len, const void* src, size_t src_len,
                           uint64_t now_ns)
{
    uint8_t cookie[WG_COOKIE_LEN];
    int ok = 0;

    if (!c->has_key || len < WG_MACS_LEN || len < WG_INIT_OFF_SENDER + 4) return 0;

    if (!make_cookie(c, cookie, src, src_len, now_ns)) goto out;
    if (!wg_rng_bytes(&c->rng, out + WG_COOKIE_OFF_NONCE, WG_COOKIE_NONCE_LEN)) goto out;

    wg_store32(out + WG_COOKIE_OFF_TYPE, WG_MSG_COOKIE);
    wg_store32(out + WG_COOKIE_OFF_RECEIVER, wg_load32(msg + WG_INIT_OFF_SENDER));
    ok = wg_xaead_encrypt(out + WG_COOKIE_OFF_COOKIE, c->cookie_key, out + WG_COOKIE_OFF_NONCE,
                          cookie, WG_COOKIE_LEN, msg + len - WG_MACS_LEN, WG_MAC_LEN);
out:
    wg_wipe(cookie, sizeof(cookie));
    if (!ok) memset(out, 0, WG_COOKIE_MSG_LEN);
    return ok;
}
