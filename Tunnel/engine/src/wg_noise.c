/*
 * wg_noise - see wg_noise.h.
 *
 * Written from the protocol description (wireguard.com/protocol, whitepaper section 5.4); the
 * split into local / remote / upcalls follows OpenBSD's wg_noise.c (ISC). In Noise terms WireGuard
 * is plain IKpsk2 with the prologue "WireGuard v1 zx2c4 Jason@zx2c4.com", the TAI64N timestamp as
 * the initiator's payload and an empty responder payload. Every AEAD in the handshake runs under a
 * key fresh from the KDF, so its nonce is always 0.
 *
 * Each create / consume works on a COPY of the handshake and stores it back only once the whole
 * message has checked out: a message that fails halfway leaves the remote as it was.
 */

#include "wg_noise.h"

#include <string.h>

/*
 * HASH("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s") and HASH(that || "WireGuard v1 zx2c4 Jason@zx2c4.com"):
 * the chaining key and hash every handshake starts from. test_crypto recomputes both from the
 * strings, and the transcripts in test_noise depend on them byte for byte.
 */
static const uint8_t INITIAL_CK[WG_HASH_LEN] = {
    0x60, 0xe2, 0x6d, 0xae, 0xf3, 0x27, 0xef, 0xc0, 0x2e, 0xc3, 0x35, 0xe2, 0xa0, 0x25, 0xd2, 0xd0,
    0x16, 0xeb, 0x42, 0x06, 0xf8, 0x72, 0x77, 0xf5, 0x2d, 0x38, 0xd1, 0x98, 0x8b, 0x78, 0xcd, 0x36
};
static const uint8_t INITIAL_H[WG_HASH_LEN] = {
    0x22, 0x11, 0xb3, 0x61, 0x08, 0x1a, 0xc5, 0x66, 0x69, 0x12, 0x43, 0xdb, 0x45, 0x8a, 0xd5, 0x32,
    0x2d, 0x9c, 0x6c, 0x66, 0x22, 0x93, 0xe8, 0xb7, 0x0e, 0xe1, 0x9c, 0x65, 0xba, 0x07, 0x9e, 0xf3
};

/* TAI64N quantum: 2^24 ns (~16.8 ms), the power of two just under the 20 ms flood interval. */
#define TAI64N_QUANTUM_NS   (1u << 24)
#define TAI64_EPOCH_OFFSET  0x400000000000000aULL

/* --------------------------------------------------------------------- symmetric state */

/* h = HASH(h || in) */
static int mix_hash(uint8_t h[WG_HASH_LEN], const void* in, size_t len)
{
    return wg_hash2(h, h, WG_HASH_LEN, in, len);
}

/* ck = KDF1(ck, in): the "e" token, which psk mode also mixes into the chaining key */
static int mix_key(uint8_t ck[WG_HASH_LEN], const void* in, size_t len)
{
    return wg_kdf(ck, NULL, NULL, ck, in, len);
}

/* (ck, key) = KDF2(ck, DH(sk, pk)); with key == NULL just ck = KDF1(ck, DH(sk, pk)) */
static int mix_dh(uint8_t ck[WG_HASH_LEN], uint8_t* key, const wg_key* sk, const wg_key* pk)
{
    uint8_t dh[WG_KEY_LEN];
    int ok = wg_dh(sk, pk, dh) && wg_kdf(ck, key, NULL, ck, dh, sizeof(dh));
    wg_wipe(dh, sizeof(dh));
    return ok;
}

/* (ck, key) = KDF2(ck, ss) with the precomputed static-static DH */
static int mix_ss(uint8_t ck[WG_HASH_LEN], uint8_t key[WG_KEY_LEN], const wg_noise_remote* r)
{
    if (!r->ss_valid) return 0;
    return wg_kdf(ck, key, NULL, ck, r->ss, WG_KEY_LEN);
}

/* (ck, tau, key) = KDF3(ck, psk); h = HASH(h || tau) */
static int mix_psk(uint8_t ck[WG_HASH_LEN], uint8_t h[WG_HASH_LEN], uint8_t key[WG_KEY_LEN],
                   const uint8_t psk[WG_KEY_LEN])
{
    uint8_t tau[WG_HASH_LEN];
    int ok = wg_kdf(ck, tau, key, ck, psk, WG_KEY_LEN) && mix_hash(h, tau, sizeof(tau));
    wg_wipe(tau, sizeof(tau));
    return ok;
}

/* out = AEAD(key, 0, pt, h); h = HASH(h || out). `out` takes len + WG_TAG_LEN bytes. */
static int encrypt_and_hash(uint8_t* out, const uint8_t key[WG_KEY_LEN], uint8_t h[WG_HASH_LEN],
                            const void* pt, size_t len)
{
    return wg_aead_encrypt(out, key, 0, pt, len, h, WG_HASH_LEN)
        && mix_hash(h, out, len + WG_TAG_LEN);
}

/* out = AEAD-open(key, 0, ct, h); h = HASH(h || ct). `out` takes ctlen - WG_TAG_LEN bytes. */
static int decrypt_and_hash(uint8_t* out, const uint8_t key[WG_KEY_LEN], uint8_t h[WG_HASH_LEN],
                            const uint8_t* ct, size_t ctlen)
{
    return wg_aead_decrypt(out, key, 0, ct, ctlen, h, WG_HASH_LEN)
        && mix_hash(h, ct, ctlen);
}

/* A fresh handshake, with the responder's static key mixed in: IK's pre-message "<- s". */
static int handshake_start(wg_noise_handshake* hs, const wg_key* responder_static)
{
    memset(hs, 0, sizeof(*hs));
    memcpy(hs->chaining_key, INITIAL_CK, WG_HASH_LEN);
    memcpy(hs->hash, INITIAL_H, WG_HASH_LEN);
    return mix_hash(hs->hash, responder_static->b, WG_KEY_LEN);
}

/* The states in which the handshake holds an index registered with the owner. */
static int owns_index(wg_hs_state s)
{
    return s == WG_HS_CREATED_INITIATION || s == WG_HS_CREATED_RESPONSE || s == WG_HS_CONSUMED_RESPONSE;
}

/* --------------------------------------------------------------------- TAI64N */

static void store_be32(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

static uint32_t load_be32(const uint8_t* p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void store_be64(uint8_t* p, uint64_t v)
{
    store_be32(p, (uint32_t)(v >> 32));
    store_be32(p + 4, (uint32_t)v);
}

static uint64_t load_be64(const uint8_t* p)
{
    return ((uint64_t)load_be32(p) << 32) | load_be32(p + 4);
}

void wg_tai64n(uint8_t out[WG_TIMESTAMP_LEN], uint64_t unix_sec, uint32_t nsec)
{
    store_be64(out, TAI64_EPOCH_OFFSET + unix_sec);
    store_be32(out + 8, nsec & ~(TAI64N_QUANTUM_NS - 1));
}

/* `now` if it is newer than `last`, else `last` plus one quantum. Both big-endian, so memcmp orders them. */
static void next_timestamp(uint8_t out[WG_TIMESTAMP_LEN], const uint8_t now[WG_TIMESTAMP_LEN],
                           const uint8_t last[WG_TIMESTAMP_LEN])
{
    uint64_t sec;
    uint32_t nsec;

    if (memcmp(now, last, WG_TIMESTAMP_LEN) > 0) {
        memcpy(out, now, WG_TIMESTAMP_LEN);
        return;
    }
    sec = load_be64(last);
    nsec = load_be32(last + 8) + TAI64N_QUANTUM_NS;    /* last came from us: nsec < 10^9, no wrap */
    if (nsec >= 1000000000u) {
        nsec -= 1000000000u;
        sec++;
    }
    store_be64(out, sec);
    store_be32(out + 8, nsec);
}

/* --------------------------------------------------------------------- identity and peers */

void wg_noise_local_init(wg_noise_local* l)
{
    memset(l, 0, sizeof(*l));
}

int wg_noise_local_set_private_key(wg_noise_local* l, const wg_key* private_key)
{
    wg_key sk = *private_key, pk;
    int ok;

    wg_key_clamp(&sk);
    ok = wg_key_public(&sk, &pk);
    if (ok) {
        l->private_key = sk;
        l->public_key = pk;
        l->has_identity = 1;
    }
    wg_wipe(&sk, sizeof(sk));
    return ok;
}

void wg_noise_remote_init(wg_noise_remote* r, wg_noise_local* l, const wg_key* public_key)
{
    memset(r, 0, sizeof(*r));
    r->local = l;
    r->public_key = *public_key;
    wg_noise_remote_precompute(r);
}

void wg_noise_remote_set_psk(wg_noise_remote* r, const uint8_t psk[WG_KEY_LEN])
{
    if (psk) memcpy(r->psk, psk, WG_KEY_LEN);
    else     wg_wipe(r->psk, WG_KEY_LEN);
}

void wg_noise_remote_precompute(wg_noise_remote* r)
{
    wg_noise_remote_clear(r);
    r->ss_valid = r->local->has_identity && wg_dh(&r->local->private_key, &r->public_key, r->ss);
    if (!r->ss_valid) wg_wipe(r->ss, WG_KEY_LEN);
}

void wg_noise_remote_clear(wg_noise_remote* r)
{
    wg_noise_local* l = r->local;

    if (owns_index(r->hs.state) && l && l->index_drop) l->index_drop(l->ctx, r->hs.local_index);
    wg_wipe(&r->hs, sizeof(r->hs));
    r->hs.state = WG_HS_ZEROED;
}

void wg_noise_remote_wipe(wg_noise_remote* r)
{
    wg_noise_remote_clear(r);
    wg_wipe(r, sizeof(*r));
}

/* --------------------------------------------------------------------- initiation */

int wg_noise_create_initiation(wg_noise_remote* r, const uint8_t timestamp[WG_TIMESTAMP_LEN],
                               uint8_t msg[WG_INIT_LEN])
{
    wg_noise_local* l = r->local;
    wg_noise_handshake hs;
    uint8_t key[WG_KEY_LEN];
    uint8_t ts[WG_TIMESTAMP_LEN];
    wg_key e_pub;
    uint32_t index;
    int ok = 0;

    if (!l->has_identity || !r->ss_valid || !l->index_set) return 0;

    if (!handshake_start(&hs, &r->public_key)) goto out;

    /* e */
    if (!wg_key_generate_rng(&l->rng, &hs.ephemeral_private, &e_pub)) goto out;
    if (!mix_key(hs.chaining_key, e_pub.b, WG_KEY_LEN)) goto out;
    if (!mix_hash(hs.hash, e_pub.b, WG_KEY_LEN)) goto out;
    memcpy(msg + WG_INIT_OFF_EPHEMERAL, e_pub.b, WG_KEY_LEN);

    /* es */
    if (!mix_dh(hs.chaining_key, key, &hs.ephemeral_private, &r->public_key)) goto out;

    /* s */
    if (!encrypt_and_hash(msg + WG_INIT_OFF_STATIC, key, hs.hash, l->public_key.b, WG_KEY_LEN)) goto out;

    /* ss */
    if (!mix_ss(hs.chaining_key, key, r)) goto out;

    /* payload: the timestamp */
    next_timestamp(ts, timestamp, r->sent_timestamp);
    if (!encrypt_and_hash(msg + WG_INIT_OFF_TIMESTAMP, key, hs.hash, ts, WG_TIMESTAMP_LEN)) goto out;

    /* The index comes last, so no failure above can leak one. The sender index is not part of
     * the Noise transcript at all - only mac1 covers it. */
    if (!l->index_set(l->ctx, r, &index)) goto out;

    wg_noise_remote_clear(r);
    hs.state = WG_HS_CREATED_INITIATION;
    hs.local_index = index;
    r->hs = hs;
    memcpy(r->sent_timestamp, ts, WG_TIMESTAMP_LEN);

    wg_store32(msg + WG_INIT_OFF_TYPE, WG_MSG_INITIATION);
    wg_store32(msg + WG_INIT_OFF_SENDER, index);
    memset(msg + WG_INIT_OFF_MAC1, 0, WG_MACS_LEN);
    ok = 1;
out:
    wg_wipe(&hs, sizeof(hs));
    wg_wipe(key, sizeof(key));
    if (!ok) memset(msg, 0, WG_INIT_LEN);
    return ok;
}

int wg_noise_consume_initiation(wg_noise_local* l, const uint8_t msg[WG_INIT_LEN], uint64_t now_ns,
                                wg_noise_remote** rp)
{
    wg_noise_remote* r;
    wg_noise_handshake hs;
    uint8_t key[WG_KEY_LEN];
    uint8_t ts[WG_TIMESTAMP_LEN];
    wg_key s_pub;
    int ok = 0;

    *rp = NULL;
    if (!l->has_identity || !l->remote_get) return 0;

    if (!handshake_start(&hs, &l->public_key)) goto out;

    /* e */
    memcpy(hs.remote_ephemeral.b, msg + WG_INIT_OFF_EPHEMERAL, WG_KEY_LEN);
    if (!mix_key(hs.chaining_key, hs.remote_ephemeral.b, WG_KEY_LEN)) goto out;
    if (!mix_hash(hs.hash, hs.remote_ephemeral.b, WG_KEY_LEN)) goto out;

    /* es */
    if (!mix_dh(hs.chaining_key, key, &l->private_key, &hs.remote_ephemeral)) goto out;

    /* s: who is this? */
    if (!decrypt_and_hash(s_pub.b, key, hs.hash, msg + WG_INIT_OFF_STATIC, WG_KEY_LEN + WG_TAG_LEN)) goto out;
    r = l->remote_get(l->ctx, &s_pub);
    if (!r) goto out;

    /* ss */
    if (!mix_ss(hs.chaining_key, key, r)) goto out;

    /* payload: the timestamp */
    if (!decrypt_and_hash(ts, key, hs.hash, msg + WG_INIT_OFF_TIMESTAMP,
                          WG_TIMESTAMP_LEN + WG_TAG_LEN)) goto out;

    /* Replay: an initiation is good once, and only if newer than any accepted before. Flood: the
     * same peer is not worth more than one handshake per interval. Neither check can run before
     * the decryption above, which is what proves the message came from this peer at all. */
    if (memcmp(ts, r->last_timestamp, WG_TIMESTAMP_LEN) <= 0) goto out;
    if (r->has_last_initiation && now_ns < r->last_initiation_ns + WG_INITIATION_MIN_INTERVAL_NS) goto out;

    /* Accepted. It replaces whatever handshake was in progress with this peer, including an
     * initiation of our own. When both sides initiate at once, each drops its own initiation for
     * the other's, and then neither response finds an initiation to match; the retransmit timer
     * (REKEY_TIMEOUT plus random jitter, which breaks the tie) starts over. That is WireGuard's
     * behaviour, not a shortcut of this code. */
    wg_noise_remote_clear(r);
    hs.state = WG_HS_CONSUMED_INITIATION;
    hs.remote_index = wg_load32(msg + WG_INIT_OFF_SENDER);
    r->hs = hs;
    memcpy(r->last_timestamp, ts, WG_TIMESTAMP_LEN);
    r->last_initiation_ns = now_ns;
    r->has_last_initiation = 1;
    *rp = r;
    ok = 1;
out:
    wg_wipe(&hs, sizeof(hs));
    wg_wipe(key, sizeof(key));
    return ok;
}

/* --------------------------------------------------------------------- response */

int wg_noise_create_response(wg_noise_remote* r, uint8_t msg[WG_RESP_LEN])
{
    wg_noise_local* l = r->local;
    wg_noise_handshake hs;
    uint8_t key[WG_KEY_LEN];
    wg_key e_pub;
    uint32_t index;
    int ok = 0;

    if (r->hs.state != WG_HS_CONSUMED_INITIATION || !l->index_set) return 0;
    hs = r->hs;

    /* e */
    if (!wg_key_generate_rng(&l->rng, &hs.ephemeral_private, &e_pub)) goto out;
    if (!mix_key(hs.chaining_key, e_pub.b, WG_KEY_LEN)) goto out;
    if (!mix_hash(hs.hash, e_pub.b, WG_KEY_LEN)) goto out;
    memcpy(msg + WG_RESP_OFF_EPHEMERAL, e_pub.b, WG_KEY_LEN);

    /* ee */
    if (!mix_dh(hs.chaining_key, NULL, &hs.ephemeral_private, &hs.remote_ephemeral)) goto out;

    /* se */
    if (!mix_dh(hs.chaining_key, NULL, &hs.ephemeral_private, &r->public_key)) goto out;

    /* psk */
    if (!mix_psk(hs.chaining_key, hs.hash, key, r->psk)) goto out;

    /* payload: empty, so just a tag */
    if (!encrypt_and_hash(msg + WG_RESP_OFF_EMPTY, key, hs.hash, NULL, 0)) goto out;

    if (!l->index_set(l->ctx, r, &index)) goto out;

    /* CONSUMED_INITIATION holds no index, so there is nothing to release before replacing it. */
    hs.state = WG_HS_CREATED_RESPONSE;
    hs.local_index = index;
    r->hs = hs;

    wg_store32(msg + WG_RESP_OFF_TYPE, WG_MSG_RESPONSE);
    wg_store32(msg + WG_RESP_OFF_SENDER, index);
    wg_store32(msg + WG_RESP_OFF_RECEIVER, hs.remote_index);
    memset(msg + WG_RESP_OFF_MAC1, 0, WG_MACS_LEN);
    ok = 1;
out:
    wg_wipe(&hs, sizeof(hs));
    wg_wipe(key, sizeof(key));
    if (!ok) memset(msg, 0, WG_RESP_LEN);
    return ok;
}

int wg_noise_consume_response(wg_noise_remote* r, const uint8_t msg[WG_RESP_LEN])
{
    wg_noise_local* l = r->local;
    wg_noise_handshake hs;
    uint8_t key[WG_KEY_LEN];
    uint8_t empty[1];
    int ok = 0;

    if (!l->has_identity) return 0;
    if (r->hs.state != WG_HS_CREATED_INITIATION) return 0;
    if (wg_load32(msg + WG_RESP_OFF_RECEIVER) != r->hs.local_index) return 0;
    hs = r->hs;

    /* e */
    memcpy(hs.remote_ephemeral.b, msg + WG_RESP_OFF_EPHEMERAL, WG_KEY_LEN);
    if (!mix_key(hs.chaining_key, hs.remote_ephemeral.b, WG_KEY_LEN)) goto out;
    if (!mix_hash(hs.hash, hs.remote_ephemeral.b, WG_KEY_LEN)) goto out;

    /* ee */
    if (!mix_dh(hs.chaining_key, NULL, &hs.ephemeral_private, &hs.remote_ephemeral)) goto out;

    /* se, from our side: our static with their ephemeral */
    if (!mix_dh(hs.chaining_key, NULL, &l->private_key, &hs.remote_ephemeral)) goto out;

    /* psk */
    if (!mix_psk(hs.chaining_key, hs.hash, key, r->psk)) goto out;

    /* payload: empty. This tag is the only thing that proves the responder knew the PSK and our
     * ephemeral; a wrong PSK on either side fails exactly here. */
    if (!decrypt_and_hash(empty, key, hs.hash, msg + WG_RESP_OFF_EMPTY, WG_TAG_LEN)) goto out;

    hs.state = WG_HS_CONSUMED_RESPONSE;
    hs.remote_index = wg_load32(msg + WG_RESP_OFF_SENDER);
    r->hs = hs;
    ok = 1;
out:
    wg_wipe(&hs, sizeof(hs));
    wg_wipe(key, sizeof(key));
    return ok;
}

/* --------------------------------------------------------------------- session keys */

int wg_noise_begin_session(wg_noise_remote* r, wg_noise_keys* keys)
{
    wg_noise_handshake* hs = &r->hs;
    uint8_t first[WG_KEY_LEN], second[WG_KEY_LEN];
    int initiator;

    if (hs->state != WG_HS_CONSUMED_RESPONSE && hs->state != WG_HS_CREATED_RESPONSE) return 0;

    /* Noise Split(): KDF2 of the final chaining key with an empty input. The first key carries
     * initiator -> responder, the second the other way. */
    if (!wg_kdf(first, second, NULL, hs->chaining_key, NULL, 0)) {
        wg_wipe(first, sizeof(first));
        wg_wipe(second, sizeof(second));
        return 0;
    }

    initiator = hs->state == WG_HS_CONSUMED_RESPONSE;
    memcpy(keys->send_key, initiator ? first : second, WG_KEY_LEN);
    memcpy(keys->recv_key, initiator ? second : first, WG_KEY_LEN);
    keys->local_index = hs->local_index;
    keys->remote_index = hs->remote_index;
    keys->initiator = initiator;

    /* The index moves to the session: zero the handshake without index_drop. */
    wg_wipe(hs, sizeof(*hs));
    hs->state = WG_HS_ZEROED;

    wg_wipe(first, sizeof(first));
    wg_wipe(second, sizeof(second));
    return 1;
}
