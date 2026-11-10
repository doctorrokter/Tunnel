/*
 * wg_cookie - mac1, mac2 and cookie replies: the DoS guard around the WireGuard handshake.
 *
 * Every handshake message ends with two MACs over everything in front of them:
 *
 *   mac1 = MAC(HASH("mac1----" || receiver's static public key), msg up to mac1)
 *   mac2 = MAC(cookie, msg up to mac2), or all zeroes without a fresh cookie
 *
 * mac1 shows that the sender knows whom it is talking to; the receiver checks it before spending
 * any DH on the message and drops the message silently when it is wrong. mac2 matters only to a
 * receiver under load: a message without a valid mac2 then gets a cookie reply instead of a
 * handshake, and the sender repeats with the cookie, which proves it owns its source address.
 * The cookie is MAC(a secret rotated every two minutes, the source address), sealed with
 * XChaCha20-Poly1305 under the receiver's static key, with the triggering mac1 as the AD.
 *
 * The maker is the sending half, one per peer. The checker is the receiving half, one per device.
 * Both take whole messages exactly as they are on the wire: the codec may have put another value
 * in the type field (AmneziaWG), and the macs cover exactly those bytes. The functions find the
 * macs in the last WG_MACS_LEN bytes, so they serve initiations and responses alike.
 *
 * Deciding "under load", rate-limiting per source and finding the peer a cookie reply is meant for
 * (by its receiver index) are the owner's job. Return values: 1 success, 0 failure.
 */

#ifndef WG_COOKIE_H
#define WG_COOKIE_H

#include <stddef.h>
#include <stdint.h>

#include "wg_crypto.h"
#include "wg_msg.h"

/* The checker rotates its secret this often; the maker stops using a cookie this much sooner,
 * so a cookie is not sent just as the secret behind it expires. */
#define WG_COOKIE_SECRET_MAX_AGE_NS (120 * WG_NSEC_PER_SEC)
#define WG_COOKIE_SECRET_LATENCY_NS (5 * WG_NSEC_PER_SEC)

typedef struct {
    uint8_t  mac1_key[WG_HASH_LEN];     /* HASH("mac1----" || peer static) */
    uint8_t  cookie_key[WG_KEY_LEN];    /* HASH("cookie--" || peer static): opens its cookie replies */
    uint8_t  cookie[WG_COOKIE_LEN];     /* the last cookie the peer gave us */
    uint64_t cookie_birth_ns;
    int      has_cookie;
    uint8_t  last_mac1[WG_MAC_LEN];     /* mac1 of the last handshake message sent: a reply's AD */
    int      has_last_mac1;
} wg_cookie_maker;

typedef struct {
    uint8_t  mac1_key[WG_HASH_LEN];     /* HASH("mac1----" || our static) */
    uint8_t  cookie_key[WG_KEY_LEN];    /* HASH("cookie--" || our static): seals our cookie replies */
    int      has_key;
    uint8_t  secret[WG_HASH_LEN];
    uint64_t secret_birth_ns;
    int      has_secret;
    wg_rng   rng;                       /* the secret and reply nonces; left empty = wg_random */
} wg_cookie_checker;

typedef enum {
    WG_MAC_INVALID = 0,                 /* bad mac1: drop without a word */
    WG_MAC_VALID_NO_COOKIE,             /* mac1 good; mac2 not checked, or not good */
    WG_MAC_VALID_WITH_COOKIE            /* mac1 and mac2 good */
} wg_mac_state;

/* --- the sending half: one per peer ---------------------------------------------------- */

int wg_cookie_maker_init(wg_cookie_maker* m, const wg_key* peer_public);

/*
 * Fills the two macs at the end of an outgoing handshake message (`len` bytes, macs included).
 * mac2 uses the peer's cookie while it is fresh, otherwise it is zeroes.
 */
int wg_cookie_add_macs(wg_cookie_maker* m, uint8_t* msg, size_t len, uint64_t now_ns);

/*
 * Takes a cookie reply the owner matched to this peer by its receiver index. It opens only
 * against the mac1 we sent last, and only once: a reply to an older message, a replay or a forgery
 * all fail, and the cookie we hold is kept.
 */
int wg_cookie_consume_reply(wg_cookie_maker* m, const uint8_t msg[WG_COOKIE_MSG_LEN], uint64_t now_ns);

/* --- the receiving half: one per device ------------------------------------------------ */

/* Zeroes `c`: no key, default randomness. */
void wg_cookie_checker_init(wg_cookie_checker* c);

/* (Re)keys the checker with our static public key; also at every change of our identity. */
int wg_cookie_checker_set_key(wg_cookie_checker* c, const wg_key* local_public);

/*
 * Checks an incoming handshake message. mac2 is checked only with `check_mac2` (the owner is under
 * load). `src` is the datagram's source address in any fixed encoding the owner likes - the
 * engine uses the IP address bytes followed by the port, big-endian - since only this checker ever
 * derives a cookie from it.
 */
wg_mac_state wg_cookie_validate(wg_cookie_checker* c, const uint8_t* msg, size_t len,
                                const void* src, size_t src_len, int check_mac2, uint64_t now_ns);

/*
 * Builds the cookie reply to a handshake message (`len` bytes, macs included) from `src`. It goes
 * to the message's sender index, which is at the same offset in an initiation and a response.
 */
int wg_cookie_create_reply(wg_cookie_checker* c, uint8_t out[WG_COOKIE_MSG_LEN],
                           const uint8_t* msg, size_t len, const void* src, size_t src_len,
                           uint64_t now_ns);

#endif /* WG_COOKIE_H */
