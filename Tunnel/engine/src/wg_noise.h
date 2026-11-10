/*
 * wg_noise - the WireGuard handshake, Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s.
 *
 * Sans-IO: messages in, messages out, transport keys at the end. No clock - the caller passes the
 * wall-clock timestamp for an initiation and the monotonic time for the flood check. No sockets,
 * no allocation. Randomness (ephemeral keys) comes through the local wg_rng, so a test can replay
 * a transcript byte for byte.
 *
 * The shape follows OpenBSD's wg_noise.c (ISC): a local identity with upcalls into its owner, and
 * a remote per peer that holds the handshake in progress. The owner (the engine) keeps the peer
 * table and the index table; the handshake only asks it for fresh sender indices and returns them.
 *
 *   initiator                                            responder
 *   wg_noise_create_initiation  --- initiation --->  wg_noise_consume_initiation
 *   wg_noise_consume_response   <--- response  ---   wg_noise_create_response
 *   wg_noise_begin_session                            wg_noise_begin_session
 *
 * mac1 / mac2 are not computed here: they are wg_cookie's, applied to the finished message. The
 * create functions write the canonical type and leave both macs zero; the wire codec may put
 * another value in the type field before the macs are added (AmneziaWG does, and mac1 covers it).
 * The consume functions never look at the type field or the macs - classify and check those first.
 *
 * All functions return 1 on success and 0 on failure (the wg_crypto convention). A failed consume
 * leaves the remote exactly as it was: garbage from the network must not cancel a handshake.
 */

#ifndef WG_NOISE_H
#define WG_NOISE_H

#include <stdint.h>

#include "wg_crypto.h"
#include "wg_msg.h"

/* An initiation from one peer is accepted at most this often (WireGuard: 50 per second). */
#define WG_INITIATION_MIN_INTERVAL_NS (WG_NSEC_PER_SEC / 50)

typedef enum {
    WG_HS_ZEROED = 0,
    WG_HS_CREATED_INITIATION,       /* initiator: initiation sent, waiting for the response */
    WG_HS_CONSUMED_INITIATION,      /* responder: initiation accepted, response not made yet */
    WG_HS_CREATED_RESPONSE,         /* responder: response made; keys ready for begin_session */
    WG_HS_CONSUMED_RESPONSE         /* initiator: response accepted; keys ready for begin_session */
} wg_hs_state;

typedef struct {
    wg_hs_state state;
    uint32_t    local_index;        /* ours; registered with the owner in CREATED_* / CONSUMED_RESPONSE */
    uint32_t    remote_index;       /* theirs, once known */
    wg_key      ephemeral_private;  /* ours */
    wg_key      remote_ephemeral;   /* theirs */
    uint8_t     hash[WG_HASH_LEN];
    uint8_t     chaining_key[WG_HASH_LEN];
} wg_noise_handshake;

struct wg_noise_remote;

typedef struct wg_noise_local {
    wg_key private_key;             /* stored clamped */
    wg_key public_key;
    int    has_identity;

    /*
     * Upcalls into the owner, all given `ctx`:
     *   remote_get  finds a peer by its static public key; an initiation reveals the key only
     *               after decryption, so the lookup has to happen in the middle of consuming it.
     *   index_set   reserves a fresh 32-bit index, random and unused, that resolves to `r` until
     *               index_drop releases it. The handshake takes one per initiation or response;
     *               wg_noise_begin_session hands it on to the session instead of releasing it.
     */
    void* ctx;
    struct wg_noise_remote* (*remote_get)(void* ctx, const wg_key* public_key);
    int  (*index_set)(void* ctx, struct wg_noise_remote* r, uint32_t* index);
    void (*index_drop)(void* ctx, uint32_t index);

    wg_rng rng;                     /* ephemeral keys; left empty = wg_random */
} wg_noise_local;

typedef struct wg_noise_remote {
    wg_noise_local* local;
    wg_key   public_key;                        /* the peer's static key */
    uint8_t  psk[WG_KEY_LEN];                   /* all zeroes when none is set, as in WireGuard */
    uint8_t  ss[WG_KEY_LEN];                    /* DH(local static, peer static), precomputed */
    int      ss_valid;                          /* 0: no local identity, or a low-order peer key */

    wg_noise_handshake hs;

    uint8_t  last_timestamp[WG_TIMESTAMP_LEN];  /* newest initiation accepted from the peer */
    uint64_t last_initiation_ns;                /* and when: the flood guard */
    int      has_last_initiation;
    uint8_t  sent_timestamp[WG_TIMESTAMP_LEN];  /* newest we sent, see wg_noise_create_initiation */
} wg_noise_remote;

/* The result of a handshake: what a session needs. */
typedef struct {
    uint8_t  send_key[WG_KEY_LEN];
    uint8_t  recv_key[WG_KEY_LEN];
    uint32_t local_index;           /* the peer puts it on the data it sends us */
    uint32_t remote_index;          /* we put it on the data we send */
    int      initiator;             /* a responder must not send data before it has received some
                                       with these keys - that is what confirms them to it */
} wg_noise_keys;

/* --- identity and peers ---------------------------------------------------------------- */

/* Zeroes `l`: no identity, no upcalls, default randomness. Set the upcalls before use. */
void wg_noise_local_init(wg_noise_local* l);

/* Takes a static private key (it is stored clamped). Every remote needs
 * wg_noise_remote_precompute afterwards. */
int wg_noise_local_set_private_key(wg_noise_local* l, const wg_key* private_key);

/*
 * Binds a peer to `l`. Never fails: a peer whose key yields an all-zero DH (a low-order point) is
 * kept but can never complete a handshake - `ss_valid` says so, for the caller to report.
 */
void wg_noise_remote_init(wg_noise_remote* r, wg_noise_local* l, const wg_key* public_key);

/* Sets the preshared key; NULL clears it (back to all zeroes). */
void wg_noise_remote_set_psk(wg_noise_remote* r, const uint8_t psk[WG_KEY_LEN]);

/* Recomputes the static-static DH after the local key changed, and drops the handshake in
 * progress, which was made with the old key. */
void wg_noise_remote_precompute(wg_noise_remote* r);

/* Drops the handshake in progress and releases its index. */
void wg_noise_remote_clear(wg_noise_remote* r);

/* wg_noise_remote_clear, then wipes every secret of the peer. For removing it. */
void wg_noise_remote_wipe(wg_noise_remote* r);

/* --- messages -------------------------------------------------------------------------- */

/*
 * TAI64N of a wall-clock time, as WireGuard sends it: seconds with the TAI64 offset, then the
 * nanoseconds rounded down to 2^24 ns so the timestamp does not leak a fine-grained clock.
 */
void wg_tai64n(uint8_t out[WG_TIMESTAMP_LEN], uint64_t unix_sec, uint32_t nsec);

/*
 * Starts a handshake: fills `msg` with an initiation (macs zero) and replaces any handshake in
 * progress with this peer. `timestamp` is wg_tai64n of the current wall-clock time.
 *
 * The responder accepts an initiation only if its timestamp is newer than any it accepted before
 * from us. A phone's clock gets stepped (network time), so when `timestamp` is not newer than the
 * last one we sent, the last one plus one quantum is sent instead - within one run of the engine
 * a clock stepping back cannot lock us out of a peer.
 */
int wg_noise_create_initiation(wg_noise_remote* r, const uint8_t timestamp[WG_TIMESTAMP_LEN],
                               uint8_t msg[WG_INIT_LEN]);

/*
 * Consumes an initiation whose mac1 already checked out. On success `*rp` is the peer it came
 * from, in state WG_HS_CONSUMED_INITIATION; answer with wg_noise_create_response. Refused: an
 * unknown static key, a timestamp not newer than the last accepted one (replay), and a second
 * initiation within WG_INITIATION_MIN_INTERVAL_NS of the last accepted one (flood).
 * `now_ns` is monotonic time.
 */
int wg_noise_consume_initiation(wg_noise_local* l, const uint8_t msg[WG_INIT_LEN], uint64_t now_ns,
                                wg_noise_remote** rp);

/* Answers a consumed initiation: fills `msg` with the response (macs zero). */
int wg_noise_create_response(wg_noise_remote* r, uint8_t msg[WG_RESP_LEN]);

/*
 * Consumes a response to our initiation. `r` is the peer that the message's receiver index
 * resolves to in the owner's index table; the index is checked against the handshake again here.
 */
int wg_noise_consume_response(wg_noise_remote* r, const uint8_t msg[WG_RESP_LEN]);

/*
 * Derives the transport keys of a finished handshake (WG_HS_CONSUMED_RESPONSE on the initiator,
 * WG_HS_CREATED_RESPONSE on the responder) and zeroes the handshake. The local index is NOT
 * released: it now identifies the session, and the owner re-points it there.
 */
int wg_noise_begin_session(wg_noise_remote* r, wg_noise_keys* keys);

#endif /* WG_NOISE_H */
