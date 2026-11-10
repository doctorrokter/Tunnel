/*
 * ts_disco - Tailscale's disco messages (TAILSCALE.md section 11a), without I/O: what magicsock
 * sends over UDP and over DERP to find a direct path to a node and keep it - Ping, Pong,
 * CallMeMaybe - framed and sealed as its sendDiscoMessage does (refs/tailscale: disco/disco.go,
 * wgengine/magicsock/magicsock.go, types/key/disco.go):
 *
 *   frame        "TS" U+1F4AC (6 bytes) | the sender's disco public key (32) | nonce (24) | box
 *   box          NaCl box under the pair's shared key (ts_disco_shared), tag first (wg_salsa.h);
 *                the nonce is random per message, as Tailscale draws it
 *   inside       type (1) | version (1: 0; bytes after the body are ignored) | body
 *   Ping         TxID (12) | the sender's node key (32; clients before 1.16 leave it out) | zero
 *                padding (MTU probes)
 *   Pong         TxID (12) | the address the ping came from: IP (16, IPv4 v4-mapped) | port (2, BE)
 *   CallMeMaybe  the sender's endpoints, 18 bytes each like a Pong's address; over DERP only
 *
 * Read as disco.Parse reads it: a Ping needs its TxID, and 32 bytes after it are its node key - all
 * zero means none, so a Ping with no key and 32 bytes of padding or more reads as one without a key
 * and 32 bytes less padding (the wire cannot tell them apart); a Pong needs all 30 bytes; a CallMeMaybe whose
 * body is empty, no multiple of 18 bytes or of another version is one with no endpoints. Every
 * other type - the peer relays' Bind..., Allocate..., CallMeMaybeVia, anything newer - comes back as
 * TS_DISCO_OTHER: the caller ignores it.
 */

#ifndef TS_DISCO_H
#define TS_DISCO_H

#include <stddef.h>
#include <stdint.h>

#include "wg_crypto.h"
#include "wg_peer.h"
#include "wg_salsa.h"

#define TS_DISCO_MAGIC_LEN      6
#define TS_DISCO_KEY_LEN        32
#define TS_DISCO_HEADER_LEN     (TS_DISCO_MAGIC_LEN + TS_DISCO_KEY_LEN + WG_BOX_NONCE_LEN)    /* 62 */
#define TS_DISCO_TXID_LEN       12
#define TS_DISCO_EPS_MAX        16      /* a CallMeMaybe's endpoints kept; the rest are left out */
#define TS_DISCO_PLAIN_MAX      1500    /* the most a message may be inside its box (a padded Ping) */
#define TS_DISCO_FRAME_MAX      (TS_DISCO_HEADER_LEN + WG_BOX_TAG_LEN + TS_DISCO_PLAIN_MAX)

typedef enum {
    TS_DISCO_OTHER = 0,
    TS_DISCO_PING = 1,
    TS_DISCO_PONG = 2,
    TS_DISCO_CALL_ME_MAYBE = 3
} ts_disco_type;

typedef struct {
    ts_disco_type type;
    uint8_t       txid[TS_DISCO_TXID_LEN];          /* Ping, Pong */
    int           has_node_key;                     /* Ping */
    uint8_t       node_key[TS_DISCO_KEY_LEN];
    size_t        padding;                          /* Ping: zero bytes after it */
    wg_endpoint   src;                              /* Pong: family 4 or 6 */
    wg_endpoint   eps[TS_DISCO_EPS_MAX];            /* CallMeMaybe */
    size_t        n_eps;
} ts_disco_msg;

/* A datagram or DERP frame that is a disco message: the magic and room for the header. */
int ts_disco_is(const uint8_t* pkt, size_t len);

/* The sender's disco public key in a frame ts_disco_is accepted. */
const uint8_t* ts_disco_sender(const uint8_t* pkt);

/* The key a pair seals with: both ends get the same. 0 for a low-order public key. */
int ts_disco_shared(uint8_t shared[WG_BOX_KEY_LEN], const uint8_t their_pub[TS_DISCO_KEY_LEN],
                    const wg_key* our_priv);

/*
 * `m` sealed into a frame from `our_pub` under `shared` and `nonce` (fresh random bytes each time:
 * a nonce must never repeat under one pair). Returns the frame's length, 0 when it does not fit in
 * `cap` or `m` cannot be written (more than TS_DISCO_EPS_MAX endpoints, an endpoint of no family,
 * padding beyond TS_DISCO_PLAIN_MAX, a type other than the three).
 */
size_t ts_disco_seal(uint8_t* out, size_t cap, const ts_disco_msg* m, const uint8_t our_pub[TS_DISCO_KEY_LEN],
                     const uint8_t shared[WG_BOX_KEY_LEN], const uint8_t nonce[WG_BOX_NONCE_LEN]);

/* A frame opened under `shared` and read into `m`: 1, `m->type` saying what it was (TS_DISCO_OTHER
 * included); 0 when it is no disco frame, its box does not open, or its message is cut short. */
int ts_disco_open(const uint8_t* pkt, size_t len, const uint8_t shared[WG_BOX_KEY_LEN], ts_disco_msg* m);

#endif /* TS_DISCO_H */
