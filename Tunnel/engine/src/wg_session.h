/*
 * wg_session - transport data: the keypairs of one peer, the replay window, and the data messages
 * sealed with them.
 *
 * A peer holds up to three keypairs, as in WireGuard:
 *   current   what we send with, and receive on;
 *   previous  the one before it, kept so packets already in flight still decrypt;
 *   next      a responder's new keypair: it may not send with it until the initiator has used it,
 *             because only that proves the initiator received the response. The first data message
 *             on `next` confirms it and moves it to `current`.
 *
 * A data message is a 16-byte header (type, receiver index, counter) and the packet padded with
 * zeroes to a multiple of 16 (never past the MTU), sealed with the counter as the nonce and no AD.
 * The header is not authenticated: the counter is, as the nonce, and the receiver index picks the
 * key. That is also why a wire codec may reshape it (AmneziaWG) - this layer never reads the type.
 *
 * Sans-IO like the rest: time comes in as now_ns, nothing is allocated (the three keypairs live in
 * the session), a keypair's index goes back to the owner through the local's index_drop upcall.
 * Single-threaded: the engine runs one loop.
 */

#ifndef WG_SESSION_H
#define WG_SESSION_H

#include <stddef.h>
#include <stdint.h>

#include "wg_crypto.h"
#include "wg_msg.h"
#include "wg_noise.h"

/* Message counts (whitepaper, section 6.1). They are bound to the counter space and the replay
 * window rather than to any profile, so they stay constants. */
#define WG_REKEY_AFTER_MESSAGES     (1ULL << 60)
#define WG_REJECT_AFTER_MESSAGES    (~0ULL - (1ULL << 13))          /* 2^64 - 2^13 - 1 */

/* Times (whitepaper, section 6.1). A session carries its own copy of the reject time, see below. */
#define WG_REKEY_AFTER_TIME_NS      (120 * WG_NSEC_PER_SEC)
#define WG_REJECT_AFTER_TIME_NS     (180 * WG_NSEC_PER_SEC)

#define WG_PADDING_MULTIPLE         16

/* A data message for a packet of `padded` bytes (packet + padding). */
#define WG_DATA_MSG_LEN(padded)     (WG_DATA_HEADER_LEN + (padded) + WG_TAG_LEN)

/* --- replay window ---------------------------------------------------------------------- */

/*
 * RFC 6479: a ring of 64-bit blocks, cleared lazily as the window slides forward, so accepting a
 * counter costs a few word operations and no shifting. 128 blocks = 8192 bits, of which one block
 * is the slack the algorithm needs: counters up to WG_REPLAY_WINDOW behind the newest one are
 * still accepted once. The size matches Linux and wireguard-go; the peer never sees it, it only
 * decides how much reordering a link may do before packets are lost.
 */
#define WG_REPLAY_BLOCKS            128
#define WG_REPLAY_WINDOW            ((WG_REPLAY_BLOCKS - 1) * 64)    /* 8128 */

typedef struct {
    uint64_t last;                      /* the greatest counter accepted (0 also before any) */
    uint64_t ring[WG_REPLAY_BLOCKS];
} wg_replay;

void wg_replay_init(wg_replay* w);

/* 1 when `counter` would be accepted. Changes nothing: a cheap test before decrypting. */
int wg_replay_check(const wg_replay* w, uint64_t counter);

/*
 * Accepts `counter` once: 1 the first time, 0 for a repeat, for a counter more than
 * WG_REPLAY_WINDOW behind the newest, and for WG_REJECT_AFTER_MESSAGES and above. Call it only
 * for an authenticated message - a forged counter must not move the window.
 */
int wg_replay_accept(wg_replay* w, uint64_t counter);

/* --- keypairs and the session ------------------------------------------------------------ */

typedef struct {
    uint8_t   send_key[WG_KEY_LEN];
    uint8_t   recv_key[WG_KEY_LEN];
    uint64_t  send_counter;             /* the next counter we send */
    wg_replay replay;                   /* counters received */
    uint64_t  birth_ns;                 /* when the handshake finished */
    uint32_t  local_index;              /* data for us carries it; registered with the owner */
    uint32_t  remote_index;             /* data we send carries it */
    int       initiator;                /* our role in the handshake that made it */
    int       send_valid;               /* 0 once too old, used up or expired on purpose */
    int       recv_valid;               /* 0 once too old */
} wg_keypair;

typedef struct {
    wg_noise_local* local;              /* its index_drop takes back a discarded keypair's index */
    wg_keypair      slot[3];            /* storage for the three below */
    wg_keypair*     next;
    wg_keypair*     current;
    wg_keypair*     previous;

    /*
     * Keys this old are used for nothing. WireGuard's value by default; a field rather than a
     * constant because AmneziaWG 3.x lets a profile move timers, and the timer layer will set it
     * together with its own.
     */
    uint64_t        reject_after_ns;
} wg_session;

typedef struct {
    size_t         len;                 /* the decrypted packet with its padding; 0 is a keepalive */
    int            confirmed;           /* it was the first message on the responder's `next`:
                                           the session is confirmed, send what waited for it */
    wg_drop_reason drop;                /* why it failed, WG_DROP_NONE on success */
} wg_recv;

/* An empty session bound to `l`, whose index_drop releases the indices of discarded keypairs. */
void wg_session_init(wg_session* s, wg_noise_local* l);

/*
 * Installs the keys of a finished handshake (wg_noise_begin_session) and takes over their index.
 * An initiator's keys become `current` at once, the old current becomes `previous`; a responder's
 * keys become `next` and wait for confirmation. Keypairs pushed out are wiped and their indices
 * released - the same rotation as Linux's add_new_keypair. The keys are copied: wipe `keys` after.
 */
void wg_session_add(wg_session* s, const wg_noise_keys* keys, uint64_t now_ns);

/* The keypair a receiver index names, or NULL. */
wg_keypair* wg_session_find(wg_session* s, uint32_t local_index);

/* Zero bytes to add to a packet of `len` bytes: up to a multiple of 16, but not past `mtu`
 * (0 = no MTU). An oversized packet is padded by its remainder modulo the MTU, as in Linux. */
size_t wg_data_padding(size_t len, size_t mtu);

/*
 * Seals a packet into a data message with `current`: `out` gets WG_DATA_MSG_LEN(len + pad) bytes,
 * `*out_len` says how many. `pkt` may sit at out + WG_DATA_HEADER_LEN (sealed in place, the usual
 * case); no other overlap is allowed. `pad` is normally wg_data_padding(len, mtu).
 *
 * 0 means there is no key to send with - no `current`, or it is too old or used up (it is then
 * marked so): queue the packet and start a handshake. A packet of length 0 is a keepalive.
 */
int wg_session_encrypt(wg_session* s, uint8_t* out, size_t* out_len,
                       const uint8_t* pkt, size_t len, size_t pad, uint64_t now_ns);

/*
 * Opens a data message the owner routed to this peer by its receiver index. The plaintext (with its
 * padding; the IP header tells the real length) goes to `out`, which takes len - 32 bytes and may
 * be msg + WG_DATA_HEADER_LEN (opened in place). Checks, in order: length, receiver index, key age,
 * the replay window (a free pre-check), the tag, then records the counter. 1 on success; `rv` says
 * what happened either way.
 */
int wg_session_decrypt(wg_session* s, uint8_t* out, const uint8_t* msg, size_t len,
                       uint64_t now_ns, wg_recv* rv);

/* Stops sending with the keys we have (`current` and `next`), so the next packet starts a
 * handshake; received data still decrypts. For a changed identity or peer configuration. */
void wg_session_expire(wg_session* s);

/* Wipes every keypair and releases their indices. */
void wg_session_clear(wg_session* s);

#endif /* WG_SESSION_H */
