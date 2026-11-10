/*
 * wg_device - one tunnel: our identity, the peers, and the dispatch of every datagram and packet.
 *
 * This is the object the I/O layer (the daemon) drives, three calls in a loop:
 *
 *   wg_device_receive   a UDP datagram arrived from `src`
 *   wg_device_send      an IP packet from tun: routed to a peer by its destination (AllowedIPs)
 *   wg_device_tick      time passed; returns the next deadline for poll()
 *
 * and it answers through upcalls: send a datagram, deliver a decrypted packet, read the wall clock.
 * Upcalls run synchronously, their buffers live only for the call, and they must not call back into
 * the device. Single-threaded like the rest of the engine.
 *
 * An owner that chooses each peer's path itself - Tailscale over DERP relays, which address a node
 * by its key, not by an IP address; its magicsock does the same for wireguard-go - also sets
 * send_peer: every datagram that goes to a peer then names the peer. Such peers' endpoints are the
 * owner's label (WG_EP_OWNER), and the owner hands over what they send with that same label as the
 * source - with wg_device_receive_from when it knows the sender, as a DERP frame does.
 *
 * A delivered packet is checked the other way round: it must be IP, no longer than what arrived
 * (it is cut to its own length, the padding goes), and its source must route to the peer it came
 * from. Everything that crosses the wire goes through the device's codec (wg_codec.h): plain
 * WireGuard unless the owner sets another.
 *
 * There is no index table: a receiver index is resolved by asking the peers, whose handshake and
 * three keypairs hold every index in use. Linear in the number of peers - right for a phone's few
 * tunnels; an owner that knows the sender (Tailscale's hundreds of peers) asks that one peer alone,
 * with wg_device_receive_from.
 */

#ifndef WG_DEVICE_H
#define WG_DEVICE_H

#include <stddef.h>
#include <stdint.h>

#include "wg_allowedips.h"
#include "wg_codec.h"
#include "wg_cookie.h"
#include "wg_noise.h"
#include "wg_peer.h"

typedef struct wg_device {
    wg_noise_local    local;            /* identity; its upcalls are the device's */
    wg_cookie_checker checker;
    wg_timing         timing;           /* change it with wg_device_set_timing */
    size_t            mtu;              /* data is padded up to it; 0 = no MTU */
    int               up;
    int               under_load;       /* the owner's call: demand a cookie (mac2) of handshakes */
    int               disable_cookies;  /* AmneziaWG's DisableCookies: never, whatever under_load says */
    wg_peer*          peers;
    wg_allowedips     allowedips;       /* every peer's prefixes, one table */
    wg_codec          codec;            /* the wire format; set it before the device comes up */

    void* ctx;
    void (*send)(void* ctx, const wg_endpoint* to, const uint8_t* msg, size_t len);
    void (*deliver)(void* ctx, wg_peer* from, uint8_t* pkt, size_t len);
    void (*wall_clock)(void* ctx, uint64_t* unix_sec, uint32_t* nsec);

    /* Optional, for an owner that routes by peer. Set, it takes everything that goes to a peer -
     * initiations, responses, data, keepalives, the codec's datagrams ahead of an initiation - with
     * the peer and its endpoint (`to`, a label or an address); `send` keeps what answers an address
     * rather than a peer: a cookie reply, to wherever the handshake message came from. */
    void (*send_peer)(void* ctx, wg_peer* p, const wg_endpoint* to, const uint8_t* msg, size_t len);

    wg_peer*          rx_from;          /* the sender, while wg_device_receive_from runs */

    /* One sealed message at a time, and the datagram the codec builds around it: the engine is
     * single-threaded. */
    uint8_t           scratch[WG_DATA_MSG_LEN(WG_MAX_PACKET + WG_PADDING_MULTIPLE)];
    uint8_t           wire[WG_DATA_MSG_LEN(WG_MAX_PACKET + WG_PADDING_MULTIPLE) + WG_CODEC_MAX_OVERHEAD];
} wg_device;

/* A down device with no identity and no peers, WireGuard's timing, MTU 1420. Set the upcalls
 * (ctx, send, deliver, wall_clock, and send_peer if the owner routes by peer) before use;
 * `local.rng` may be replaced (tests). */
void wg_device_init(wg_device* d);

/* Sets our static private key. Handshakes in flight are dropped and current sessions stop sending,
 * so the next packet starts a handshake under the new identity. */
int wg_device_set_private_key(wg_device* d, const wg_key* private_key);

/* The protocol's times (AmneziaWG moves them): for the timers armed from now on, and for how long
 * every peer's keys live. */
void wg_device_set_timing(wg_device* d, const wg_timing* t);

/*
 * Gives the AllowedIPs table its nodes, in storage the caller owns. n prefixes need at most 2n
 * nodes. Only while the table is empty (0 otherwise); until then every wg_peer_allow fails.
 */
int wg_device_set_allowedips_storage(wg_device* d, wg_allowedips_node* nodes, size_t cap);

/*
 * Moves the AllowedIPs table to a bigger pool the caller owns (at least as many nodes as the
 * current one), when a wg_peer_allow failed for room - a netmap grew. Every prefix stays, and every
 * lookup answers as before. The new pool is a block of its own, not the old one realloc()ed: the
 * old one is read during the move, and then it is the caller's again, handed back in *old (NULL if
 * there was none). 0 for a smaller pool or none, and nothing changes.
 */
int wg_device_grow_allowedips(wg_device* d, wg_allowedips_node* nodes, size_t cap,
                              wg_allowedips_node** old);

/*
 * Adds a peer in storage the caller owns (it must stay put). `stage_mem` holds the packets that
 * wait for a key; a few tens of KB are plenty. 0 for our own key or a duplicate.
 */
int wg_device_add_peer(wg_device* d, wg_peer* p, const wg_key* public_key,
                       uint8_t* stage_mem, size_t stage_cap);

/* Takes a peer out and wipes its keys. */
void wg_device_remove_peer(wg_device* d, wg_peer* p);

wg_peer* wg_device_find_peer(wg_device* d, const wg_key* public_key);

/* Up: timers run, staged packets go out, persistent keepalives start (and with them handshakes).
 * Down: every peer's timers, staged packets, handshake and keys are dropped. */
void wg_device_up(wg_device* d, uint64_t now_ns);
void wg_device_down(wg_device* d);

/*
 * An IP packet from tun: sent to the peer whose AllowedIPs match its destination most specifically,
 * or staged until a handshake gives keys. 0 when it cannot go, and `why` (may be NULL) says why -
 * for WG_DROP_NO_ROUTE the daemon may answer the sender with ICMP unreachable, as Linux does.
 */
int wg_device_send(wg_device* d, const uint8_t* pkt, size_t len, uint64_t now_ns, wg_drop_reason* why);

/* A packet for a peer the caller chose: no routing, nothing looked at inside (tests, probes). */
int wg_device_send_to_peer(wg_device* d, wg_peer* p, const uint8_t* pkt, size_t len, uint64_t now_ns);

/* A datagram from `src`. Decrypted in place, so `dgram` is written to. 1 when it was authentic and
 * used; 0 when it was dropped (a cookie reply may still have gone out, under load). */
int wg_device_receive(wg_device* d, uint8_t* dgram, size_t len, const wg_endpoint* src,
                      uint64_t now_ns);

/*
 * The same for a datagram the owner knows came from peer `p` (a DERP frame names its sender's
 * key). Its index is looked for at `p` alone, not at every peer - only answering an initiation
 * still asks them all once, for a fresh index that is free everywhere - and a message that is not
 * `p`'s (an initiation under another key, another peer's index) is refused before any handshake
 * or keys change; for data, p->last_drop says WG_DROP_UNKNOWN_INDEX. 0 for a NULL `p` or another
 * device's.
 */
int wg_device_receive_from(wg_device* d, wg_peer* p, uint8_t* dgram, size_t len,
                           const wg_endpoint* src, uint64_t now_ns);

/* Fires due timers; returns the next deadline (WG_NEVER: nothing armed). */
uint64_t wg_device_tick(wg_device* d, uint64_t now_ns);

/* The next deadline without firing anything - after a send or receive may have armed one. */
uint64_t wg_device_next_deadline(const wg_device* d);

/* --- the wire, through the codec: for wg_peer --------------------------------------------- */

/* The type field of an outgoing canonical message; before its macs. */
void wg_device_stamp(wg_device* d, uint32_t type, uint8_t* msg, size_t len);

/* Wraps a finished message and hands it to an upcall: send_peer when it goes to peer `p` and the
 * owner routes by peer, send otherwise (`p` NULL: a cookie reply). Returns the bytes put on the
 * wire. */
size_t wg_device_transmit(wg_device* d, wg_peer* p, const wg_endpoint* to, uint32_t type,
                          const uint8_t* msg, size_t len);

/* Sends what the codec puts ahead of an initiation to `p`, the same way. Returns the bytes put on
 * the wire. */
size_t wg_device_before_initiation(wg_device* d, wg_peer* p, const wg_endpoint* to);

/* Zero bytes to pad a data packet of `len` (at most WG_MAX_PACKET) with: the codec's choice, never
 * more than the scratch buffer holds. */
size_t wg_device_padding(const wg_device* d, size_t len);

/* A message from a peer proved authentic (see the codec's `authentic`). */
void wg_device_authentic(wg_device* d, uint32_t type, size_t len, int moved);

#endif /* WG_DEVICE_H */
