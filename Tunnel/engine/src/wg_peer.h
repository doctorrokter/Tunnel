/*
 * wg_peer - one peer over time: its handshake, keys and cookie, where it is, the packets waiting for
 * a key, and WireGuard's five timers.
 *
 * The timers follow Linux's timers.c event for event:
 *
 *   retransmit_handshake   an initiation got no response: send another after REKEY_TIMEOUT plus
 *                          jitter, give up after REKEY_ATTEMPT_TIME (20 initiations in all)
 *   send_keepalive         data came in and we had nothing to send back: a keepalive after
 *                          KEEPALIVE_TIMEOUT, so the other side knows its packets arrive
 *   new_handshake          we sent data and heard nothing for KEEPALIVE_TIMEOUT + REKEY_TIMEOUT:
 *                          the session may be dead on the other side, handshake again
 *   zero_key_material      no new session for 3 x REJECT_AFTER_TIME: wipe every key
 *   persistent_keepalive   the configured interval passed with no authenticated packet either way
 *
 * (the times as WireGuard has them; wg_timing below lets AmneziaWG move them)
 *
 * Sans-IO: a timer is a deadline in monotonic ns (WG_NEVER when not armed); the device fires them
 * from wg_device_tick and reports the earliest one to the I/O loop. Randomness (jitter) comes from
 * the device's rng, the wall clock (for initiation timestamps) from its wall_clock upcall.
 *
 * The functions below the "driven by wg_device" line are the device's; the I/O layer talks to the
 * device, and to a peer only to configure it.
 */

#ifndef WG_PEER_H
#define WG_PEER_H

#include <stddef.h>
#include <stdint.h>

#include "wg_cookie.h"
#include "wg_noise.h"
#include "wg_session.h"

#define WG_NEVER            (~0ULL)     /* a deadline that is not armed */
#define WG_MAX_PACKET       65535       /* the largest packet the engine carries */

/* --- endpoint --------------------------------------------------------------------------- */

/* Where a peer is: an address and a UDP port, as the I/O layer saw them - or the owner's label. */
typedef struct {
    uint8_t  family;                    /* 0 = unknown, 4 or 6, or WG_EP_OWNER */
    uint8_t  addr[16];                  /* an IPv4 address in the first 4 bytes */
    uint16_t port;                      /* host byte order */
} wg_endpoint;

/*
 * The endpoint of a peer whose path the owner chooses (Tailscale: a DERP relay now, a direct path
 * later - its magicsock works the same way): one constant label, addr and port zero, and the owner
 * passes the same label as the source of whatever that peer sends. A label is an endpoint like any
 * other - the peer sends (through the device's send_peer, which knows the way) - but it names no
 * address: roaming has nothing to move, and a relay that hands over one peer's packet as another's
 * cannot move a peer to where the other one is.
 */
#define WG_EP_OWNER         0xff

/* The address and port as bytes (4 or 16, then the port big-endian): the cookie's input. 0 when
 * the endpoint is unknown or a label. */
size_t wg_endpoint_bytes(const wg_endpoint* e, uint8_t out[18]);

/* Addresses compare by address and port; any other family (a label) by family and port. */
int wg_endpoint_equal(const wg_endpoint* a, const wg_endpoint* b);

/* --- timing ------------------------------------------------------------------------------ */

/*
 * The protocol's times (whitepaper, section 6.1), in whole seconds. WireGuard fixes them; AmneziaWG
 * lets a profile widen each into a range, and a value is drawn from it each time a timer is armed.
 * Which uses draw and which take an end of the range is amneziawg-go's choice (timers.go), noted
 * at each use in wg_peer.c. A device starts with wg_timing_wireguard, every range a single value;
 * set another with wg_device_set_timing.
 */
typedef struct {
    wg_range rekey_timeout;             /* 5: an unanswered initiation is sent again */
    wg_range keepalive_timeout;         /* 10 */
    wg_range rekey_after_time;          /* 120: the initiator renews the session */
    wg_range reject_after_time;         /* 180: keys this old are used for nothing */
    wg_range max_handshake_attempts;    /* 18 retries (90 s of them), then a handshake is given up */
} wg_timing;

extern const wg_timing wg_timing_wireguard;

#define WG_REKEY_JITTER_NS  (334 * 1000000ULL)      /* random extra delay on handshake timers */

/* --- staged packets ---------------------------------------------------------------------- */

/*
 * Packets waiting for a key: a FIFO of length-prefixed records in a ring the owner provides. When
 * it is full the OLDEST packets make room, as in Linux - after an outage the newest traffic is the
 * one worth sending. An empty record is a keepalive.
 */
typedef struct {
    uint8_t* mem;
    size_t   cap;
    size_t   head;                      /* ring offset of the oldest record */
    size_t   used;                      /* bytes of records */
    size_t   count;                     /* records */
    uint64_t dropped;                   /* records pushed out to make room */
} wg_stage;

void wg_stage_init(wg_stage* q, uint8_t* mem, size_t cap);

/* Appends a packet (len <= WG_MAX_PACKET), pushing out the oldest records as needed. 0 when the
 * packet could never fit. */
int wg_stage_push(wg_stage* q, const uint8_t* pkt, size_t len);

/* Copies the oldest packet to `out` (WG_MAX_PACKET bytes are enough) and returns its length; the
 * record stays. Only with count > 0. */
size_t wg_stage_peek(const wg_stage* q, uint8_t* out);

/* Removes the oldest record. */
void wg_stage_drop(wg_stage* q);

void wg_stage_clear(wg_stage* q);

/* --- the peer ---------------------------------------------------------------------------- */

struct wg_device;

typedef struct wg_peer {
    struct wg_peer*   next;             /* the device's list */
    struct wg_device* dev;

    wg_noise_remote   noise;            /* static key, PSK, handshake */
    wg_cookie_maker   cookie;           /* the macs we add, the cookie it gave us */
    wg_session        session;          /* transport keys */
    wg_endpoint       endpoint;         /* configured, then wherever it last spoke from (or a label) */
    wg_range          persistent_keepalive;         /* seconds, drawn anew each time; 0..0 = off */
    wg_stage          staged;

    /* timers: deadlines, WG_NEVER when not armed */
    uint64_t          t_retransmit_handshake;
    uint64_t          t_send_keepalive;
    uint64_t          t_new_handshake;
    uint64_t          t_zero_key_material;
    uint64_t          t_persistent_keepalive;
    unsigned          handshake_attempts;
    unsigned          max_handshake_attempts;       /* drawn for each new handshake */
    int               need_another_keepalive;
    int               sent_lastminute_handshake;
    uint64_t          last_sent_handshake_ns;       /* initiations: at most one per REKEY_TIMEOUT */
    int               has_sent_handshake;

    /* what the UI and UAPI show */
    uint64_t          last_handshake_ns;            /* monotonic; valid with has_handshake */
    int               has_handshake;
    uint64_t          rx_bytes;                     /* datagram bytes: delivered and keepalives in, */
    uint64_t          tx_bytes;                     /* everything out */
    wg_drop_reason    last_drop;                    /* why the last data message was refused */
} wg_peer;

/* --- configuration ----------------------------------------------------------------------- */

void wg_peer_set_psk(wg_peer* p, const uint8_t psk[WG_KEY_LEN]);
void wg_peer_set_endpoint(wg_peer* p, const wg_endpoint* ep);

/* Turning it on sends a keepalive at once - which starts a handshake when there is no session,
 * the way a client behind NAT connects. 0 turns it off. */
void wg_peer_set_persistent_keepalive(wg_peer* p, uint16_t seconds, uint64_t now_ns);

/* The same with AmneziaWG's range: each interval is drawn from lo..hi seconds. 0..0 is off. */
void wg_peer_set_persistent_keepalive_range(wg_peer* p, wg_range seconds, uint64_t now_ns);

/* Starts a handshake now ("connect"). Rate-limited like every initiation: one per REKEY_TIMEOUT. */
void wg_peer_initiate(wg_peer* p, uint64_t now_ns);

/*
 * AllowedIPs: the prefixes this peer is the route for, and the only sources it may send from.
 * Allowing a prefix another peer holds moves it here. 0 for a bad prefix, or when the device's
 * table has no room left (see wg_device_set_allowedips_storage).
 */
int  wg_peer_allow(wg_peer* p, int family, const uint8_t* addr, uint8_t cidr);
int  wg_peer_disallow(wg_peer* p, int family, const uint8_t* addr, uint8_t cidr);
void wg_peer_disallow_all(wg_peer* p);

/* The earliest armed deadline, WG_NEVER if none. */
uint64_t wg_peer_next_deadline(const wg_peer* p);

/* --- driven by wg_device ------------------------------------------------------------------ */

void wg_peer_init(wg_peer* p, struct wg_device* dev, const wg_key* public_key,
                  uint8_t* stage_mem, size_t stage_cap);

/* Stops everything: timers, staged packets, handshake, keys. The configuration stays. */
void wg_peer_reset(wg_peer* p);

/* The device came up: send what was staged, start the persistent keepalive. */
void wg_peer_up(wg_peer* p, uint64_t now_ns);

/* Fires the timers that are due. */
void wg_peer_tick(wg_peer* p, uint64_t now_ns);

/* A packet for this peer: sealed and sent at once, or staged until a handshake gives keys. 0 when
 * it cannot go (no endpoint, where a label counts as one; no room to wait), with the reason in
 * `why` (may be NULL). */
int wg_peer_send(wg_peer* p, const uint8_t* pkt, size_t len, uint64_t now_ns, wg_drop_reason* why);

/* The device consumed an initiation from this peer (mac1 checked): answer it. */
void wg_peer_on_initiation(wg_peer* p, const wg_endpoint* src, size_t len, uint64_t now_ns);

/* The device consumed a response to our initiation: start the session. */
void wg_peer_on_response(wg_peer* p, const wg_endpoint* src, size_t len, uint64_t now_ns);

/*
 * A data message whose receiver index names one of this peer's keypairs, decrypted in place. The
 * packet inside must be IP, whole, and from a source that routes to this peer; it is then cut to
 * its own length and handed to the device's deliver upcall. 1 for a keepalive (empty, or starting
 * with a zero byte: AmneziaWG pads keepalives with zeroes, and no IP packet starts with one) or a
 * delivered packet; 0 otherwise, the reason in last_drop (an authentic but dishonest packet still
 * counts as the peer speaking: roaming and timers see it, as in Linux).
 */
int wg_peer_on_data(wg_peer* p, uint8_t* msg, size_t len, const wg_endpoint* src, uint64_t now_ns);

#endif /* WG_PEER_H */
