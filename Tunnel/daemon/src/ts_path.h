/*
 * ts_path - the direct path to one node (TAILSCALE.md section 11a), without I/O: magicsock's
 * endpoint (refs/tailscale wgengine/magicsock/endpoint.go) for what a phone needs. It knows the
 * node's addresses to try, which of them answered a ping and how fast, whether the best one may
 * carry the traffic now, and when to ping again; the caller sends the pings, the CallMeMaybe and the
 * traffic, all on the clock it passes in.
 *
 *   candidates   the node's endpoints from the netmap (they go when the netmap drops them), from its
 *                CallMeMaybe (the set it sent last) and the addresses its pings came from (they go
 *                45 s after the last one) - at most TS_PATH_CANDS; an address of the tailnet's own
 *                ranges, of no port or no address is never one (ts_path_usable)
 *   sending      while no direct address is trusted, every candidate not pinged for 5 s gets a ping
 *                and a CallMeMaybe follows over DERP; the traffic itself goes over DERP meanwhile
 *   pong         found by its TxID (5 s at most): the address it was sent to may become the best
 *                (betterAddr: how much faster, a private address +20, link-local +30, loopback +50,
 *                IPv6 +10, a change only for more than 1 %); the best is trusted 6.5 s from its pong
 *   heartbeat    every 3 s while the session is active (traffic to the node in the last 45 s): the
 *                best gets a ping, and every candidate when the trust ran out, or a full round is a
 *                minute old and the best is slower than 5 ms
 *   change       of the network (ts_path_reset): no best, no trust, nothing in flight
 */

#ifndef TS_PATH_H
#define TS_PATH_H

#include <stddef.h>
#include <stdint.h>

#include "wg_peer.h"

#define TS_PATH_CANDS           16
#define TS_PATH_INFLIGHT        16
#define TS_PATH_TXID_LEN        12

#define TS_PATH_SEC             1000000000ULL
#define TS_PATH_PING_EVERY      (5 * TS_PATH_SEC)           /* discoPingInterval */
#define TS_PATH_PING_TIMEOUT    (5 * TS_PATH_SEC)           /* pingTimeoutDuration */
#define TS_PATH_TRUST           (6500 * 1000000ULL)         /* trustUDPAddrDuration */
#define TS_PATH_HEARTBEAT       (3 * TS_PATH_SEC)           /* heartbeatInterval */
#define TS_PATH_ACTIVE          (45 * TS_PATH_SEC)          /* sessionActiveTimeout */
#define TS_PATH_UPGRADE         (60 * TS_PATH_SEC)          /* upgradeUDPDirectInterval */
#define TS_PATH_GOOD_ENOUGH     (5 * 1000000ULL)            /* goodEnoughLatency */
#define TS_PATH_NEVER           (~0ULL)

/* Where a candidate came from - any of them. */
#define TS_PATH_NETMAP          1u
#define TS_PATH_CMM             2u
#define TS_PATH_PINGED          4u

typedef struct {
    wg_endpoint ep;
    unsigned    from;                   /* TS_PATH_NETMAP | TS_PATH_CMM | TS_PATH_PINGED */
    uint64_t    last_ping;              /* we pinged it; 0: never */
    uint64_t    heard;                  /* its last ping to us came from here */
} ts_path_cand;

typedef struct {
    uint8_t     txid[TS_PATH_TXID_LEN];
    wg_endpoint to;
    uint64_t    sent;                   /* 0: a free slot */
} ts_path_ping;

typedef struct {
    ts_path_cand cand[TS_PATH_CANDS];
    size_t       n;
    ts_path_ping inflight[TS_PATH_INFLIGHT];
    wg_endpoint  best;                  /* family 0: none */
    uint64_t     best_latency;
    uint64_t     trust_until;           /* the best carries traffic before this */
    uint64_t     last_full;             /* the last round of pings to every candidate; 0: none yet */
    uint64_t     last_send;             /* traffic to the node; 0: none yet */
    uint64_t     last_heartbeat;
    int          cmm_due;               /* a round went out: a CallMeMaybe over DERP should follow */
    int          ping_all;              /* a CallMeMaybe came: every candidate at the next tick */
} ts_path;

void ts_path_init(ts_path* p);

/* An address a node may be reached at directly: IPv4 or IPv6, a port, an address that is no
 * wildcard, multicast or the tailnet's own (100.64.0.0/10, fd7a:115c:a1e0::/48 - those are inside
 * the tun, a packet there would come back to us). */
int ts_path_usable(const wg_endpoint* e);

/* The node's endpoints as the netmap has them now (the set, replacing the last one). */
void ts_path_netmap(ts_path* p, const wg_endpoint* eps, size_t n);

/* Its CallMeMaybe (the set it sent, replacing the last one): every candidate gets a ping at once. */
void ts_path_call_me_maybe(ts_path* p, const wg_endpoint* eps, size_t n, uint64_t now);

/* A ping from the node arrived from `src` (over UDP): a candidate for 45 s. */
void ts_path_pinged_from(ts_path* p, const wg_endpoint* src, uint64_t now);

/* 1 and the address when the traffic may go directly now; 0: over DERP. */
int ts_path_direct(const ts_path* p, uint64_t now, wg_endpoint* to);

/*
 * Traffic for the node now (ts_path_send) or the clock (ts_path_tick): the pings due, at most `cap`,
 * into `to` with their TxIDs taken from `txid` (random bytes the caller drew, one row per slot).
 * Returns how many to send.
 */
size_t ts_path_send(ts_path* p, uint64_t now, wg_endpoint* to, const uint8_t (*txid)[TS_PATH_TXID_LEN], size_t cap);
size_t ts_path_tick(ts_path* p, uint64_t now, wg_endpoint* to, const uint8_t (*txid)[TS_PATH_TXID_LEN], size_t cap);

/* 1 once after a round of pings went out: time for a CallMeMaybe over DERP. */
int ts_path_take_cmm(ts_path* p);

/* A pong: 1 when its TxID is a ping of ours in flight (then the path may change); 0 otherwise. */
int ts_path_pong(ts_path* p, const uint8_t txid[TS_PATH_TXID_LEN], uint64_t now);

/* An address the node may send from: one of its candidates or the best. */
int ts_path_knows(const ts_path* p, const wg_endpoint* src);

/* The next moment ts_path_tick has work: TS_PATH_NEVER for none. */
uint64_t ts_path_next(const ts_path* p);

/* The network changed: no best, no trust, nothing in flight; the candidates stay. */
void ts_path_reset(ts_path* p);

#endif /* TS_PATH_H */
