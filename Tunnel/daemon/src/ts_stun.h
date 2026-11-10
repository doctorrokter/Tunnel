/*
 * ts_stun - STUN as Tailscale speaks it (TAILSCALE.md section 11a, stage 2), without I/O: the
 * binding request magicsock's netcheck sends to a DERP region's STUN port and the reading of the
 * answer - the address and port the server saw us at, which is our address outside every NAT on
 * the way (refs/tailscale: net/stun/stun.go):
 *
 *   request    00 01 | length 00 14 | cookie 21 12 a4 42 | TxID (12)
 *              | SOFTWARE 80 22 00 08 "tailnode" | FINGERPRINT 80 28 00 04 crc32 ^ 0x5354554e
 *   response   01 01 | length | cookie | TxID | attributes, each type (2) | length (2) | value padded
 *              to 4; XOR-MAPPED-ADDRESS (0x0020, and 0x8020 that servers send too) says where we
 *              are - family 1 (IPv4) or 2 (IPv6), the port XOR 0x2112, the address XOR the cookie
 *              (and the TxID for IPv6); MAPPED-ADDRESS (0x0001), the same in clear, only when there is
 *              no XOR one
 *
 * Read as stun.ParseResponse reads it: the length may be shorter than the datagram (the rest is
 * not looked at), never longer; one broken attribute, or a broken address attribute, refuses the
 * whole answer; of several address attributes the last of each kind counts; an IPv4 address mapped
 * into IPv6 comes back as IPv4.
 */

#ifndef TS_STUN_H
#define TS_STUN_H

#include <stddef.h>
#include <stdint.h>

#include "wg_peer.h"

#define TS_STUN_TXID_LEN        12
#define TS_STUN_REQUEST_LEN     40
#define TS_STUN_PORT_DEFAULT    3478    /* a DERP node's STUNPort 0 */

/* Whether a datagram is STUN at all: 20 bytes or more, the top two bits zero, the cookie. */
int ts_stun_is(const uint8_t* pkt, size_t len);

/* The binding request with `txid` into `out` (TS_STUN_REQUEST_LEN bytes); 0 when `cap` is short. */
size_t ts_stun_request(uint8_t* out, size_t cap, const uint8_t txid[TS_STUN_TXID_LEN]);

/* A binding success response: 1 with its TxID and where the server saw us (family 4 or 6); 0 for
 * anything else. */
int ts_stun_parse_response(const uint8_t* pkt, size_t len, uint8_t txid[TS_STUN_TXID_LEN], wg_endpoint* at);

/*
 * Rounds - our address outside every NAT, as magicsock's netcheck learns it, all on the caller's
 * clock (ns) and still without I/O:
 *
 *   a round      one binding request to each of up to TS_STUN_SERVERS servers (the home region's
 *                first, then the fastest others - the caller picks them), a second try after
 *                TS_STUN_RETRY_NS to a server that has not answered, over after TS_STUN_ROUND_NS or
 *                once every server has answered
 *   the answer   the first server to answer says where we are (netcheck's GlobalV4); another that
 *                saw us elsewhere means the NAT maps per destination - a hard NAT (its
 *                MappingVariesByDestIP), where a node can reach us only if its own side is open
 *   when         asked for (the start, a DERP map, a changed network: ts_stun_want), then every
 *                20-26 s while there is traffic to a node in the last TS_STUN_ACTIVE_NS - just under
 *                the 30 s many NATs keep a UDP mapping (magicsock's periodic ReSTUN); idle, none,
 *                and traffic after more than 20 s of none asks for one at once (ts_stun_traffic)
 *   keeping it   a round without an answer keeps the last address for TS_STUN_KEEP_NS since it was
 *                last seen (magicsock's endpointTracker, 5 min 10 s); a changed network forgets it
 *                at once (ts_stun_forget)
 *
 * Only an answer from a server of the running round with the TxID sent to it counts.
 */

#define TS_STUN_SERVERS         3
#define TS_STUN_TRIES           2
#define TS_STUN_RETRY_NS        (500ULL * 1000000ULL)
#define TS_STUN_ROUND_NS        (3ULL * 1000000000ULL)
#define TS_STUN_EVERY_NS        (20ULL * 1000000000ULL)     /* ... plus up to TS_STUN_JITTER_NS */
#define TS_STUN_JITTER_NS       (6ULL * 1000000000ULL)
#define TS_STUN_ACTIVE_NS       (45ULL * 1000000000ULL)
#define TS_STUN_KEEP_NS         (310ULL * 1000000000ULL)

typedef struct {
    wg_endpoint server;
    uint8_t     txid[TS_STUN_TXID_LEN];
    uint8_t     tries;                  /* sent so far this round */
    uint8_t     answered;
    uint64_t    sent_at;                /* the last try */
    wg_endpoint seen;                   /* where it saw us, once answered */
} ts_stun_probe;

typedef struct {
    uint8_t     family;                 /* 4 or 6: the socket's - an answer seeing us in the other says nothing */
    ts_stun_probe probe[TS_STUN_SERVERS];
    size_t      n;                      /* this round's servers; 0: no round running */
    uint64_t    round_end;
    size_t      answers;                /* this round's so far */
    wg_endpoint first;                  /* this round's first answer */
    int         round_varies;

    int         want;                   /* a round as soon as there are servers */
    uint64_t    next;                   /* the periodic one; 0: none planned */
    uint64_t    last_end;               /* when the last round ended; 0: never */

    wg_endpoint global;                 /* family 0: not known */
    uint64_t    global_seen;            /* when a round last said so */
    int         varies;                 /* the last round that had answers from several servers */
} ts_stun_state;

/* Rounds for a socket of `family` (4 or 6): only answers that see us in that family count. */
void ts_stun_init(ts_stun_state* st, int family);

/* A round as soon as possible. */
void ts_stun_want(ts_stun_state* st);

/* The network changed: the address is forgotten, a running round dropped, a new one wanted. */
void ts_stun_forget(ts_stun_state* st);

/* Traffic to a node at `now`: after an idle spell (no periodic round planned, the last one more than
 * TS_STUN_EVERY_NS ago or never), a round is wanted. */
void ts_stun_traffic(ts_stun_state* st, uint64_t now);

/* 1 when a round should begin now: wanted (or the periodic one due while `active`) and none
 * running. A periodic one due while not active is dropped instead. */
int ts_stun_due(ts_stun_state* st, uint64_t now, int active);

/* Begins a round with `n` servers (at most TS_STUN_SERVERS are taken) and a TxID for each. n = 0:
 * nothing to ask - the wish stays until servers come (ts_stun_want again with a DERP map). */
void ts_stun_begin(ts_stun_state* st, const wg_endpoint* servers, const uint8_t (*txids)[TS_STUN_TXID_LEN],
                   size_t n, uint64_t now);

/* The requests to send now - first tries and second ones - as server and TxID, at most `cap`. */
size_t ts_stun_sends(ts_stun_state* st, uint64_t now, wg_endpoint* to, uint8_t (*txid)[TS_STUN_TXID_LEN],
                     size_t cap);

/* Whether `from` is a server of the running round: its datagrams are STUN, not WireGuard. */
int ts_stun_knows(const ts_stun_state* st, const wg_endpoint* from);

/* A datagram from `from` that ts_stun_knows: 1 when it was the answer to our request (taken). */
int ts_stun_answer(ts_stun_state* st, const wg_endpoint* from, const uint8_t* pkt, size_t len, uint64_t now);

/* The clock: ends the round when every server answered or its time is up, plans the next periodic
 * one while `active` (`jitter` random), lets an address go that was not seen for TS_STUN_KEEP_NS.
 * 1 when the address or the hard-NAT finding changed - our endpoints are to be told again. */
int ts_stun_tick(ts_stun_state* st, uint64_t now, int active, uint32_t jitter);

/* When ts_stun_tick or ts_stun_sends has work next; ~0ULL: none. */
uint64_t ts_stun_next(const ts_stun_state* st);

#endif /* TS_STUN_H */
