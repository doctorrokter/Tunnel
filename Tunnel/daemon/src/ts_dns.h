/*
 * ts_dns - MagicDNS's resolver at 100.100.100.100 and fd7a:115c:a1e0::53 (docs/TAILSCALE.md,
 * section 8a), sans-IO.
 *
 * The phone's system DNS points at 100.100.100.100, which the tailnet's route already takes into the
 * tun: a query arrives as an IP packet read from it, the answer goes back into it as one. No socket
 * of the phone listens on port 53.
 *   - A name of the tailnet (what the lookup callback says is ours) is answered here: A and AAAA
 *     from the netmap, NODATA for other kinds of record, NXDOMAIN for a name under the MagicDNS
 *     domain that the tailnet does not have. TTL 600, as tailscaled's.
 *   - Any other name is forwarded: ts_dns_query gives the DNS message to send upstream (its id
 *     ours, its EDNS size cut to TS_DNS_UDP_MAX so that the answer fits the tun), the caller sends
 *     it, and ts_dns_answer turns the upstream's answer into the IP packet for the tun.
 *   - A name under a split-DNS route (DNSConfig.Routes, the lookup says which) is forwarded to that
 *     route's servers, not the default ones; one under a route we cannot follow (its servers are DoH
 *     and the like) gets SERVFAIL - it never goes to servers it was not meant for.
 *   - Opcodes other than QUERY get NOTIMP, a query without exactly one question FORMERR, a query
 *     that would be forwarded with no upstream known SERVFAIL. Anything else that is not a query
 *     to us - a response, a fragment, IP options we do not walk, a malformed packet - is dropped.
 *
 * Bounded: at most TS_DNS_PENDING queries wait for upstream at a time (more are dropped - the phone's
 * resolver asks again), each for TS_DNS_TIMEOUT_NS. An upstream's answer is taken only for a query
 * waiting under its id with the very question it carries. Nothing is allocated; every read is
 * checked against the packet's length, names are walked without following compression pointers.
 */

#ifndef TS_DNS_H
#define TS_DNS_H

#include <stddef.h>
#include <stdint.h>

#define TS_DNS_PENDING      64
#define TS_DNS_TIMEOUT_NS   (5ULL * 1000000000ULL)
#define TS_DNS_TTL          600
#define TS_DNS_UDP_MAX      1232            /* EDNS size forwarded: with IPv6 and UDP it fills 1280 */
#define TS_DNS_PKT_MAX      1280            /* the tun's MTU: no packet we put in is longer */
#define TS_DNS_ANSWERS_MAX  8               /* addresses in one local answer */
#define TS_DNS_TEXT_MAX     253             /* a name as text, no trailing dot */

typedef enum {
    TS_DNS_NAME_OTHER = 0,                  /* not the tailnet's: forward it to the default servers */
    TS_DNS_NAME_NX,                         /* under the MagicDNS domain, not in the tailnet: NXDOMAIN */
    TS_DNS_NAME_OURS,                       /* the tailnet's: its addresses (none - NODATA) */
    TS_DNS_NAME_ROUTED,                     /* a split-DNS route's (*route: which): forward it to its servers */
    TS_DNS_NAME_FAIL                        /* a route we cannot follow (DoH...): SERVFAIL, never elsewhere */
} ts_dns_name_kind;

/*
 * The tailnet's view of `name` (lower case, no trailing dot, `len` bytes, NUL after it): for OURS
 * up to `cap` addresses of `family` (4 or 6) into out, their number in *n; for ROUTED the caller's
 * number for the route in *route.
 */
typedef ts_dns_name_kind (*ts_dns_lookup_fn)(void* ctx, const char* name, size_t len, int family,
                                             uint8_t (*out)[16], size_t cap, size_t* n, int* route);

typedef struct {
    int      used;
    uint16_t id;                            /* the id upstream sees */
    uint16_t client_id;                     /* the phone's */
    uint8_t  family;                        /* the phone's side: 4 or 6 */
    uint8_t  client[16];
    uint16_t client_port;
    uint64_t question;                      /* a hash of the question section, as sent */
    uint64_t deadline;
} ts_dns_wait;

typedef struct {
    ts_dns_lookup_fn lookup;
    void*            ctx;
    uint32_t         rng;
    ts_dns_wait      wait[TS_DNS_PENDING];
    /* counters, for the log */
    uint64_t         answered, forwarded, upstream, expired, dropped;
} ts_dns;

void ts_dns_init(ts_dns* r, ts_dns_lookup_fn lookup, void* ctx, uint32_t seed);

/* An IP packet read from the tun: UDP to the resolver's address, port 53? (Cheap: the caller asks
 * for every packet of a Tailscale tunnel.) */
int ts_dns_is_ours(const uint8_t* pkt, size_t len);

typedef enum {
    TS_DNS_DROP = 0,
    TS_DNS_ANSWER,                          /* out: the IP packet for the tun */
    TS_DNS_FORWARD                          /* out: the DNS message for upstream */
} ts_dns_action;

/* A packet ts_dns_is_ours took. `can_forward` 0: no default upstream is known (SERVFAIL rather than
 * wait; a routed name goes to its route's servers all the same). For a FORWARD, *route is the route
 * the lookup named, -1 for the default servers. out needs TS_DNS_PKT_MAX bytes. */
ts_dns_action ts_dns_query(ts_dns* r, const uint8_t* pkt, size_t len, int can_forward, uint64_t now,
                           uint8_t* out, size_t cap, size_t* out_len, int* route);

/* An upstream's answer (the DNS message it sent): 1 and the IP packet for the tun in out
 * (TS_DNS_PKT_MAX bytes); 0 when it answers no query that waits. Too long for the tun - the header
 * and the question with TC set (the phone's resolver may ask again over TCP). */
int ts_dns_answer(ts_dns* r, const uint8_t* msg, size_t len, uint8_t* out, size_t cap, size_t* out_len);

/* Queries waiting past their time are let go - the phone's resolver asks again; how many went in
 * *gone. The next deadline (~0ULL: none). */
uint64_t ts_dns_expire(ts_dns* r, uint64_t now, unsigned* gone);

/* Lets every waiting query go (upstream changed, the tunnel goes). */
void ts_dns_reset(ts_dns* r);

#endif /* TS_DNS_H */
