/*
 * bt_resolve - the daemon's own DNS client for endpoint names (docs/DAEMON.md, section 6), sans-IO
 * like the engine.
 *
 * Why not getaddrinfo: once a tunnel's DNS is set, the system resolver asks the DNS inside the
 * tunnel - which is exactly what does not work while the tunnel reconnects to a server whose address
 * changed. And getaddrinfo blocks the whole loop for seconds on a bad network. So the daemon asks
 * the PHYSICAL network's servers itself, over its socket that bypasses the tunnel, from its poll
 * loop.
 *
 * Two layers:
 *   bt_dns_query / bt_dns_parse   one question and its answer on the wire (RFC 1035): A or AAAA,
 *                                 CNAME chains inside the answer followed, name compression with
 *                                 loop protection, truncated answers used for what they hold
 *   bt_lookup                     a name to addresses: A and AAAA to the servers in turn, a new
 *                                 server on every retry or on SERVFAIL/REFUSED, IPv4 preferred
 *
 * The lookup sends through an upcall and is fed replies and time; the caller owns the socket (UDP,
 * a random source port) and the clock. Plain UDP, no EDNS: an endpoint's few addresses fit in 512
 * bytes.
 */

#ifndef BT_RESOLVE_H
#define BT_RESOLVE_H

#include <stddef.h>
#include <stdint.h>

#include "wg_crypto.h"

#define BT_DNS_PORT         53
#define BT_DNS_TYPE_A       1
#define BT_DNS_TYPE_CNAME   5
#define BT_DNS_TYPE_AAAA    28
#define BT_DNS_NAME_MAX     253
#define BT_DNS_MSG_MAX      1500        /* the largest reply looked at */
#define BT_DNS_MAX_ADDRS    8

#define BT_NEVER            (~0ULL)
#define BT_NSEC_PER_SEC     1000000000ULL

typedef struct {
    uint8_t family;                     /* 4 or 6 */
    uint8_t addr[16];
} bt_addr;

int bt_addr_equal(const bt_addr* a, const bt_addr* b);

/* A host name we will ask about: labels of 1-63 of [A-Za-z0-9_-], 253 characters at most, a
 * trailing dot allowed. Not an address literal - those never reach DNS. */
int bt_dns_name_valid(const char* name);

/* A recursive query for `name` (qtype A or AAAA). The length, 0 when the name is bad or cap short. */
size_t bt_dns_query(uint8_t* out, size_t cap, uint16_t id, const char* name, uint16_t qtype);

typedef struct {
    int      rcode;                     /* 0 ok, 2 SERVFAIL, 3 NXDOMAIN, 5 REFUSED... */
    int      truncated;
    bt_addr  addrs[BT_DNS_MAX_ADDRS];
    size_t   n;
    uint32_t ttl;                       /* the least TTL of the records used; 0 without addresses */
} bt_dns_answer;

/*
 * The reply to OUR question - same id, same name (any case), same type - or 0: anything else is
 * ignored as noise or spoofing. With rcode 0, the addresses of the question's name, following
 * CNAMEs within the answer section.
 */
int bt_dns_parse(const uint8_t* msg, size_t len, uint16_t id, const char* name, uint16_t qtype,
                 bt_dns_answer* out);

/* --- a lookup ------------------------------------------------------------------------------- */

#define BT_LOOKUP_SERVERS       4
#define BT_LOOKUP_ATTEMPTS      4       /* rounds of queries */
#define BT_LOOKUP_RETRY_NS      (2 * BT_NSEC_PER_SEC)

typedef enum {
    BT_LOOKUP_IDLE = 0,
    BT_LOOKUP_RUNNING,
    BT_LOOKUP_DONE,                     /* addrs[0..n) */
    BT_LOOKUP_FAILED                    /* see error */
} bt_lookup_state;

typedef enum {
    BT_LOOKUP_OK = 0,
    BT_LOOKUP_ERR_NAME,                 /* not a name we can ask about */
    BT_LOOKUP_ERR_NO_SERVERS,
    BT_LOOKUP_ERR_NXDOMAIN,             /* the name does not exist */
    BT_LOOKUP_ERR_NODATA,               /* it exists, but has no address of the families asked */
    BT_LOOKUP_ERR_TIMEOUT               /* no usable reply from any server */
} bt_lookup_error;

typedef void (*bt_lookup_send_fn)(void* ctx, const bt_addr* server, const uint8_t* query, size_t len);

typedef struct {
    char            name[BT_DNS_NAME_MAX + 1];      /* lowercase, no trailing dot */
    bt_addr         servers[BT_LOOKUP_SERVERS];
    size_t          n_servers;
    int             want[2];            /* [0] A, [1] AAAA */
    uint16_t        id[2];
    int             answered[2];
    unsigned        attempt;            /* rounds sent */
    uint64_t        deadline;           /* the next round */
    bt_lookup_state state;
    bt_lookup_error error;
    bt_addr         v4[BT_DNS_MAX_ADDRS], v6[BT_DNS_MAX_ADDRS];
    size_t          n4, n6;
    uint32_t        ttl4, ttl6;
    /* the result: IPv4 first */
    bt_addr         addrs[BT_DNS_MAX_ADDRS];
    size_t          n;
    uint32_t        ttl;
} bt_lookup;

/*
 * Starts looking up `name` at `servers` (the first BT_LOOKUP_SERVERS; port 53), asking for A
 * and/or AAAA. The first round goes out at the next tick. Returns 1 when running; 0 when it failed
 * at once (a bad name, no servers, nothing asked), with state and error set.
 */
int bt_lookup_start(bt_lookup* l, const char* name, const bt_addr* servers, size_t n_servers,
                    int want4, int want6, const wg_rng* rng, uint64_t now_ns);

/* Sends a round when due, fails the lookup when the rounds are used up. Returns the next deadline
 * (BT_NEVER once finished). */
uint64_t bt_lookup_tick(bt_lookup* l, uint64_t now_ns, bt_lookup_send_fn send, void* ctx);

/* A datagram that arrived on the lookup's socket. 1 when it was a reply to this lookup (it may have
 * finished it; a SERVFAIL moves on to the next server at the next tick), 0 when ignored. */
int bt_lookup_receive(bt_lookup* l, const bt_addr* from, uint16_t from_port, const uint8_t* msg,
                      size_t len, uint64_t now_ns);

const char* bt_lookup_error_text(bt_lookup_error e);

#endif /* BT_RESOLVE_H */
