/*
 * wg_allowedips - cryptokey routing: which peer an address belongs to.
 *
 * Every peer owns a set of prefixes (its AllowedIPs). An outgoing packet goes to the peer whose
 * prefix matches its DESTINATION most specifically; an incoming one is accepted only if its SOURCE
 * resolves, by the same longest-prefix match, to the peer it came from. A prefix belongs to one peer
 * at a time: giving it to another moves it.
 *
 * The table is a path-compressed binary trie per family, as in Linux and wireguard-go: a lookup
 * walks at most 32 (IPv4) or 128 (IPv6) bits however many prefixes there are - and split-tunnel
 * profiles ("everything except these networks", common for Russia) carry hundreds to thousands.
 * Nodes come from a pool the owner provides; a table of n prefixes needs at most 2n - 1 nodes per
 * family (every prefix, plus the branch points where prefixes part). Nodes refer to each other by
 * index, not by pointer, so a table can move to a bigger pool whole (wg_allowedips_grow).
 *
 * Also here: the few facts of an IP header that routing needs (wg_ip_parse).
 */

#ifndef WG_ALLOWEDIPS_H
#define WG_ALLOWEDIPS_H

#include <stddef.h>
#include <stdint.h>

struct wg_peer;

#define WG_AIP_NONE (-1)

typedef struct {
    uint8_t         bits[16];           /* the prefix, zero past cidr; network byte order */
    uint8_t         cidr;
    uint8_t         family;             /* 4 or 6; 0 = the node is free */
    int32_t         child[2];           /* by the first bit after the prefix */
    int32_t         parent;             /* WG_AIP_NONE at a root */
    struct wg_peer* peer;               /* NULL: a branch point with no route of its own */
} wg_allowedips_node;

typedef struct {
    wg_allowedips_node* nodes;
    int32_t             cap;
    int32_t             used;
    int32_t             free_list;      /* through child[0] */
    int32_t             root[2];        /* IPv4, IPv6 */
} wg_allowedips;

/* An empty table over `cap` nodes (NULL/0: a table that refuses every insert). */
void wg_allowedips_init(wg_allowedips* t, wg_allowedips_node* nodes, size_t cap);

/*
 * Moves the table to another pool of `cap` nodes, no fewer than it has: every node is copied to
 * the same index, so every prefix and every lookup stays as it was, and the rest of the new pool
 * is free. The old pool is not touched again and goes back through `old` (if not NULL; NULL when
 * the table had none). 0, with nothing changed, for a NULL pool, a smaller one, or one of more
 * than 2^31 - 1 nodes.
 */
int wg_allowedips_grow(wg_allowedips* t, wg_allowedips_node* nodes, size_t cap,
                       wg_allowedips_node** old);

/*
 * Gives `family` (4 or 6) prefix addr/cidr to `peer`; host bits past cidr are ignored. An existing
 * prefix just changes owner. 0 for bad arguments or when the pool is too small - the table is then
 * exactly as it was.
 */
int wg_allowedips_insert(wg_allowedips* t, int family, const uint8_t* addr, uint8_t cidr,
                         struct wg_peer* peer);

/* Takes the exact prefix away from `peer`. 0 if `peer` does not own it. */
int wg_allowedips_remove(wg_allowedips* t, int family, const uint8_t* addr, uint8_t cidr,
                         struct wg_peer* peer);

void wg_allowedips_remove_peer(wg_allowedips* t, struct wg_peer* peer);

/* The peer for an address (4 or 16 bytes): the longest matching prefix wins. NULL: no route. */
struct wg_peer* wg_allowedips_lookup(const wg_allowedips* t, int family, const uint8_t* addr);

/* Calls `fn` for every prefix `peer` owns (for UAPI and the UI). */
void wg_allowedips_walk(const wg_allowedips* t, const struct wg_peer* peer,
                        void (*fn)(void* ctx, int family, const uint8_t* addr, uint8_t cidr),
                        void* ctx);

/* --- IP packets --------------------------------------------------------------------------- */

typedef struct {
    int            family;              /* 4 or 6; 0: not an IP packet (or shorter than its header) */
    const uint8_t* src;                 /* 4 or 16 bytes inside the packet */
    const uint8_t* dst;
    size_t         len;                 /* the length the header claims */
} wg_ip;

/*
 * Reads version, addresses and length from a packet of `len` bytes. 1 when it is IPv4 or IPv6 and
 * the claimed length fits in `len` (a decrypted packet is then cut to it, dropping the padding).
 * 0 otherwise; `ip->family` still says whether it was IP at all (a lying length) or not.
 */
int wg_ip_parse(const uint8_t* pkt, size_t len, wg_ip* ip);

#endif /* WG_ALLOWEDIPS_H */
