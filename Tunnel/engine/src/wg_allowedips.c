/*
 * wg_allowedips - see wg_allowedips.h.
 *
 * The trie's invariants:
 *   - a node stands for the prefix (bits, cidr); its children extend that prefix, sorted by the
 *     first bit after it;
 *   - a node without a peer is a branch point and has exactly two children - anything less and it
 *     is spliced out.
 * Written from the idea (Linux's allowedips.c and wireguard-go's trie work the same way); no code
 * was taken from either.
 */

#include "wg_allowedips.h"

#include <string.h>

#define NONE WG_AIP_NONE

static unsigned family_bits(int family)
{
    return family == 4 ? 32 : family == 6 ? 128 : 0;
}

static int family_slot(int family)
{
    return family == 6;
}

/* Bit `pos` of a key, counting from the most significant bit of the first byte. */
static unsigned bit_at(const uint8_t* key, unsigned pos)
{
    return (key[pos >> 3] >> (7 - (pos & 7))) & 1;
}

/* How many leading bits a and b share, counting no further than `max`. */
static unsigned common_bits(const uint8_t* a, const uint8_t* b, unsigned max)
{
    unsigned n = 0, i = 0;
    uint8_t x;

    while (n < max) {
        x = a[i] ^ b[i];
        i++;
        if (x) {
            while (!(x & 0x80)) {
                x = (uint8_t)(x << 1);
                n++;
            }
            return n < max ? n : max;
        }
        n += 8;
    }
    return max;
}

/* The first `cidr` bits of addr, zero after. */
static void prefix_of(uint8_t out[16], const uint8_t* addr, unsigned cidr)
{
    unsigned full = cidr / 8, rem = cidr % 8;

    memset(out, 0, 16);
    memcpy(out, addr, full);
    if (rem) out[full] = (uint8_t)(addr[full] & (0xff << (8 - rem)));
}

/* --------------------------------------------------------------------- node pool */

void wg_allowedips_init(wg_allowedips* t, wg_allowedips_node* nodes, size_t cap)
{
    int32_t i;

    memset(t, 0, sizeof(*t));
    t->nodes = nodes;
    t->cap = nodes ? (int32_t)cap : 0;
    t->root[0] = t->root[1] = NONE;
    t->free_list = NONE;
    for (i = t->cap - 1; i >= 0; i--) {
        memset(&nodes[i], 0, sizeof(nodes[i]));
        nodes[i].child[0] = t->free_list;
        t->free_list = i;
    }
}

int wg_allowedips_grow(wg_allowedips* t, wg_allowedips_node* nodes, size_t cap,
                       wg_allowedips_node** old)
{
    int32_t i;

    if (!nodes || cap < (size_t)t->cap || cap > 0x7fffffff) return 0;
    /* memmove: still right if the owner hands in the very pool the table has, grown in place */
    if (t->cap) memmove(nodes, t->nodes, (size_t)t->cap * sizeof(*nodes));
    /* Zeroed, as init leaves them: a scan of the pool (remove_peer, walk) reads family 0 as free. */
    for (i = (int32_t)cap - 1; i >= t->cap; i--) {
        memset(&nodes[i], 0, sizeof(nodes[i]));
        nodes[i].child[0] = t->free_list;
        t->free_list = i;
    }
    if (old) *old = t->nodes;
    t->nodes = nodes;
    t->cap = (int32_t)cap;
    return 1;
}

static int32_t node_new(wg_allowedips* t, int family, const uint8_t* key, unsigned cidr,
                        struct wg_peer* peer)
{
    int32_t i = t->free_list;
    wg_allowedips_node* n = &t->nodes[i];

    t->free_list = n->child[0];
    t->used++;
    prefix_of(n->bits, key, cidr);
    n->cidr = (uint8_t)cidr;
    n->family = (uint8_t)family;
    n->child[0] = n->child[1] = NONE;
    n->parent = NONE;
    n->peer = peer;
    return i;
}

static void node_free(wg_allowedips* t, int32_t i)
{
    wg_allowedips_node* n = &t->nodes[i];

    memset(n, 0, sizeof(*n));
    n->child[0] = t->free_list;
    t->free_list = i;
    t->used--;
}

/* Puts `child` where `old` was under `parent` (the root when parent is NONE). */
static void replace_child(wg_allowedips* t, int slot, int32_t parent, int32_t old, int32_t child)
{
    if (parent == NONE)                         t->root[slot] = child;
    else if (t->nodes[parent].child[0] == old)  t->nodes[parent].child[0] = child;
    else                                        t->nodes[parent].child[1] = child;
    if (child != NONE) t->nodes[child].parent = parent;
}

static void attach(wg_allowedips* t, int slot, int32_t parent, unsigned dir, int32_t child)
{
    if (parent == NONE) t->root[slot] = child;
    else                t->nodes[parent].child[dir] = child;
    t->nodes[child].parent = parent;
}

/* --------------------------------------------------------------------- the trie */

/*
 * Walks down to the prefix key/cidr. Returns the exact node if there is one; otherwise NONE, with
 * *parent / *dir the place a new node would hang from and *below what currently hangs there.
 */
static int32_t descend(const wg_allowedips* t, int slot, const uint8_t* key, unsigned cidr,
                       int32_t* parent, unsigned* dir, int32_t* below)
{
    int32_t node = t->root[slot];
    const wg_allowedips_node* n;

    *parent = NONE;
    *dir = 0;
    while (node != NONE) {
        n = &t->nodes[node];
        if (n->cidr > cidr || common_bits(n->bits, key, n->cidr) < n->cidr) break;
        if (n->cidr == cidr) return node;
        *parent = node;
        *dir = bit_at(key, n->cidr);
        node = n->child[*dir];
    }
    *below = node;
    return NONE;
}

int wg_allowedips_insert(wg_allowedips* t, int family, const uint8_t* addr, uint8_t cidr,
                         struct wg_peer* peer)
{
    unsigned bits = family_bits(family), dir, common, need;
    int slot = family_slot(family);
    uint8_t key[16];
    int32_t parent, below, node, fresh, fork;

    if (!bits || cidr > bits || !peer) return 0;
    prefix_of(key, addr, cidr);

    node = descend(t, slot, key, cidr, &parent, &dir, &below);
    if (node != NONE) {
        t->nodes[node].peer = peer;                 /* the prefix exists: it changes owner */
        return 1;
    }

    /* What hangs at the insertion point either extends the new prefix (the new node goes above
     * it) or parts from it at some bit (a branch point takes both). Count before touching. */
    common = 0;
    if (below != NONE) {
        unsigned bc = t->nodes[below].cidr;
        common = common_bits(t->nodes[below].bits, key, bc < cidr ? bc : cidr);
    }
    need = (below == NONE || common == cidr) ? 1 : 2;
    if (t->cap - t->used < (int32_t)need) return 0;

    fresh = node_new(t, family, key, cidr, peer);
    if (below == NONE) {
        attach(t, slot, parent, dir, fresh);
    } else if (common == cidr) {
        t->nodes[fresh].child[bit_at(t->nodes[below].bits, cidr)] = below;
        t->nodes[below].parent = fresh;
        attach(t, slot, parent, dir, fresh);
    } else {
        fork = node_new(t, family, key, common, NULL);
        t->nodes[fork].child[bit_at(key, common)] = fresh;
        t->nodes[fork].child[bit_at(t->nodes[below].bits, common)] = below;
        t->nodes[fresh].parent = fork;
        t->nodes[below].parent = fork;
        attach(t, slot, parent, dir, fork);
    }
    return 1;
}

/* Takes the route off node i and prunes what no longer needs to exist. */
static void unroute(wg_allowedips* t, int slot, int32_t i)
{
    wg_allowedips_node* n = &t->nodes[i];
    int32_t parent = n->parent, child, other;

    n->peer = NULL;
    if (n->child[0] != NONE && n->child[1] != NONE) return;     /* stays, as a branch point */

    child = n->child[0] != NONE ? n->child[0] : n->child[1];
    replace_child(t, slot, parent, i, child);
    node_free(t, i);

    /* A branch point left with one child has no reason to exist either. */
    if (parent != NONE && !t->nodes[parent].peer) {
        n = &t->nodes[parent];
        if (n->child[0] == NONE || n->child[1] == NONE) {
            other = n->child[0] != NONE ? n->child[0] : n->child[1];
            replace_child(t, slot, n->parent, parent, other);
            node_free(t, parent);
        }
    }
}

int wg_allowedips_remove(wg_allowedips* t, int family, const uint8_t* addr, uint8_t cidr,
                         struct wg_peer* peer)
{
    unsigned bits = family_bits(family), dir;
    int slot = family_slot(family);
    uint8_t key[16];
    int32_t parent, below, node;

    if (!bits || cidr > bits || !peer) return 0;
    prefix_of(key, addr, cidr);
    node = descend(t, slot, key, cidr, &parent, &dir, &below);
    if (node == NONE || t->nodes[node].peer != peer) return 0;
    unroute(t, slot, node);
    return 1;
}

void wg_allowedips_remove_peer(wg_allowedips* t, struct wg_peer* peer)
{
    int32_t i;

    if (!peer) return;              /* NULL is what branch points hold, not a peer */
    /* Pruning frees other nodes along the way; freed ones read as family 0 and are skipped. */
    for (i = 0; i < t->cap; i++)
        if (t->nodes[i].family && t->nodes[i].peer == peer)
            unroute(t, family_slot(t->nodes[i].family), i);
}

struct wg_peer* wg_allowedips_lookup(const wg_allowedips* t, int family, const uint8_t* addr)
{
    unsigned bits = family_bits(family);
    const wg_allowedips_node* n;
    struct wg_peer* found = NULL;
    int32_t node;

    if (!bits) return NULL;
    node = t->root[family_slot(family)];
    while (node != NONE) {
        n = &t->nodes[node];
        if (common_bits(n->bits, addr, n->cidr) < n->cidr) break;
        if (n->peer) found = n->peer;
        if (n->cidr == bits) break;
        node = n->child[bit_at(addr, n->cidr)];
    }
    return found;
}

void wg_allowedips_walk(const wg_allowedips* t, const struct wg_peer* peer,
                        void (*fn)(void* ctx, int family, const uint8_t* addr, uint8_t cidr),
                        void* ctx)
{
    int32_t i;

    if (!peer) return;
    for (i = 0; i < t->cap; i++)
        if (t->nodes[i].family && t->nodes[i].peer == peer)
            fn(ctx, t->nodes[i].family, t->nodes[i].bits, t->nodes[i].cidr);
}

/* --------------------------------------------------------------------- IP packets */

int wg_ip_parse(const uint8_t* pkt, size_t len, wg_ip* ip)
{
    memset(ip, 0, sizeof(*ip));
    if (len >= 20 && (pkt[0] >> 4) == 4) {
        ip->family = 4;
        ip->src = pkt + 12;
        ip->dst = pkt + 16;
        ip->len = ((size_t)pkt[2] << 8) | pkt[3];
        return ip->len >= 20 && ip->len <= len;
    }
    if (len >= 40 && (pkt[0] >> 4) == 6) {
        ip->family = 6;
        ip->src = pkt + 8;
        ip->dst = pkt + 24;
        ip->len = 40 + (((size_t)pkt[4] << 8) | pkt[5]);
        return ip->len <= len;
    }
    return 0;
}
