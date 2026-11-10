/*
 * wg_allowedips: the trie on hand-picked cases (nesting, masked host bits, owners moving, pruning,
 * a full pool), a randomized run against a plain list with longest-prefix match, a full table
 * moving to a bigger pool, and IP header parsing.
 */

#include "test_util.h"
#include "../src/wg_allowedips.h"

/* The table only compares peers: any distinct pointers do. */
static char tag[8];
#define PA ((struct wg_peer*)&tag[0])
#define PB ((struct wg_peer*)&tag[1])
#define PC ((struct wg_peer*)&tag[2])
#define PD ((struct wg_peer*)&tag[3])

static wg_allowedips_node pool[4096];
static wg_allowedips T;

static uint8_t abuf[16][16];
static int anext;

static const uint8_t* v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    uint8_t* p = abuf[anext++ & 15];
    p[0] = a; p[1] = b; p[2] = c; p[3] = d;
    return p;
}

/* An IPv6 address from four 32-bit words, most significant first. */
static const uint8_t* v6(uint32_t w0, uint32_t w1, uint32_t w2, uint32_t w3)
{
    uint8_t* p = abuf[anext++ & 15];
    uint32_t w[4];
    int i;
    w[0] = w0; w[1] = w1; w[2] = w2; w[3] = w3;
    for (i = 0; i < 16; i++) p[i] = (uint8_t)(w[i / 4] >> (24 - 8 * (i % 4)));
    return p;
}

#define ADD4(peer, a, b, c, d, cidr)  wg_allowedips_insert(&T, 4, v4(a, b, c, d), cidr, peer)
#define AT4(a, b, c, d)               wg_allowedips_lookup(&T, 4, v4(a, b, c, d))
#define ADD6(peer, w0, w1, w2, w3, cidr)  wg_allowedips_insert(&T, 6, v6(w0, w1, w2, w3), cidr, peer)
#define AT6(w0, w1, w2, w3)           wg_allowedips_lookup(&T, 6, v6(w0, w1, w2, w3))

static void fresh(size_t cap)
{
    wg_allowedips_init(&T, pool, cap);
}

/* ------------------------------------------------------------------------------ hand-picked */

TEST(empty_and_default_routes)
{
    fresh(64);
    CHECK(AT4(1, 2, 3, 4) == NULL);
    CHECK(ADD4(PA, 0, 0, 0, 0, 0));
    CHECK(AT4(1, 2, 3, 4) == PA && AT4(255, 255, 255, 255) == PA);
    CHECK(AT6(0x20010db8, 0, 0, 1) == NULL);            /* the families do not mix */
    CHECK(ADD6(PB, 0, 0, 0, 0, 0));
    CHECK(AT6(0x20010db8, 0, 0, 1) == PB && AT4(1, 2, 3, 4) == PA);
    CHECK(T.used == 2);
}

TEST(longest_prefix_wins)
{
    fresh(64);
    CHECK(ADD4(PA, 10, 0, 0, 0, 8));
    CHECK(ADD4(PB, 10, 1, 0, 0, 16));
    CHECK(ADD4(PC, 10, 1, 2, 0, 24));
    CHECK(ADD4(PD, 10, 1, 2, 3, 32));
    CHECK(AT4(10, 9, 9, 9) == PA);
    CHECK(AT4(10, 1, 9, 9) == PB);
    CHECK(AT4(10, 1, 2, 9) == PC);
    CHECK(AT4(10, 1, 2, 3) == PD);
    CHECK(AT4(11, 0, 0, 1) == NULL);
    CHECK(AT4(9, 255, 255, 255) == NULL);

    /* Inserted the other way round, the answers are the same. */
    fresh(64);
    CHECK(ADD4(PD, 10, 1, 2, 3, 32));
    CHECK(ADD4(PC, 10, 1, 2, 0, 24));
    CHECK(ADD4(PB, 10, 1, 0, 0, 16));
    CHECK(ADD4(PA, 10, 0, 0, 0, 8));
    CHECK(AT4(10, 9, 9, 9) == PA && AT4(10, 1, 9, 9) == PB && AT4(10, 1, 2, 9) == PC);
    CHECK(AT4(10, 1, 2, 3) == PD && AT4(11, 0, 0, 1) == NULL);
    CHECK(T.used == 4);                                 /* a chain: no branch points */
}

TEST(host_bits_are_ignored)
{
    fresh(64);
    CHECK(ADD4(PA, 192, 168, 4, 77, 24));               /* means 192.168.4.0/24 */
    CHECK(AT4(192, 168, 4, 1) == PA && AT4(192, 168, 5, 1) == NULL);
    CHECK(ADD4(PB, 192, 168, 4, 200, 24));              /* the same prefix: it moves to B */
    CHECK(AT4(192, 168, 4, 1) == PB && T.used == 1);
    CHECK(!wg_allowedips_remove(&T, 4, v4(192, 168, 4, 9), 24, PA));    /* A no longer owns it */
    CHECK(wg_allowedips_remove(&T, 4, v4(192, 168, 4, 9), 24, PB));
    CHECK(AT4(192, 168, 4, 1) == NULL && T.used == 0);
}

TEST(parting_prefixes)
{
    fresh(64);
    /* Siblings: a branch point at 10.0.0.0/24 joins them, with no route of its own. */
    CHECK(ADD4(PA, 10, 0, 0, 0, 25));
    CHECK(ADD4(PB, 10, 0, 0, 128, 25));
    CHECK(T.used == 3);
    CHECK(AT4(10, 0, 0, 1) == PA && AT4(10, 0, 0, 200) == PB && AT4(10, 0, 1, 1) == NULL);

    /* The branch point takes a route when that exact prefix is added... */
    CHECK(ADD4(PC, 10, 0, 0, 0, 24));
    CHECK(T.used == 3 && AT4(10, 0, 0, 1) == PA);

    /* ...and keeps it when a sibling goes; without a route it would be pruned too. */
    CHECK(wg_allowedips_remove(&T, 4, v4(10, 0, 0, 0), 25, PA));
    CHECK(AT4(10, 0, 0, 1) == PC && T.used == 2);
    CHECK(wg_allowedips_remove(&T, 4, v4(10, 0, 0, 0), 24, PC));
    CHECK(AT4(10, 0, 0, 1) == NULL && AT4(10, 0, 0, 200) == PB && T.used == 1);
    CHECK(wg_allowedips_remove(&T, 4, v4(10, 0, 0, 128), 25, PB));
    CHECK(T.used == 0 && T.root[0] == WG_AIP_NONE);
}

TEST(ipv6_odd_lengths)
{
    fresh(64);
    CHECK(ADD6(PA, 0x2001db80, 0, 0, 0, 21));
    CHECK(ADD6(PB, 0x2001db80, 0x00010002, 0, 0, 64));
    CHECK(ADD6(PC, 0x2001db80, 0x00010002, 0xabcdef00, 0, 83));
    CHECK(ADD6(PD, 0x2001db80, 0x00010002, 0xabcdef00, 0x12345678, 128));

    CHECK(AT6(0x2001dbff, 0, 0, 1) == PA);              /* inside /21: 2001:d800::/21 */
    CHECK(AT6(0x2001d800, 0, 0, 1) == PA);
    CHECK(AT6(0x2001e000, 0, 0, 1) == NULL);            /* just past it */
    CHECK(AT6(0x2001db80, 0x00010002, 0x11112222, 0) == PB);
    CHECK(AT6(0x2001db80, 0x00010002, 0xabcdffff, 0xffffffff) == PC);   /* /83 keeps 0xabcd e... */
    CHECK(AT6(0x2001db80, 0x00010002, 0xabcdc000, 0) == PB);            /* ...bit 82 differs */
    CHECK(AT6(0x2001db80, 0x00010002, 0xabcdef00, 0x12345678) == PD);
    CHECK(AT6(0x2001db80, 0x00010002, 0xabcdef00, 0x12345679) == PC);
}

TEST(remove_peer_and_prune)
{
    int i;

    fresh(256);
    /* A and B interleaved, sharing prefixes at every level. */
    for (i = 0; i < 32; i++) {
        CHECK(ADD4(PA, 172, 16, (uint8_t)i, 0, 24));
        CHECK(ADD4(PB, 172, 16, (uint8_t)i, 128, 25));
    }
    CHECK(ADD4(PA, 172, 16, 0, 0, 12));
    CHECK(AT4(172, 16, 5, 1) == PA && AT4(172, 16, 5, 200) == PB && AT4(172, 20, 0, 1) == PA);

    wg_allowedips_remove_peer(&T, PA);
    CHECK(AT4(172, 16, 5, 1) == NULL && AT4(172, 16, 5, 200) == PB && AT4(172, 20, 0, 1) == NULL);
    CHECK(T.used == 32 + 31);                           /* B's 32 prefixes and their branch points */

    wg_allowedips_remove_peer(&T, PB);
    CHECK(T.used == 0 && T.root[0] == WG_AIP_NONE && T.root[1] == WG_AIP_NONE);
    wg_allowedips_remove_peer(&T, NULL);                /* NULL is no one: harmless */
}

TEST(a_full_pool_changes_nothing)
{
    fresh(3);
    CHECK(ADD4(PA, 10, 0, 0, 0, 25));
    CHECK(ADD4(PB, 10, 0, 0, 128, 25));                 /* 3 nodes: two routes, one branch */
    CHECK(!ADD4(PC, 10, 0, 1, 0, 24));                  /* would need two more */
    CHECK(AT4(10, 0, 0, 1) == PA && AT4(10, 0, 0, 200) == PB && AT4(10, 0, 1, 1) == NULL);
    CHECK(ADD4(PC, 10, 0, 0, 0, 24));                   /* an existing node takes it: no room needed */
    CHECK(T.used == 3);

    fresh(0);
    CHECK(!ADD4(PA, 0, 0, 0, 0, 0));
    CHECK(!wg_allowedips_insert(&T, 5, v4(1, 2, 3, 4), 8, PA));       /* no such family */
    fresh(8);
    CHECK(!ADD4(PA, 1, 2, 3, 4, 33));                    /* no such length */
    CHECK(!ADD4(NULL, 1, 2, 3, 4, 8));                   /* no one */
}

static int walked, walked_ok;

static void walk_fn(void* ctx, int family, const uint8_t* addr, uint8_t cidr)
{
    (void)ctx;
    walked++;
    if (family == 4 && cidr == 27 && memcmp(addr, v4(192, 95, 5, 64), 4) == 0) walked_ok++;
    if (family == 6 && cidr == 83 && memcmp(addr, v6(0x26075300, 0x6d8a6bf8, 0xdab1e000, 0), 16) == 0)
        walked_ok++;
}

TEST(walk_lists_masked_prefixes)
{
    fresh(64);
    CHECK(ADD4(PA, 192, 95, 5, 93, 27));
    CHECK(ADD6(PA, 0x26075300, 0x6d8a6bf8, 0xdab1f1df, 0xc05f1523, 83));
    CHECK(ADD4(PB, 192, 95, 5, 0, 24));                 /* someone else's: not listed */
    walked = walked_ok = 0;
    wg_allowedips_walk(&T, PA, walk_fn, NULL);
    CHECK(walked == 2 && walked_ok == 2);
}

TEST(deep_ipv6_chain)
{
    int i;

    /* 128 host routes each one bit longer in common with the last: the deepest trie there is. */
    fresh(1024);
    for (i = 0; i < 128; i++) {
        uint8_t a[16];
        memset(a, 0xff, sizeof(a));
        if (i < 128) a[i / 8] = (uint8_t)(a[i / 8] & ~(0x80 >> (i % 8)));
        CHECK(wg_allowedips_insert(&T, 6, a, 128, i % 2 ? PA : PB));
    }
    {
        uint8_t all[16];
        memset(all, 0xff, sizeof(all));
        CHECK(wg_allowedips_insert(&T, 6, all, 128, PC));
        CHECK(wg_allowedips_lookup(&T, 6, all) == PC);
    }
    wg_allowedips_remove_peer(&T, PA);
    wg_allowedips_remove_peer(&T, PB);
    wg_allowedips_remove_peer(&T, PC);
    CHECK(T.used == 0);
}

/* ------------------------------------------------------------------------------ against a model */

typedef struct {
    int             family;
    uint8_t         addr[16];
    uint8_t         cidr;
    struct wg_peer* peer;
} entry;

static entry model[1600];
static int nmodel;

static uint64_t xs = 0x243f6a8885a308d3ULL;
static uint64_t rnd(void)
{
    xs ^= xs >> 12;
    xs ^= xs << 25;
    xs ^= xs >> 27;
    return xs * 0x2545f4914f6cdd1dULL;
}

static int prefix_match(const uint8_t* p, const uint8_t* a, int cidr)
{
    int i;
    for (i = 0; i < cidr; i++)
        if (((p[i / 8] ^ a[i / 8]) >> (7 - i % 8)) & 1) return 0;
    return 1;
}

static void mask_to(uint8_t out[16], const uint8_t* a, int cidr, int bytes)
{
    int i;
    memset(out, 0, 16);
    memcpy(out, a, (size_t)bytes);
    for (i = cidr; i < bytes * 8; i++) out[i / 8] &= (uint8_t)~(0x80 >> (i % 8));
}

static struct wg_peer* model_lookup(int family, const uint8_t* a)
{
    int i, best = -1;
    for (i = 0; i < nmodel; i++)
        if (model[i].family == family && prefix_match(model[i].addr, a, model[i].cidr)
            && (best < 0 || model[i].cidr > model[best].cidr))
            best = i;
    return best < 0 ? NULL : model[best].peer;
}

static int model_find(int family, const uint8_t* key, int cidr)
{
    int i;
    for (i = 0; i < nmodel; i++)
        if (model[i].family == family && model[i].cidr == cidr && memcmp(model[i].addr, key, 16) == 0)
            return i;
    return -1;
}

/* An address biased towards a few shared prefixes, so routes nest and part a lot. */
static void random_addr(int family, uint8_t a[16])
{
    static const uint8_t bases[3][4] = { { 10, 20, 0, 0 }, { 10, 21, 0, 0 }, { 192, 168, 1, 0 } };
    uint64_t r = rnd(), s = rnd();
    int i;

    for (i = 0; i < 8; i++) a[i] = (uint8_t)(r >> (8 * i));
    for (i = 0; i < 8; i++) a[8 + i] = (uint8_t)(s >> (8 * i));
    if (rnd() % 10 < 7) {
        const uint8_t* b = bases[rnd() % 3];
        a[0] = b[0];
        a[1] = b[1];
        if (rnd() % 2) a[2] = b[2];
    }
}

TEST(against_model)
{
    struct wg_peer* peers[4] = { PA, PB, PC, PD };
    uint8_t a[16], key[16];
    long ops, mismatches = 0, removed = 0, moved = 0;
    int family, bytes, cidr, i;
    struct wg_peer* p;

    fresh(sizeof(pool) / sizeof(pool[0]));
    nmodel = 0;
    for (ops = 0; ops < 60000; ops++) {
        family = rnd() % 3 ? 4 : 6;
        bytes = family == 4 ? 4 : 16;
        random_addr(family, a);
        switch (rnd() % 10) {
        case 0: case 1: case 2: case 3:                 /* give a prefix to someone */
            if (nmodel >= 1500) break;
            cidr = (int)(rnd() % (bytes * 8 + 1));
            p = peers[rnd() % 4];
            mask_to(key, a, cidr, bytes);
            if (!wg_allowedips_insert(&T, family, a, (uint8_t)cidr, p)) { mismatches++; break; }
            i = model_find(family, key, cidr);
            if (i >= 0) {
                model[i].peer = p;
                moved++;
            } else {
                model[nmodel].family = family;
                memcpy(model[nmodel].addr, key, 16);
                model[nmodel].cidr = (uint8_t)cidr;
                model[nmodel].peer = p;
                nmodel++;
            }
            break;
        case 4: case 5:                                 /* take one away, maybe from the wrong owner */
            if (!nmodel) break;
            i = (int)(rnd() % (uint64_t)nmodel);
            p = rnd() % 4 ? model[i].peer : peers[rnd() % 4];
            if (wg_allowedips_remove(&T, model[i].family, model[i].addr, model[i].cidr, p)
                != (p == model[i].peer)) mismatches++;
            if (p == model[i].peer) {
                model[i] = model[--nmodel];
                removed++;
            }
            break;
        default:                                        /* look up, near a route half the time */
            if (nmodel && rnd() % 2) {
                i = (int)(rnd() % (uint64_t)nmodel);
                family = model[i].family;
                bytes = family == 4 ? 4 : 16;
                memcpy(key, model[i].addr, 16);
                for (cidr = model[i].cidr; cidr < bytes * 8; cidr++)
                    if (rnd() % 2) key[cidr / 8] |= (uint8_t)(0x80 >> (cidr % 8));
                memcpy(a, key, 16);
            }
            if (wg_allowedips_lookup(&T, family, a) != model_lookup(family, a)) mismatches++;
            break;
        }
        if (T.used > 2 * nmodel) mismatches++;          /* never more than 2n - 1 per family */
        if (ops % 20000 == 19999) {                     /* now and then a whole peer goes */
            p = peers[rnd() % 4];
            wg_allowedips_remove_peer(&T, p);
            for (i = 0; i < nmodel; )
                if (model[i].peer == p) model[i] = model[--nmodel];
                else i++;
        }
    }
    CHECK(mismatches == 0);
    CHECK(removed > 1000 && moved > 10);

    /* Everything out again: every node back in the pool. */
    while (nmodel) {
        nmodel--;
        CHECK(wg_allowedips_remove(&T, model[nmodel].family, model[nmodel].addr, model[nmodel].cidr,
                                   model[nmodel].peer));
    }
    CHECK(T.used == 0 && T.root[0] == WG_AIP_NONE && T.root[1] == WG_AIP_NONE);
}

/* ------------------------------------------------------------------------------ a bigger pool */

static wg_allowedips_node pool_small[300], pool_big[1200];

/* The free list holds every free node once, and nothing else. */
static int free_list_ok(const wg_allowedips* t)
{
    static uint8_t seen[1200];
    int32_t i, n = 0;

    if (t->cap > (int32_t)sizeof(seen)) return 0;
    memset(seen, 0, sizeof(seen));
    for (i = t->free_list; i != WG_AIP_NONE; i = t->nodes[i].child[0]) {
        if (i < 0 || i >= t->cap || seen[i] || t->nodes[i].family) return 0;
        seen[i] = 1;
        n++;
    }
    return n == t->cap - t->used;
}

/* A random prefix, nesting and parting as in against_model, to a random owner - into the table
 * and the model. 0 when the table has no room for it. */
static int put_random(void)
{
    static struct wg_peer* const owners[4] = { PA, PB, PC, PD };
    uint8_t a[16], key[16];
    int family = rnd() % 3 ? 4 : 6, bytes = family == 4 ? 4 : 16, i;
    int cidr = (int)(rnd() % (uint64_t)(bytes * 8 + 1));
    struct wg_peer* p = owners[rnd() % 4];

    random_addr(family, a);
    mask_to(key, a, cidr, bytes);
    if (!wg_allowedips_insert(&T, family, a, (uint8_t)cidr, p)) return 0;
    i = model_find(family, key, cidr);
    if (i < 0) {
        i = nmodel++;
        model[i].family = family;
        memcpy(model[i].addr, key, 16);
        model[i].cidr = (uint8_t)cidr;
    }
    model[i].peer = p;
    return 1;
}

/* An address to look up, next to one of the model's routes half the time; returns its family. */
static int probe_addr(uint8_t a[16])
{
    int family = rnd() % 3 ? 4 : 6, i, cidr, bytes;

    random_addr(family, a);
    if (nmodel && rnd() % 2) {
        i = (int)(rnd() % (uint64_t)nmodel);
        family = model[i].family;
        bytes = family == 4 ? 4 : 16;
        memcpy(a, model[i].addr, 16);
        for (cidr = model[i].cidr; cidr < bytes * 8; cidr++)
            if (rnd() % 2) a[cidr / 8] |= (uint8_t)(0x80 >> (cidr % 8));
    }
    return family;
}

TEST(growing_the_pool_keeps_every_route)
{
    static uint8_t probes[4000][16];
    static int probe_family[4000];
    static struct wg_peer* answers[4000];
    wg_allowedips_node* old = NULL;
    uint8_t a[16];
    int i, family, used, bad = 0;
    long ops;

    /* A small pool filled until it refuses a prefix, and what it answers for 4000 addresses. */
    wg_allowedips_init(&T, pool_small, 300);
    nmodel = 0;
    while (put_random()) {}
    CHECK(T.used >= 299 && nmodel >= 150);
    for (i = 0; i < 4000; i++) {
        probe_family[i] = probe_addr(probes[i]);
        answers[i] = wg_allowedips_lookup(&T, probe_family[i], probes[i]);
        if (answers[i] != model_lookup(probe_family[i], probes[i])) bad++;
    }
    CHECK(bad == 0);

    /* Not into a smaller pool, nor into none, nor one the int32 indices cannot count: refused,
     * nothing moves. */
    used = T.used;
    CHECK(!wg_allowedips_grow(&T, pool_big, 299, &old) && old == NULL);
    CHECK(!wg_allowedips_grow(&T, NULL, 1200, &old) && old == NULL);
    CHECK(!wg_allowedips_grow(&T, pool_big, (size_t)0x80000000u, &old) && old == NULL);
    CHECK(T.nodes == pool_small && T.cap == 300 && T.used == used);

    /* Into a bigger one that comes full of garbage; then the old one is scribbled over, which the
     * table must not notice: every answer is the same. */
    memset(pool_big, 0x5a, sizeof(pool_big));
    CHECK(wg_allowedips_grow(&T, pool_big, 1200, &old));
    CHECK(old == pool_small && T.nodes == pool_big && T.cap == 1200 && T.used == used);
    memset(pool_small, 0xa5, sizeof(pool_small));
    CHECK(free_list_ok(&T));
    for (i = 0; i < 4000; i++)
        if (wg_allowedips_lookup(&T, probe_family[i], probes[i]) != answers[i]) bad++;
    CHECK(bad == 0);

    /* And it goes on as any table: prefixes in (at most 2n nodes: room for all) and out, lookups,
     * against the model. */
    for (ops = 0; ops < 30000; ops++) {
        switch (rnd() % 4) {
        case 0:
            if (nmodel < 580 && !put_random()) bad++;
            break;
        case 1:
            if (!nmodel) break;
            i = (int)(rnd() % (uint64_t)nmodel);
            if (!wg_allowedips_remove(&T, model[i].family, model[i].addr, model[i].cidr, model[i].peer))
                bad++;
            model[i] = model[--nmodel];
            break;
        default:
            family = probe_addr(a);
            if (wg_allowedips_lookup(&T, family, a) != model_lookup(family, a)) bad++;
            break;
        }
    }
    CHECK(bad == 0 && free_list_ok(&T));
    while (nmodel) {
        nmodel--;
        CHECK(wg_allowedips_remove(&T, model[nmodel].family, model[nmodel].addr, model[nmodel].cidr,
                                   model[nmodel].peer));
    }
    CHECK(T.used == 0 && T.root[0] == WG_AIP_NONE && T.root[1] == WG_AIP_NONE && free_list_ok(&T));

    /* From no pool at all (a device before its storage); then the same pool handed in again. */
    wg_allowedips_init(&T, NULL, 0);
    CHECK(!ADD4(PA, 10, 0, 0, 0, 8));
    CHECK(wg_allowedips_grow(&T, pool_small, 300, &old) && old == NULL && free_list_ok(&T));
    CHECK(ADD4(PA, 10, 0, 0, 0, 8) && ADD4(PB, 10, 1, 0, 0, 16));
    CHECK(wg_allowedips_grow(&T, pool_small, 300, NULL));
    CHECK(AT4(10, 9, 9, 9) == PA && AT4(10, 1, 2, 3) == PB && T.used == 2 && free_list_ok(&T));
}

/* ------------------------------------------------------------------------------ IP headers */

TEST(ip_parse)
{
    uint8_t p[80];
    wg_ip ip;

    memset(p, 0, sizeof(p));
    p[0] = 0x45; p[3] = 60;                             /* IPv4, 60 bytes */
    memcpy(p + 12, v4(10, 0, 0, 1), 4);
    memcpy(p + 16, v4(10, 0, 0, 2), 4);
    CHECK(wg_ip_parse(p, 64, &ip) && ip.family == 4 && ip.len == 60);  /* padding after it */
    CHECK(memcmp(ip.src, v4(10, 0, 0, 1), 4) == 0 && memcmp(ip.dst, v4(10, 0, 0, 2), 4) == 0);
    CHECK(!wg_ip_parse(p, 59, &ip) && ip.family == 4);  /* claims more than there is */
    p[3] = 19;
    CHECK(!wg_ip_parse(p, 64, &ip) && ip.family == 4);  /* less than its own header */
    CHECK(!wg_ip_parse(p, 19, &ip) && ip.family == 0);  /* not even a header */

    memset(p, 0, sizeof(p));
    p[0] = 0x60; p[5] = 20;                             /* IPv6, 40 + 20 bytes */
    memcpy(p + 8, v6(0xfd000000, 0, 0, 1), 16);
    memcpy(p + 24, v6(0x20010db8, 0, 0, 5), 16);
    CHECK(wg_ip_parse(p, 64, &ip) && ip.family == 6 && ip.len == 60);
    CHECK(memcmp(ip.src, v6(0xfd000000, 0, 0, 1), 16) == 0);
    CHECK(memcmp(ip.dst, v6(0x20010db8, 0, 0, 5), 16) == 0);
    CHECK(!wg_ip_parse(p, 59, &ip) && ip.family == 6);
    CHECK(!wg_ip_parse(p, 39, &ip) && ip.family == 0);

    p[0] = 0x55;                                        /* version 5 */
    CHECK(!wg_ip_parse(p, 64, &ip) && ip.family == 0);
}

int main(void)
{
    RUN(empty_and_default_routes);
    RUN(longest_prefix_wins);
    RUN(host_bits_are_ignored);
    RUN(parting_prefixes);
    RUN(ipv6_odd_lengths);
    RUN(remove_peer_and_prune);
    RUN(a_full_pool_changes_nothing);
    RUN(walk_lists_masked_prefixes);
    RUN(deep_ipv6_chain);
    RUN(against_model);
    RUN(growing_the_pool_keeps_every_route);
    RUN(ip_parse);
    return t_summary("test_allowedips");
}
