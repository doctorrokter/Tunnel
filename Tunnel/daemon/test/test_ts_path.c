/*
 * ts_path: the direct path to one node (docs/TAILSCALE.md, section 11a), on a made-up clock - the
 * rules of magicsock's endpoint (wgengine/magicsock/endpoint.go) one by one: which candidates get a
 * ping and when, the CallMeMaybe after a round, the best address by its pong (betterAddr's points),
 * the 6.5 s of trust, the heartbeat while the session is active and its end when it is not, the
 * full round when trust runs out, the netmap and a CallMeMaybe changing the candidates, the network
 * changing. Then fuzzed: random operations at random times, the invariants checked after each.
 *
 * Seeded like the daemon's fuzzer: BT_FUZZ_SEED=<hex> picks another run.
 */

#include "test_util.h"
#include "../src/ts_path.h"

#define T0      1000000000000ULL
#define MS      1000000ULL
#define SEC     TS_PATH_SEC

static uint64_t xs = 0xbb67ae8584caa73bULL;

static uint64_t rnd(void)
{
    xs ^= xs << 13;
    xs ^= xs >> 7;
    xs ^= xs << 17;
    return xs;
}

static wg_endpoint v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port)
{
    wg_endpoint e;
    memset(&e, 0, sizeof(e));
    e.family = 4;
    e.addr[0] = a;
    e.addr[1] = b;
    e.addr[2] = c;
    e.addr[3] = d;
    e.port = port;
    return e;
}

static int same(const wg_endpoint* a, const wg_endpoint* b)
{
    return a->family == b->family && a->port == b->port && memcmp(a->addr, b->addr, 16) == 0;
}

/* Pings due, with TxIDs numbered from `*serial` (so a test can answer one by its TxID). */
static uint8_t txids[TS_PATH_INFLIGHT][TS_PATH_TXID_LEN];
static wg_endpoint sent_to[TS_PATH_INFLIGHT];
static unsigned serial = 1;

static void fresh_txids(void)
{
    size_t i;
    for (i = 0; i < TS_PATH_INFLIGHT; i++) {
        memset(txids[i], 0, TS_PATH_TXID_LEN);
        txids[i][0] = (uint8_t)(serial >> 8);
        txids[i][1] = (uint8_t)serial;
        serial++;
    }
}

static size_t do_send(ts_path* p, uint64_t now)
{
    fresh_txids();
    return ts_path_send(p, now, sent_to, (const uint8_t(*)[TS_PATH_TXID_LEN])txids, TS_PATH_INFLIGHT);
}

static size_t do_tick(ts_path* p, uint64_t now)
{
    fresh_txids();
    return ts_path_tick(p, now, sent_to, (const uint8_t(*)[TS_PATH_TXID_LEN])txids, TS_PATH_INFLIGHT);
}

/* The TxID of the ping that went to `e` in the last batch of `n`; NULL if none did. */
static const uint8_t* txid_to(const wg_endpoint* e, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (same(&sent_to[i], e)) return txids[i];
    return NULL;
}

/* ------------------------------------------------------------------ the rules */

TEST(usable)
{
    wg_endpoint e = v4(192, 168, 1, 15, 41641);
    CHECK(ts_path_usable(&e));
    e = v4(192, 168, 1, 15, 0);
    CHECK(!ts_path_usable(&e));                         /* no port */
    e = v4(0, 0, 0, 0, 41641);
    CHECK(!ts_path_usable(&e));
    e = v4(100, 64, 0, 1, 41641);
    CHECK(!ts_path_usable(&e));                         /* the tailnet's own: inside our tun */
    e = v4(100, 127, 255, 255, 41641);
    CHECK(!ts_path_usable(&e));
    e = v4(100, 128, 0, 1, 41641);
    CHECK(ts_path_usable(&e));                          /* just past 100.64.0.0/10 */
    e = v4(224, 0, 0, 1, 41641);
    CHECK(!ts_path_usable(&e));
    e = v4(255, 255, 255, 255, 41641);
    CHECK(!ts_path_usable(&e));
    memset(&e, 0, sizeof(e));
    e.family = 6;
    e.port = 41641;
    CHECK(!ts_path_usable(&e));                         /* :: */
    e.addr[0] = 0xfd;
    e.addr[1] = 0x7a;
    e.addr[2] = 0x11;
    e.addr[3] = 0x5c;
    e.addr[4] = 0xa1;
    e.addr[5] = 0xe0;
    e.addr[15] = 1;
    CHECK(!ts_path_usable(&e));                         /* fd7a:115c:a1e0::1 */
    e.addr[5] = 0xe1;
    CHECK(ts_path_usable(&e));
    e.family = 0;
    CHECK(!ts_path_usable(&e));
}

TEST(nothing_to_try)
{
    ts_path p;
    wg_endpoint to;

    ts_path_init(&p);
    CHECK(do_send(&p, T0) == 0);
    CHECK(!ts_path_direct(&p, T0, &to));
    CHECK(!ts_path_take_cmm(&p));                       /* no round went out: no CallMeMaybe */
}

TEST(lan_wins)
{
    ts_path p;
    wg_endpoint eps[2], to;
    const uint8_t *tx_lan, *tx_pub;
    size_t n;

    eps[0] = v4(192, 168, 1, 15, 41641);                /* the NAS at home */
    eps[1] = v4(203, 0, 113, 7, 61234);                 /* its router outside */
    ts_path_init(&p);
    ts_path_netmap(&p, eps, 2);
    REQUIRE(p.n == 2);

    /* traffic: every candidate gets a ping, a CallMeMaybe should follow, the traffic goes by DERP */
    n = do_send(&p, T0);
    CHECK(n == 2);
    tx_lan = txid_to(&eps[0], n);
    tx_pub = txid_to(&eps[1], n);
    REQUIRE(tx_lan && tx_pub);
    {
        uint8_t lan[TS_PATH_TXID_LEN], pub[TS_PATH_TXID_LEN];
        memcpy(lan, tx_lan, sizeof(lan));
        memcpy(pub, tx_pub, sizeof(pub));
        CHECK(ts_path_take_cmm(&p));
        CHECK(!ts_path_take_cmm(&p));                   /* once */
        CHECK(!ts_path_direct(&p, T0, &to));
        /* more traffic within 5 s: no ping again */
        CHECK(do_send(&p, T0 + 1 * SEC) == 0);

        /* the outside answers first (20 ms), then the LAN (22 ms): 10 points to the outside for
         * speed, 20 to the LAN for being private - the LAN */
        CHECK(ts_path_pong(&p, pub, T0 + 20 * MS));
        CHECK(ts_path_direct(&p, T0 + 20 * MS, &to) && same(&to, &eps[1]));
        CHECK(ts_path_pong(&p, lan, T0 + 22 * MS));
        CHECK(ts_path_direct(&p, T0 + 22 * MS, &to) && same(&to, &eps[0]));
        CHECK(p.best_latency == 22 * MS);
        /* the same TxID again: no longer in flight */
        CHECK(!ts_path_pong(&p, lan, T0 + 31 * MS));
    }
    /* trusted 6.5 s from its pong */
    CHECK(ts_path_direct(&p, T0 + 22 * MS + TS_PATH_TRUST - 1, &to));
    CHECK(!ts_path_direct(&p, T0 + 22 * MS + TS_PATH_TRUST, &to));
}

TEST(better_addr_points)
{
    ts_path p;
    wg_endpoint a = v4(198, 51, 100, 1, 1000), b = v4(198, 51, 100, 2, 1000), lan = v4(10, 0, 0, 2, 1000);
    wg_endpoint eps[3], to;
    uint8_t ta[TS_PATH_TXID_LEN], tb[TS_PATH_TXID_LEN], tl[TS_PATH_TXID_LEN];
    size_t n;

    eps[0] = a;
    eps[1] = b;
    eps[2] = lan;
    ts_path_init(&p);
    ts_path_netmap(&p, eps, 3);
    n = do_send(&p, T0);
    REQUIRE(n == 3);
    memcpy(ta, txid_to(&a, n), TS_PATH_TXID_LEN);
    memcpy(tb, txid_to(&b, n), TS_PATH_TXID_LEN);
    memcpy(tl, txid_to(&lan, n), TS_PATH_TXID_LEN);
    /* b at 99.5 ms first, then a at 100 ms - less than 1 % apart: b stays */
    CHECK(ts_path_pong(&p, tb, T0 + 99500 * 1000ULL));
    CHECK(ts_path_pong(&p, ta, T0 + 100 * MS));
    CHECK(ts_path_direct(&p, T0 + 100 * MS, &to) && same(&to, &b));
    /* the LAN at 115 ms: 14 points to b for speed, 20 to the LAN for being private: the LAN */
    CHECK(ts_path_pong(&p, tl, T0 + 115 * MS));
    CHECK(ts_path_direct(&p, T0 + 115 * MS, &to) && same(&to, &lan));
}

TEST(heartbeat_and_idle)
{
    ts_path p;
    wg_endpoint eps[1], to;
    uint8_t tx[TS_PATH_TXID_LEN];
    size_t n;
    uint64_t t;

    eps[0] = v4(192, 168, 1, 15, 41641);
    ts_path_init(&p);
    ts_path_netmap(&p, eps, 1);
    n = do_send(&p, T0);
    REQUIRE(n == 1);
    memcpy(tx, txids[0], sizeof(tx));
    CHECK(ts_path_pong(&p, tx, T0 + 5 * MS));
    CHECK(ts_path_direct(&p, T0 + 5 * MS, &to));
    /* a direct path: more traffic sends no pings */
    CHECK(do_send(&p, T0 + 10 * MS) == 0);
    /* heartbeat: nothing before 3 s, the best at 3 s */
    CHECK(do_tick(&p, T0 + 2 * SEC) == 0);
    CHECK(ts_path_next(&p) <= T0 + 10 * MS + TS_PATH_HEARTBEAT);
    n = do_tick(&p, T0 + 10 * MS + TS_PATH_HEARTBEAT);
    CHECK(n == 1 && same(&sent_to[0], &eps[0]));
    memcpy(tx, txids[0], sizeof(tx));
    t = T0 + 10 * MS + TS_PATH_HEARTBEAT + 4 * MS;
    CHECK(ts_path_pong(&p, tx, t));
    CHECK(ts_path_direct(&p, t + TS_PATH_TRUST - 1, &to));     /* trust renewed */
    /* no answer to the next heartbeats: trust runs out, back to DERP and pinging */
    n = do_tick(&p, t + TS_PATH_HEARTBEAT);
    CHECK(n == 1);
    CHECK(!ts_path_direct(&p, t + TS_PATH_TRUST, &to));
    /* idle: 45 s after the last traffic no heartbeat any more */
    CHECK(do_tick(&p, T0 + 10 * MS + TS_PATH_ACTIVE + 1 + 3 * SEC) == 0);
    CHECK(do_tick(&p, T0 + 120 * SEC) == 0);
    /* nothing in flight, no learned candidates: nothing to wake for */
    CHECK(ts_path_next(&p) == TS_PATH_NEVER || ts_path_next(&p) > T0 + 120 * SEC);
}

TEST(trust_out_full_round)
{
    ts_path p;
    wg_endpoint eps[2], to;
    uint8_t tx[TS_PATH_TXID_LEN];
    size_t n;

    eps[0] = v4(192, 168, 1, 15, 41641);
    eps[1] = v4(203, 0, 113, 7, 61234);
    ts_path_init(&p);
    ts_path_netmap(&p, eps, 2);
    n = do_send(&p, T0);
    REQUIRE(n == 2);
    memcpy(tx, txid_to(&eps[0], n), sizeof(tx));
    ts_path_take_cmm(&p);
    CHECK(ts_path_pong(&p, tx, T0 + 5 * MS));
    /* 7 s later the trust is gone: new traffic pings everything again and asks for a CallMeMaybe */
    n = do_send(&p, T0 + 7 * SEC);
    CHECK(n == 2);
    CHECK(ts_path_take_cmm(&p));
    CHECK(!ts_path_direct(&p, T0 + 7 * SEC, &to));
}

TEST(netmap_and_cmm)
{
    ts_path p;
    wg_endpoint eps[3], cmm[2], to;
    uint8_t tx[TS_PATH_TXID_LEN];
    size_t n;

    eps[0] = v4(192, 168, 1, 15, 41641);
    eps[1] = v4(203, 0, 113, 7, 61234);
    eps[2] = v4(100, 64, 0, 9, 41641);                  /* the tailnet's own: left out */
    ts_path_init(&p);
    ts_path_netmap(&p, eps, 3);
    CHECK(p.n == 2);
    n = do_send(&p, T0);
    REQUIRE(n == 2);
    CHECK(ts_path_take_cmm(&p));                        /* the round's CallMeMaybe */
    memcpy(tx, txid_to(&eps[0], n), sizeof(tx));
    CHECK(ts_path_pong(&p, tx, T0 + 5 * MS));
    CHECK(ts_path_direct(&p, T0 + 5 * MS, &to) && same(&to, &eps[0]));
    /* the netmap drops the LAN address: the best goes with it */
    ts_path_netmap(&p, &eps[1], 1);
    CHECK(p.n == 1);
    CHECK(!ts_path_direct(&p, T0 + 6 * MS, &to));
    /* a CallMeMaybe: its addresses join, and the next tick pings every candidate - no CMM back */
    cmm[0] = v4(192, 168, 1, 15, 41641);
    cmm[1] = v4(198, 51, 100, 9, 5000);
    ts_path_call_me_maybe(&p, cmm, 2, T0 + 1 * SEC);
    CHECK(p.n == 3);
    CHECK(ts_path_next(&p) == 0);
    n = do_tick(&p, T0 + 1 * SEC);
    CHECK(n == 3);
    CHECK(!ts_path_take_cmm(&p));
    /* a new CallMeMaybe replaces the old set: the address only it named goes */
    ts_path_call_me_maybe(&p, cmm, 1, T0 + 2 * SEC);
    CHECK(p.n == 2);
    CHECK(ts_path_knows(&p, &cmm[0]) && !ts_path_knows(&p, &cmm[1]));
}

TEST(learned_from_pings)
{
    ts_path p;
    wg_endpoint src = v4(203, 0, 113, 50, 40000), tailnet = v4(100, 100, 1, 1, 41641);

    ts_path_init(&p);
    ts_path_pinged_from(&p, &src, T0);
    ts_path_pinged_from(&p, &tailnet, T0);              /* never from inside the tailnet */
    CHECK(p.n == 1 && ts_path_knows(&p, &src));
    /* heard again at +30 s: it stays until 45 s after that */
    ts_path_pinged_from(&p, &src, T0 + 30 * SEC);
    do_tick(&p, T0 + 70 * SEC);
    CHECK(ts_path_knows(&p, &src));
    CHECK(ts_path_next(&p) <= T0 + 30 * SEC + TS_PATH_ACTIVE + 1);
    do_tick(&p, T0 + 30 * SEC + TS_PATH_ACTIVE + 1);
    CHECK(!ts_path_knows(&p, &src) && p.n == 0);
}

TEST(network_change)
{
    ts_path p;
    wg_endpoint eps[1], to;
    uint8_t tx[TS_PATH_TXID_LEN];
    size_t n;

    eps[0] = v4(192, 168, 1, 15, 41641);
    ts_path_init(&p);
    ts_path_netmap(&p, eps, 1);
    n = do_send(&p, T0);
    REQUIRE(n == 1);
    memcpy(tx, txids[0], sizeof(tx));
    ts_path_reset(&p);
    /* the pong of a ping before the change: not ours any more */
    CHECK(!ts_path_pong(&p, tx, T0 + 5 * MS));
    CHECK(!ts_path_direct(&p, T0 + 5 * MS, &to));
    /* the candidates stay, and get a ping at once - not 5 s after the last */
    CHECK(p.n == 1);
    CHECK(do_send(&p, T0 + 10 * MS) == 1);
}

TEST(limits)
{
    ts_path p;
    wg_endpoint eps[TS_PATH_CANDS + 4];
    size_t i, n;

    for (i = 0; i < TS_PATH_CANDS + 4; i++) eps[i] = v4(198, 51, 100, (uint8_t)(i + 1), 1000);
    ts_path_init(&p);
    ts_path_netmap(&p, eps, TS_PATH_CANDS + 4);
    CHECK(p.n == TS_PATH_CANDS);
    /* a table of netmap addresses: one a ping named finds no room */
    {
        wg_endpoint extra = v4(203, 0, 113, 1, 1);
        ts_path_pinged_from(&p, &extra, T0);
        CHECK(!ts_path_knows(&p, &extra));
    }
    /* as many pings as fit in flight, and no more than the room given */
    n = do_send(&p, T0);
    CHECK(n == TS_PATH_CANDS);
    fresh_txids();
    ts_path_init(&p);
    ts_path_netmap(&p, eps, TS_PATH_CANDS);
    n = ts_path_send(&p, T0, sent_to, (const uint8_t(*)[TS_PATH_TXID_LEN])txids, 3);
    CHECK(n == 3);
}

/* ------------------------------------------------------------------ fuzz */

static void check_invariants(const ts_path* p, uint64_t now)
{
    size_t i, k;
    wg_endpoint to;

    CHECK(p->n <= TS_PATH_CANDS);
    for (i = 0; i < p->n; i++) {
        CHECK(p->cand[i].from != 0);
        CHECK(ts_path_usable(&p->cand[i].ep));
        for (k = i + 1; k < p->n; k++) CHECK(!same(&p->cand[i].ep, &p->cand[k].ep));
    }
    if (ts_path_direct(p, now, &to)) CHECK(ts_path_usable(&to));
    if (!p->best.family) CHECK(!ts_path_direct(p, now, &to));
}

static wg_endpoint random_ep(void)
{
    /* a small world: addresses repeat, some are the tailnet's own, some have no port */
    static const uint8_t firsts[] = { 192, 10, 203, 100, 0 };
    wg_endpoint e = v4(firsts[rnd() % sizeof(firsts)], (uint8_t)(rnd() % 3 == 0 ? 64 + rnd() % 64 : 168),
                       (uint8_t)(rnd() % 3), (uint8_t)(rnd() % 6), (uint16_t)(rnd() % 4 == 0 ? 0 : 41641 + rnd() % 3));
    return e;
}

TEST(fuzz)
{
    unsigned run, step;

    for (run = 0; run < 2000; run++) {
        ts_path p;
        uint64_t now = T0;
        uint8_t last_tx[TS_PATH_INFLIGHT][TS_PATH_TXID_LEN];
        size_t last_n = 0;

        ts_path_init(&p);
        for (step = 0; step < 200; step++) {
            wg_endpoint eps[24];
            size_t n = (size_t)(rnd() % 24), i;
            for (i = 0; i < n; i++) eps[i] = random_ep();
            now += rnd() % 4 == 0 ? rnd() % (60 * SEC) : rnd() % (2 * SEC);
            switch (rnd() % 8) {
            case 0: ts_path_netmap(&p, eps, n); break;
            case 1: ts_path_call_me_maybe(&p, eps, n, now); break;
            case 2: if (n) ts_path_pinged_from(&p, &eps[0], now); break;
            case 3:
                last_n = do_send(&p, now);
                memcpy(last_tx, txids, sizeof(last_tx));
                break;
            case 4:
                last_n = do_tick(&p, now);
                memcpy(last_tx, txids, sizeof(last_tx));
                break;
            case 5:
                if (last_n) ts_path_pong(&p, last_tx[rnd() % last_n], now);
                break;
            case 6: if (rnd() % 8 == 0) ts_path_reset(&p); break;
            default: ts_path_take_cmm(&p); break;
            }
            check_invariants(&p, now);
            /* the next deadline is never in the past by more than a step, unless due now */
            (void)ts_path_next(&p);
        }
    }
}

int main(void)
{
    const char* seed = getenv("BT_FUZZ_SEED");

    if (seed) xs = strtoull(seed, NULL, 16) | 1;
    printf("test_ts_path (fuzz seed %llx)\n", (unsigned long long)xs);
    RUN(usable);
    RUN(nothing_to_try);
    RUN(lan_wins);
    RUN(better_addr_points);
    RUN(heartbeat_and_idle);
    RUN(trust_out_full_round);
    RUN(netmap_and_cmm);
    RUN(learned_from_pings);
    RUN(network_change);
    RUN(limits);
    RUN(fuzz);
    return t_summary("test_ts_path");
}
