/*
 * ts_stun: STUN as Tailscale speaks it (docs/TAILSCALE.md, section 11a, stage 2). The vectors come
 * from Tailscale's own code (vectors/stun, Go): binding requests as stun.Request builds them - ours
 * must be the same bytes - and stun.ParseResponse's verdict on answers of real servers, built ones and
 * hand-made ones, each whole, cut at every length and with every byte flipped: ours must come to the
 * same verdict, address and port. Then fuzzed, each datagram in a heap buffer of exactly its size, so
 * a read past one is caught.
 *
 * Seeded like the daemon's fuzzer: BT_FUZZ_SEED=<hex> picks another run.
 */

#include "test_util.h"
#include "../src/ts_stun.h"
#include "vectors/stun/kat_stun.h"

static uint64_t xs = 0x6a09e667f3bcc909ULL;

static uint64_t rnd(void)
{
    xs ^= xs << 13;
    xs ^= xs >> 7;
    xs ^= xs << 17;
    return xs;
}

/* Our verdict on `n` bytes, held in a heap buffer of exactly that size, against Go's. */
static int same_verdict(const uint8_t* data, size_t n, const stun_verdict* want)
{
    uint8_t* b = (uint8_t*)malloc(n ? n : 1);
    uint8_t txid[TS_STUN_TXID_LEN], addr[16];
    wg_endpoint at;
    int ok, is, same;
    size_t alen;

    if (!b) return 0;
    if (n) memcpy(b, data, n);
    memset(&at, 0xaa, sizeof(at));
    is = ts_stun_is(n ? b : NULL, n);
    ok = ts_stun_parse_response(n ? b : NULL, n, txid, &at);
    same = is == want->is && ok == want->ok;
    if (same && ok) {
        alen = t_hex(addr, sizeof(addr), want->addr);
        same = at.family == want->family && at.port == want->port && alen == (want->family == 4 ? 4u : 16u) &&
               memcmp(at.addr, addr, alen) == 0 && memcmp(txid, b + 8, TS_STUN_TXID_LEN) == 0;
    }
    free(b);
    return same;
}

TEST(requests)
{
    size_t i;
    uint8_t out[64];

    for (i = 0; i < sizeof(stun_requests) / sizeof(stun_requests[0]); i++) {
        const stun_request_vec* v = &stun_requests[i];
        memset(out, 0, sizeof(out));
        CHECK(ts_stun_request(out, sizeof(out), v->txid) == TS_STUN_REQUEST_LEN);
        CHECK_MEM(out, v->req, TS_STUN_REQUEST_LEN);
        CHECK(ts_stun_is(out, TS_STUN_REQUEST_LEN));
        /* a request is not an answer */
        {
            uint8_t txid[TS_STUN_TXID_LEN];
            wg_endpoint at;
            CHECK(!ts_stun_parse_response(out, TS_STUN_REQUEST_LEN, txid, &at));
        }
    }
    CHECK(ts_stun_request(out, TS_STUN_REQUEST_LEN - 1, stun_requests[0].txid) == 0);
    CHECK(ts_stun_request(NULL, sizeof(out), stun_requests[0].txid) == 0);
}

TEST(answers)
{
    size_t i;

    for (i = 0; i < sizeof(stun_fixtures) / sizeof(stun_fixtures[0]); i++) {
        const stun_fixture* f = &stun_fixtures[i];
        int same = same_verdict(f->data, f->len, &f->whole);
        CHECK(same);
        if (!same) fprintf(stderr, "    %s\n", f->name);
    }
}

/* What Go says of the real servers' answers, spelled out (stun_test.go's want*): a check of the
 * generated verdicts themselves. */
TEST(known_addresses)
{
    static const struct { const char* name; int family; const char* addr; uint16_t port; } want[] = {
        { "google-1", 4, "4845212d", 59028 },
        { "stun-sipgate-net-10000", 4, "4845212d", 58539 },
        { "stuntman-server-ipv6", 6, "260200d1b4cfc10038b231fffeef96f6", 37070 },
        { "no-4in6", 4, "d1b4cfc1", 60463 },
        { "in-process-pion-server", 4, "7f000001", 61300 },
    };
    size_t i, k;

    for (i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
        for (k = 0; k < sizeof(stun_fixtures) / sizeof(stun_fixtures[0]); k++) {
            const stun_fixture* f = &stun_fixtures[k];
            uint8_t txid[TS_STUN_TXID_LEN], a[16];
            wg_endpoint at;
            size_t n;
            if (strcmp(f->name, want[i].name) != 0) continue;
            REQUIRE(ts_stun_parse_response(f->data, f->len, txid, &at));
            n = t_hex(a, sizeof(a), want[i].addr);
            CHECK(at.family == want[i].family);
            CHECK(at.port == want[i].port);
            CHECK(memcmp(at.addr, a, n) == 0);
        }
    }
}

TEST(cuts_and_flips)
{
    size_t i, n, p, m;
    int bad = 0;

    for (i = 0; i < sizeof(stun_fixtures) / sizeof(stun_fixtures[0]); i++) {
        const stun_fixture* f = &stun_fixtures[i];
        uint8_t* b = (uint8_t*)malloc(f->len ? f->len : 1);
        REQUIRE(b != NULL);
        for (n = 0; n <= f->len; n++) {
            int same = same_verdict(f->data, n, &f->cut[n]);
            CHECK(same);
            if (!same && bad++ < 10) fprintf(stderr, "    %s cut to %u\n", f->name, (unsigned)n);
        }
        for (p = 0; p < f->len; p++) {
            for (m = 0; m < STUN_MASKS; m++) {
                int same;
                memcpy(b, f->data, f->len);
                b[p] ^= stun_masks[m];
                same = same_verdict(b, f->len, &f->flip[p * STUN_MASKS + m]);
                CHECK(same);
                if (!same && bad++ < 10)
                    fprintf(stderr, "    %s byte %u ^ %02x\n", f->name, (unsigned)p, stun_masks[m]);
            }
        }
        free(b);
    }
}

/* Random datagrams - half of them looking like answers - in buffers of exactly their size: no read
 * past the end (ASan), and what is taken is what the rules allow. */
TEST(fuzz)
{
    int round;

    for (round = 0; round < 300000; round++) {
        size_t n = (size_t)(rnd() % 120), i;
        uint8_t* b = (uint8_t*)malloc(n ? n : 1);
        uint8_t txid[TS_STUN_TXID_LEN];
        wg_endpoint at;
        int ok;
        REQUIRE(b != NULL);
        for (i = 0; i < n; i++) b[i] = (uint8_t)rnd();
        if (n >= 20 && (rnd() & 1)) {
            b[0] = 0x01;
            b[1] = 0x01;
            b[2] = 0;
            b[3] = (uint8_t)(rnd() % (n - 20 + 8));
            b[4] = 0x21; b[5] = 0x12; b[6] = 0xa4; b[7] = 0x42;
            if (n >= 24 && (rnd() & 1)) {
                b[20] = 0x00;
                b[21] = (rnd() & 1) ? 0x20 : 0x01;
            }
        }
        ok = ts_stun_parse_response(n ? b : NULL, n, txid, &at);
        if (ok) {
            CHECK(n >= 20 && ts_stun_is(b, n) && b[0] == 0x01 && b[1] == 0x01);
            CHECK(at.family == 4 || at.family == 6);
            CHECK((size_t)((b[2] << 8) | b[3]) <= n - 20);
            CHECK(memcmp(txid, b + 8, TS_STUN_TXID_LEN) == 0);
        }
        free(b);
    }
}

/* --------------------------------------------------------------------- rounds, on a clock */

#define MS 1000000ULL
#define S  1000000000ULL

static wg_endpoint ep4(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port)
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

static int ep_is(const wg_endpoint* e, const wg_endpoint* want)
{
    return e->family == want->family && e->port == want->port && memcmp(e->addr, want->addr, 16) == 0;
}

/* The answer a server gives: stun's Response for `txid`, saying it saw us at `seen`. */
static size_t reply(uint8_t* out, const uint8_t* txid, const wg_endpoint* seen)
{
    static const uint8_t ck[4] = { 0x21, 0x12, 0xa4, 0x42 };
    size_t i;

    out[0] = 0x01; out[1] = 0x01; out[2] = 0; out[3] = 12;
    memcpy(out + 4, ck, 4);
    memcpy(out + 8, txid, 12);
    out[20] = 0x00; out[21] = 0x20; out[22] = 0; out[23] = 8;
    out[24] = 0; out[25] = 1;
    out[26] = (uint8_t)((seen->port ^ 0x2112) >> 8);
    out[27] = (uint8_t)((seen->port ^ 0x2112) & 0xff);
    for (i = 0; i < 4; i++) out[28 + i] = (uint8_t)(seen->addr[i] ^ ck[i]);
    return 32;
}

static void txids3(uint8_t (*t)[TS_STUN_TXID_LEN], uint8_t base)
{
    size_t i;
    for (i = 0; i < TS_STUN_SERVERS; i++) memset(t[i], base + (uint8_t)i, TS_STUN_TXID_LEN);
}

static const wg_endpoint* srv(int i)
{
    static wg_endpoint s[TS_STUN_SERVERS + 1];
    s[i] = ep4(10, 20, 0, (uint8_t)(1 + i), 3478);
    return &s[i];
}

TEST(round_basic)
{
    ts_stun_state st;
    wg_endpoint servers[2] = { *srv(0), *srv(1) }, to[4], us = ep4(10, 20, 88, 2, 40000);
    uint8_t tx[TS_STUN_SERVERS][TS_STUN_TXID_LEN], got[4][TS_STUN_TXID_LEN], pkt[64];
    uint64_t t = 1000 * S;
    size_t n;

    ts_stun_init(&st, 4);
    CHECK(!ts_stun_due(&st, t, 1));                     /* nobody asked */
    ts_stun_want(&st);
    CHECK(ts_stun_due(&st, t, 0));
    txids3(tx, 1);
    ts_stun_begin(&st, servers, (const uint8_t(*)[TS_STUN_TXID_LEN])tx, 2, t);
    CHECK(!ts_stun_due(&st, t, 1));                     /* one is running */
    n = ts_stun_sends(&st, t, to, got, 4);
    REQUIRE(n == 2);
    CHECK(ep_is(&to[0], srv(0)) && ep_is(&to[1], srv(1)));
    CHECK(memcmp(got[1], tx[1], TS_STUN_TXID_LEN) == 0);
    CHECK(ts_stun_sends(&st, t, to, got, 4) == 0);      /* not twice at once */
    CHECK(ts_stun_knows(&st, srv(1)) && !ts_stun_knows(&st, srv(2)));

    /* the first answer: where we are; the round goes on for the other server */
    n = reply(pkt, tx[0], &us);
    CHECK(ts_stun_answer(&st, srv(0), pkt, n, t + 20 * MS));
    CHECK(!ts_stun_answer(&st, srv(0), pkt, n, t + 21 * MS));   /* the same again: not twice */
    CHECK(ts_stun_tick(&st, t + 30 * MS, 1, 0) == 0);
    CHECK(st.n == 2 && st.global.family == 0);
    n = reply(pkt, tx[1], &us);
    CHECK(ts_stun_answer(&st, srv(1), pkt, n, t + 40 * MS));
    CHECK(ts_stun_tick(&st, t + 40 * MS, 1, 6000) == 1); /* every server answered: over, found */
    CHECK(st.n == 0 && ep_is(&st.global, &us) && !st.varies);
    CHECK(st.next == t + 40 * MS + 26 * S);              /* the most jitter: 26 s */
    CHECK(ts_stun_next(&st) == st.next);
    CHECK(!ts_stun_knows(&st, srv(0)));                  /* no round, no server of ours */
    CHECK(!ts_stun_due(&st, t + 10 * S, 1));
    CHECK(ts_stun_due(&st, st.next, 1));                 /* the periodic one */
}

TEST(round_retry_and_timeout)
{
    ts_stun_state st;
    wg_endpoint servers[1] = { *srv(0) }, to[2];
    uint8_t tx[TS_STUN_SERVERS][TS_STUN_TXID_LEN], got[2][TS_STUN_TXID_LEN];
    uint64_t t = 50 * S;

    ts_stun_init(&st, 4);
    ts_stun_want(&st);
    REQUIRE(ts_stun_due(&st, t, 1));
    txids3(tx, 9);
    ts_stun_begin(&st, servers, (const uint8_t(*)[TS_STUN_TXID_LEN])tx, 1, t);
    CHECK(ts_stun_sends(&st, t, to, got, 2) == 1);
    CHECK(ts_stun_next(&st) == t + TS_STUN_RETRY_NS);
    CHECK(ts_stun_sends(&st, t + 499 * MS, to, got, 2) == 0);
    CHECK(ts_stun_sends(&st, t + 500 * MS, to, got, 2) == 1);   /* the second try, the same TxID */
    CHECK(memcmp(got[0], tx[0], TS_STUN_TXID_LEN) == 0);
    CHECK(ts_stun_sends(&st, t + 2 * S, to, got, 2) == 0);      /* two at most */
    CHECK(ts_stun_next(&st) == t + TS_STUN_ROUND_NS);
    CHECK(ts_stun_tick(&st, t + TS_STUN_ROUND_NS - 1, 1, 0) == 0 && st.n == 1);
    CHECK(ts_stun_tick(&st, t + TS_STUN_ROUND_NS, 1, 0) == 0);  /* over, nothing found, nothing changed */
    CHECK(st.n == 0 && st.global.family == 0 && st.next == t + TS_STUN_ROUND_NS + 20 * S);
}

TEST(round_hard_nat)
{
    ts_stun_state st;
    wg_endpoint servers[3] = { *srv(0), *srv(1), *srv(2) }, to[4];
    wg_endpoint a = ep4(10, 20, 88, 2, 40000), b = ep4(10, 20, 88, 2, 40001);
    uint8_t tx[TS_STUN_SERVERS][TS_STUN_TXID_LEN], got[4][TS_STUN_TXID_LEN], pkt[64];
    uint64_t t = 7 * S;
    size_t n;

    ts_stun_init(&st, 4);
    ts_stun_want(&st);
    REQUIRE(ts_stun_due(&st, t, 1));
    txids3(tx, 20);
    ts_stun_begin(&st, servers, (const uint8_t(*)[TS_STUN_TXID_LEN])tx, 3, t);
    REQUIRE(ts_stun_sends(&st, t, to, got, 4) == 3);
    /* the second server answers first: its view is where we are */
    n = reply(pkt, tx[1], &b);
    CHECK(ts_stun_answer(&st, srv(1), pkt, n, t + 5 * MS));
    n = reply(pkt, tx[0], &a);
    CHECK(ts_stun_answer(&st, srv(0), pkt, n, t + 9 * MS));
    CHECK(ts_stun_tick(&st, t + TS_STUN_ROUND_NS, 1, 0) == 1);      /* the third never answers */
    CHECK(ep_is(&st.global, &b) && st.varies == 1);

    /* next round: one answer alone cannot tell - the finding stays */
    REQUIRE(ts_stun_due(&st, st.next, 1));
    t = st.next;
    txids3(tx, 40);
    ts_stun_begin(&st, servers, (const uint8_t(*)[TS_STUN_TXID_LEN])tx, 3, t);
    REQUIRE(ts_stun_sends(&st, t, to, got, 4) == 3);
    n = reply(pkt, tx[2], &b);
    CHECK(ts_stun_answer(&st, srv(2), pkt, n, t + 5 * MS));
    CHECK(ts_stun_tick(&st, t + TS_STUN_ROUND_NS, 1, 0) == 0);
    CHECK(ep_is(&st.global, &b) && st.varies == 1);

    /* and two that agree: no longer hard */
    t = st.next;
    REQUIRE(ts_stun_due(&st, t, 1));
    txids3(tx, 60);
    ts_stun_begin(&st, servers, (const uint8_t(*)[TS_STUN_TXID_LEN])tx, 2, t);
    REQUIRE(ts_stun_sends(&st, t, to, got, 4) == 2);
    n = reply(pkt, tx[0], &a);
    CHECK(ts_stun_answer(&st, srv(0), pkt, n, t));
    n = reply(pkt, tx[1], &a);
    CHECK(ts_stun_answer(&st, srv(1), pkt, n, t));
    CHECK(ts_stun_tick(&st, t + MS, 1, 0) == 1);
    CHECK(ep_is(&st.global, &a) && st.varies == 0);
}

TEST(round_refusals)
{
    ts_stun_state st;
    wg_endpoint servers[2] = { *srv(0), *srv(1) }, to[4], us = ep4(1, 2, 3, 4, 5), other = ep4(10, 20, 0, 1, 3479);
    uint8_t tx[TS_STUN_SERVERS][TS_STUN_TXID_LEN], got[4][TS_STUN_TXID_LEN], pkt[64], bad[TS_STUN_TXID_LEN];
    uint64_t t = 3 * S;
    size_t n;

    ts_stun_init(&st, 4);
    memset(bad, 0x77, sizeof(bad));
    n = reply(pkt, bad, &us);
    CHECK(!ts_stun_answer(&st, srv(0), pkt, n, t));     /* no round */
    ts_stun_want(&st);
    REQUIRE(ts_stun_due(&st, t, 1));
    txids3(tx, 1);
    ts_stun_begin(&st, servers, (const uint8_t(*)[TS_STUN_TXID_LEN])tx, 2, t);
    n = reply(pkt, tx[0], &us);
    CHECK(!ts_stun_answer(&st, srv(0), pkt, n, t));     /* the right TxID, but nothing was sent yet */
    REQUIRE(ts_stun_sends(&st, t, to, got, 4) == 2);
    n = reply(pkt, bad, &us);
    CHECK(!ts_stun_answer(&st, srv(0), pkt, n, t));     /* a TxID we did not send */
    n = reply(pkt, tx[1], &us);
    CHECK(!ts_stun_answer(&st, srv(0), pkt, n, t));     /* server 1's TxID from server 0 */
    CHECK(!ts_stun_answer(&st, &other, pkt, n, t));     /* from another port */
    CHECK(!ts_stun_answer(&st, srv(1), pkt, 31, t));    /* cut short */
    pkt[1] = 0x11;                                       /* an error response */
    CHECK(!ts_stun_answer(&st, srv(1), pkt, n, t));
    CHECK(ts_stun_tick(&st, t + TS_STUN_ROUND_NS, 0, 0) == 0 && st.global.family == 0);
    CHECK(st.next == 0);                                 /* idle: no periodic one */
}

TEST(round_idle_and_traffic)
{
    ts_stun_state st;
    wg_endpoint servers[1] = { *srv(0) }, to[2], us = ep4(9, 9, 9, 9, 9);
    uint8_t tx[TS_STUN_SERVERS][TS_STUN_TXID_LEN], got[2][TS_STUN_TXID_LEN], pkt[64];
    uint64_t t = 100 * S;
    size_t n;

    ts_stun_init(&st, 4);
    ts_stun_traffic(&st, t);                             /* never had one: wanted */
    CHECK(st.want);
    REQUIRE(ts_stun_due(&st, t, 1));
    txids3(tx, 1);
    ts_stun_begin(&st, servers, (const uint8_t(*)[TS_STUN_TXID_LEN])tx, 1, t);
    REQUIRE(ts_stun_sends(&st, t, to, got, 2) == 1);
    ts_stun_traffic(&st, t);                             /* one is running: nothing more */
    CHECK(!st.want);
    n = reply(pkt, tx[0], &us);
    CHECK(ts_stun_answer(&st, srv(0), pkt, n, t));
    CHECK(ts_stun_tick(&st, t + MS, 1, 0) == 1);
    /* the periodic one comes due while idle: dropped, and nothing is planned */
    CHECK(!ts_stun_due(&st, st.next, 0));
    CHECK(st.next == 0 && !st.want);
    ts_stun_traffic(&st, t + 10 * S);                    /* the last round 10 s ago: not yet */
    CHECK(!st.want);
    ts_stun_traffic(&st, t + MS + 20 * S);               /* 20 s: again */
    CHECK(st.want);
}

TEST(round_keep_and_forget)
{
    ts_stun_state st;
    wg_endpoint servers[1] = { *srv(0) }, to[2], us = ep4(8, 8, 8, 8, 8);
    uint8_t tx[TS_STUN_SERVERS][TS_STUN_TXID_LEN], got[2][TS_STUN_TXID_LEN], pkt[64];
    uint64_t t = 10 * S, seen;
    size_t n;
    int i;

    ts_stun_init(&st, 4);
    ts_stun_want(&st);
    REQUIRE(ts_stun_due(&st, t, 1));
    txids3(tx, 1);
    ts_stun_begin(&st, servers, (const uint8_t(*)[TS_STUN_TXID_LEN])tx, 1, t);
    REQUIRE(ts_stun_sends(&st, t, to, got, 2) == 1);
    n = reply(pkt, tx[0], &us);
    CHECK(ts_stun_answer(&st, srv(0), pkt, n, t));
    CHECK(ts_stun_tick(&st, t, 1, 0) == 1);
    seen = t;
    /* rounds without an answer keep it ... */
    for (i = 0; i < 12; i++) {
        t = st.next;
        REQUIRE(ts_stun_due(&st, t, 1));
        txids3(tx, (uint8_t)(10 + i));
        ts_stun_begin(&st, servers, (const uint8_t(*)[TS_STUN_TXID_LEN])tx, 1, t);
        ts_stun_sends(&st, t, to, got, 2);
        CHECK(ts_stun_tick(&st, t + TS_STUN_ROUND_NS, 1, 0) == 0);
        CHECK(ep_is(&st.global, &us));
    }
    /* ... for TS_STUN_KEEP_NS since it was last seen (idle now: no periodic round in the way) */
    st.next = 0;
    CHECK(ts_stun_next(&st) == seen + TS_STUN_KEEP_NS);
    CHECK(ts_stun_tick(&st, seen + TS_STUN_KEEP_NS - 1, 1, 0) == 0);
    CHECK(ts_stun_tick(&st, seen + TS_STUN_KEEP_NS, 1, 0) == 1);
    CHECK(st.global.family == 0);

    /* a changed network: forgotten at once, the running round dropped, a new one wanted */
    st.global = us;
    st.global_seen = t;
    st.varies = 1;
    ts_stun_begin(&st, servers, (const uint8_t(*)[TS_STUN_TXID_LEN])tx, 1, t);
    ts_stun_forget(&st);
    CHECK(st.global.family == 0 && !st.varies && st.n == 0 && st.want && st.next == 0);
    CHECK(!ts_stun_knows(&st, srv(0)));
    /* no servers to ask: the wish stays */
    ts_stun_begin(&st, servers, (const uint8_t(*)[TS_STUN_TXID_LEN])tx, 0, t);
    CHECK(st.want && st.n == 0);
    /* more servers than it takes */
    {
        wg_endpoint many[5] = { *srv(0), *srv(1), *srv(2), ep4(1, 1, 1, 1, 1), ep4(2, 2, 2, 2, 2) };
        uint8_t tx5[5][TS_STUN_TXID_LEN];
        memset(tx5, 3, sizeof(tx5));
        ts_stun_begin(&st, many, (const uint8_t(*)[TS_STUN_TXID_LEN])tx5, 5, t);
        CHECK(st.n == TS_STUN_SERVERS);
        CHECK(ts_stun_sends(&st, t, to, got, 1) == 1);  /* at most cap at once */
        CHECK(ts_stun_sends(&st, t, to, got, 2) == 2);
    }
}

/* An answer seeing us over IPv6: taken (it is ours) but says nothing of our IPv4 socket. */
TEST(round_ipv6_answer)
{
    ts_stun_state st;
    wg_endpoint servers[1] = { *srv(0) }, to[2];
    uint8_t tx[TS_STUN_SERVERS][TS_STUN_TXID_LEN], got[2][TS_STUN_TXID_LEN], pkt[64];
    uint64_t t = S;
    size_t i;

    ts_stun_init(&st, 4);
    ts_stun_want(&st);
    REQUIRE(ts_stun_due(&st, t, 1));
    txids3(tx, 5);
    ts_stun_begin(&st, servers, (const uint8_t(*)[TS_STUN_TXID_LEN])tx, 1, t);
    REQUIRE(ts_stun_sends(&st, t, to, got, 2) == 1);
    /* XOR-MAPPED-ADDRESS, family 2: [1::4]:254 */
    pkt[0] = 0x01; pkt[1] = 0x01; pkt[2] = 0; pkt[3] = 24;
    pkt[4] = 0x21; pkt[5] = 0x12; pkt[6] = 0xa4; pkt[7] = 0x42;
    memcpy(pkt + 8, tx[0], 12);
    pkt[20] = 0; pkt[21] = 0x20; pkt[22] = 0; pkt[23] = 20;
    pkt[24] = 0; pkt[25] = 2; pkt[26] = (uint8_t)((254 ^ 0x2112) >> 8); pkt[27] = (uint8_t)((254 ^ 0x2112) & 0xff);
    for (i = 0; i < 16; i++) pkt[28 + i] = (uint8_t)(i == 1 ? 1 : i == 15 ? 4 : 0) ^ (i < 4 ? pkt[4 + i] : tx[0][i - 4]);
    CHECK(ts_stun_answer(&st, srv(0), pkt, 44, t));
    CHECK(ts_stun_tick(&st, t, 1, 0) == 0);                 /* over (answered), nothing found */
    CHECK(st.n == 0 && st.global.family == 0);
}

/* XOR-MAPPED-ADDRESS family 2 for `seen` (an IPv6 endpoint): stun.Response's form. */
static size_t reply6(uint8_t* out, const uint8_t* txid, const wg_endpoint* seen)
{
    static const uint8_t ck[4] = { 0x21, 0x12, 0xa4, 0x42 };
    size_t i;

    out[0] = 0x01; out[1] = 0x01; out[2] = 0; out[3] = 24;
    memcpy(out + 4, ck, 4);
    memcpy(out + 8, txid, 12);
    out[20] = 0x00; out[21] = 0x20; out[22] = 0; out[23] = 20;
    out[24] = 0; out[25] = 2;
    out[26] = (uint8_t)((seen->port ^ 0x2112) >> 8);
    out[27] = (uint8_t)((seen->port ^ 0x2112) & 0xff);
    for (i = 0; i < 16; i++) out[28 + i] = (uint8_t)(seen->addr[i] ^ (i < 4 ? ck[i] : txid[i - 4]));
    return 44;
}

/* An IPv6 socket's rounds: an IPv6 view counts, an IPv4 one says nothing. */
TEST(round_ipv6_socket)
{
    ts_stun_state st;
    wg_endpoint server6, us6, us4 = ep4(1, 2, 3, 4, 5), to[2];
    uint8_t tx[TS_STUN_SERVERS][TS_STUN_TXID_LEN], got[2][TS_STUN_TXID_LEN], pkt[64];
    uint64_t t = 5 * S;
    size_t n;

    memset(&server6, 0, sizeof(server6));
    server6.family = 6;
    server6.addr[0] = 0x20; server6.addr[1] = 0x01; server6.addr[2] = 0x0d; server6.addr[3] = 0xb8; server6.addr[15] = 3;
    server6.port = 3478;
    us6 = server6;
    us6.addr[15] = 2;
    us6.port = 40001;

    ts_stun_init(&st, 6);
    CHECK(st.family == 6);
    ts_stun_want(&st);
    REQUIRE(ts_stun_due(&st, t, 1));
    txids3(tx, 1);
    ts_stun_begin(&st, &server6, (const uint8_t(*)[TS_STUN_TXID_LEN])tx, 1, t);
    REQUIRE(ts_stun_sends(&st, t, to, got, 2) == 1);
    CHECK(ep_is(&to[0], &server6));
    n = reply(pkt, tx[0], &us4);                         /* an IPv4 view: taken, nothing found */
    CHECK(ts_stun_answer(&st, &server6, pkt, n, t));
    CHECK(ts_stun_tick(&st, t, 1, 0) == 0 && st.global.family == 0);

    t = st.next;
    REQUIRE(ts_stun_due(&st, t, 1));
    txids3(tx, 2);
    ts_stun_begin(&st, &server6, (const uint8_t(*)[TS_STUN_TXID_LEN])tx, 1, t);
    REQUIRE(ts_stun_sends(&st, t, to, got, 2) == 1);
    n = reply6(pkt, tx[0], &us6);
    CHECK(ts_stun_answer(&st, &server6, pkt, n, t));
    CHECK(ts_stun_tick(&st, t, 1, 0) == 1);
    CHECK(ep_is(&st.global, &us6));
    ts_stun_forget(&st);
    CHECK(st.family == 6 && st.global.family == 0);     /* the family stays */
}

/* Random operations in random order: the bounds hold, nothing crashes, `changed` means a change. */
TEST(round_fuzz)
{
    ts_stun_state st;
    uint64_t t = S;
    int step;
    wg_endpoint servers[TS_STUN_SERVERS + 2];
    uint8_t tx[TS_STUN_SERVERS + 2][TS_STUN_TXID_LEN], got[4][TS_STUN_TXID_LEN], pkt[64];
    wg_endpoint to[4];

    ts_stun_init(&st, 4);
    for (step = 0; step < 400000; step++) {
        unsigned op = (unsigned)(rnd() % 9);
        wg_endpoint before = st.global;
        int vbefore = st.varies, changed;
        size_t i, n;

        t += rnd() % (2 * S);
        switch (op) {
        case 0: ts_stun_want(&st); break;
        case 1: if (rnd() % 50 == 0) ts_stun_forget(&st); break;
        case 2: ts_stun_traffic(&st, t); break;
        case 3:
            if (ts_stun_due(&st, t, (int)(rnd() & 1))) {
                n = (size_t)(rnd() % (TS_STUN_SERVERS + 3));
                for (i = 0; i < n; i++) {
                    servers[i] = ep4(10, 20, 0, (uint8_t)(1 + rnd() % 4), 3478);
                    memset(tx[i], (int)(rnd() & 0xff), TS_STUN_TXID_LEN);
                }
                ts_stun_begin(&st, servers, (const uint8_t(*)[TS_STUN_TXID_LEN])tx, n, t);
            }
            break;
        case 4: ts_stun_sends(&st, t, to, got, 1 + (size_t)(rnd() % 4)); break;
        case 5:
            if (st.n) {
                size_t k = (size_t)(rnd() % st.n);
                wg_endpoint seen = ep4(10, 20, 88, 2, (uint16_t)(40000 + rnd() % 3));
                n = reply(pkt, (rnd() % 4) ? st.probe[k].txid : tx[0], &seen);
                ts_stun_answer(&st, &st.probe[k].server, pkt, n, t);
            }
            break;
        default:
            changed = ts_stun_tick(&st, t, (int)(rnd() & 1), (uint32_t)rnd());
            CHECK(changed == (!ep_is(&before, &st.global) || vbefore != st.varies));
            break;
        }
        CHECK(st.n <= TS_STUN_SERVERS);
        CHECK(st.answers <= st.n);
        CHECK(!st.n || st.round_end <= t + TS_STUN_ROUND_NS);
        CHECK(!st.next || st.next <= t + TS_STUN_EVERY_NS + TS_STUN_JITTER_NS);
        CHECK(st.global.family == 0 || st.global.family == st.family);
        if (st.n) {
            for (i = 0; i < st.n; i++) CHECK(st.probe[i].tries <= TS_STUN_TRIES);
        }
    }
}

int main(void)
{
    const char* seed = getenv("BT_FUZZ_SEED");

    if (seed) xs = strtoull(seed, NULL, 16) | 1;
    printf("test_ts_stun (fuzz seed %llx)\n", (unsigned long long)xs);
    RUN(requests);
    RUN(answers);
    RUN(known_addresses);
    RUN(cuts_and_flips);
    RUN(fuzz);
    RUN(round_basic);
    RUN(round_retry_and_timeout);
    RUN(round_hard_nat);
    RUN(round_refusals);
    RUN(round_idle_and_traffic);
    RUN(round_keep_and_forget);
    RUN(round_ipv6_answer);
    RUN(round_ipv6_socket);
    RUN(round_fuzz);
    return t_summary("test_ts_stun");
}
