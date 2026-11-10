/*
 * bt_resolve: the query on the wire byte for byte, replies parsed (CNAME chains, compression,
 * truncation, everything that must be ignored), and a lookup over time against scripted servers.
 */

#include "test_util.h"
#include "../src/bt_resolve.h"

/* ------------------------------------------------------------------ building replies */

typedef struct {
    uint8_t b[BT_DNS_MSG_MAX];
    size_t  n;
    size_t  ancount_at;
} msg;

static void u8(msg* m, unsigned v) { m->b[m->n++] = (uint8_t)v; }
static void u16(msg* m, unsigned v) { u8(m, v >> 8); u8(m, v & 0xff); }
static void u32(msg* m, uint32_t v) { u16(m, v >> 16); u16(m, v & 0xffff); }

/* A name as labels; "@" followed by a number as the last label writes a pointer to that offset. */
static void name(msg* m, const char* s)
{
    while (*s) {
        const char* dot = strchr(s, '.');
        size_t len = dot ? (size_t)(dot - s) : strlen(s);
        if (s[0] == '@') {
            u16(m, 0xc000 | (unsigned)atoi(s + 1));
            return;
        }
        u8(m, (unsigned)len);
        memcpy(m->b + m->n, s, len);
        m->n += len;
        s += len;
        if (*s == '.') s++;
    }
    u8(m, 0);
}

static void header(msg* m, uint16_t id, unsigned flags, const char* qname, uint16_t qtype, unsigned ancount)
{
    m->n = 0;
    u16(m, id);
    u16(m, flags);
    u16(m, 1);
    m->ancount_at = m->n;
    u16(m, ancount);
    u16(m, 0);
    u16(m, 0);
    name(m, qname);
    u16(m, qtype);
    u16(m, 1);
}

static void rr_a(msg* m, const char* owner, uint32_t ttl, uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    name(m, owner);
    u16(m, BT_DNS_TYPE_A);
    u16(m, 1);
    u32(m, ttl);
    u16(m, 4);
    u8(m, a); u8(m, b); u8(m, c); u8(m, d);
}

static void rr_aaaa(msg* m, const char* owner, uint32_t ttl, uint8_t last)
{
    static const uint8_t pfx[14] = { 0x20, 0x01, 0x0d, 0xb8 };
    name(m, owner);
    u16(m, BT_DNS_TYPE_AAAA);
    u16(m, 1);
    u32(m, ttl);
    u16(m, 16);
    memcpy(m->b + m->n, pfx, 14);
    m->n += 14;
    u8(m, 0);
    u8(m, last);
}

static void rr_cname(msg* m, const char* owner, uint32_t ttl, const char* target)
{
    size_t at;
    name(m, owner);
    u16(m, BT_DNS_TYPE_CNAME);
    u16(m, 1);
    u32(m, ttl);
    at = m->n;
    u16(m, 0);
    name(m, target);
    m->b[at] = (uint8_t)((m->n - at - 2) >> 8);
    m->b[at + 1] = (uint8_t)(m->n - at - 2);
}

#define OK_FLAGS    0x8180      /* QR RD RA, rcode 0 */

static bt_dns_answer ans;

/* ------------------------------------------------------------------ the wire */

TEST(query_bytes)
{
    uint8_t q[300];
    uint8_t want[64];
    size_t n = bt_dns_query(q, sizeof(q), 0x1234, "Example.COM.", BT_DNS_TYPE_A);
    size_t wn = t_hex(want, sizeof(want), "1234 0100 0001 0000 0000 0000 07 6578616d706c65 03 636f6d 00 0001 0001");

    CHECK(n == wn);
    CHECK_MEM(q, want, wn);
    n = bt_dns_query(q, sizeof(q), 0xbeef, "a.b", BT_DNS_TYPE_AAAA);
    wn = t_hex(want, sizeof(want), "beef 0100 0001 0000 0000 0000 01 61 01 62 00 001c 0001");
    CHECK(n == wn);
    CHECK_MEM(q, want, wn);
    CHECK(bt_dns_query(q, 20, 1, "example.com", BT_DNS_TYPE_A) == 0);     /* no room */
    CHECK(bt_dns_query(q, sizeof(q), 1, "bad..name", BT_DNS_TYPE_A) == 0);
}

TEST(name_rules)
{
    char l63[70], l64[70], n253[260], n254[260];
    size_t i;

    CHECK(bt_dns_name_valid("vpn.example.com"));
    CHECK(bt_dns_name_valid("vpn.example.com."));
    CHECK(bt_dns_name_valid("_srv.x-y.Z9"));
    CHECK(bt_dns_name_valid("localhost"));
    CHECK(!bt_dns_name_valid(""));
    CHECK(!bt_dns_name_valid("."));
    CHECK(!bt_dns_name_valid(".a"));
    CHECK(!bt_dns_name_valid("a..b"));
    CHECK(!bt_dns_name_valid("a b"));
    CHECK(!bt_dns_name_valid("пример.рф"));
    CHECK(!bt_dns_name_valid("a.b.."));
    memset(l63, 'a', 63); l63[63] = 0;
    memset(l64, 'a', 64); l64[64] = 0;
    CHECK(bt_dns_name_valid(l63));
    CHECK(!bt_dns_name_valid(l64));
    /* 253 characters: labels of 49 and dots */
    for (i = 0; i < 253; i++) n253[i] = (i % 50 == 49) ? '.' : 'b';
    n253[253] = 0;
    CHECK(bt_dns_name_valid(n253));
    memcpy(n254, n253, 253);
    n254[253] = 'b';
    n254[254] = 0;
    CHECK(!bt_dns_name_valid(n254));
}

TEST(parse_simple)
{
    msg m;

    header(&m, 7, OK_FLAGS, "vpn.example.com", BT_DNS_TYPE_A, 2);
    rr_a(&m, "@12", 300, 203, 0, 113, 7);
    rr_a(&m, "@12", 60, 203, 0, 113, 8);
    REQUIRE(bt_dns_parse(m.b, m.n, 7, "VPN.Example.com", BT_DNS_TYPE_A, &ans));
    CHECK(ans.rcode == 0 && !ans.truncated);
    REQUIRE(ans.n == 2);
    CHECK(ans.addrs[0].family == 4 && memcmp(ans.addrs[0].addr, "\xcb\x00\x71\x07", 4) == 0);
    CHECK(ans.addrs[1].addr[3] == 8);
    CHECK(ans.ttl == 60);

    header(&m, 8, OK_FLAGS, "vpn.example.com", BT_DNS_TYPE_AAAA, 1);
    rr_aaaa(&m, "@12", 120, 0x42);
    REQUIRE(bt_dns_parse(m.b, m.n, 8, "vpn.example.com", BT_DNS_TYPE_AAAA, &ans));
    REQUIRE(ans.n == 1);
    CHECK(ans.addrs[0].family == 6 && ans.addrs[0].addr[0] == 0x20 && ans.addrs[0].addr[15] == 0x42);
}

TEST(parse_cname_chain)
{
    msg m;

    /* www.example.com -> edge.cdn.net -> e1.cdn.net, the records out of order, with an unrelated
     * A that must not be used; the chain's least TTL wins */
    header(&m, 9, OK_FLAGS, "www.example.com", BT_DNS_TYPE_A, 4);
    rr_a(&m, "other.example.com", 5, 9, 9, 9, 9);
    rr_cname(&m, "@12", 600, "edge.cdn.net");
    rr_a(&m, "e1.cdn.net", 30, 192, 0, 2, 1);
    rr_cname(&m, "edge.cdn.net", 900, "e1.cdn.net");
    REQUIRE(bt_dns_parse(m.b, m.n, 9, "www.example.com", BT_DNS_TYPE_A, &ans));
    REQUIRE(ans.n == 1);
    CHECK(ans.addrs[0].addr[0] == 192 && ans.addrs[0].addr[3] == 1);
    CHECK(ans.ttl == 30);

    /* a CNAME loop: bounded, no address */
    header(&m, 10, OK_FLAGS, "a.x", BT_DNS_TYPE_A, 2);
    rr_cname(&m, "a.x", 5, "b.x");
    rr_cname(&m, "b.x", 5, "a.x");
    REQUIRE(bt_dns_parse(m.b, m.n, 10, "a.x", BT_DNS_TYPE_A, &ans));
    CHECK(ans.n == 0 && ans.ttl == 0);
}

TEST(parse_compressed_target)
{
    msg m;
    size_t qname_at = 12;
    char ptr[32];

    /* CNAME target "e1" + pointer to "example.com" inside the question */
    header(&m, 11, OK_FLAGS, "www.example.com", BT_DNS_TYPE_A, 2);
    snprintf(ptr, sizeof(ptr), "e1.@%u", (unsigned)(qname_at + 4));
    rr_cname(&m, "@12", 60, ptr);
    rr_a(&m, "e1.example.com", 60, 10, 1, 2, 3);
    REQUIRE(bt_dns_parse(m.b, m.n, 11, "www.example.com", BT_DNS_TYPE_A, &ans));
    REQUIRE(ans.n == 1);
    CHECK(ans.addrs[0].addr[3] == 3);
}

TEST(parse_rejects)
{
    msg m;

    header(&m, 7, OK_FLAGS, "vpn.example.com", BT_DNS_TYPE_A, 1);
    rr_a(&m, "@12", 300, 1, 2, 3, 4);
    CHECK(!bt_dns_parse(m.b, m.n, 8, "vpn.example.com", BT_DNS_TYPE_A, &ans));      /* id */
    CHECK(!bt_dns_parse(m.b, m.n, 7, "vpn.example.org", BT_DNS_TYPE_A, &ans));      /* name */
    CHECK(!bt_dns_parse(m.b, m.n, 7, "vpn.example.com", BT_DNS_TYPE_AAAA, &ans));   /* type */
    CHECK(!bt_dns_parse(m.b, 11, 7, "vpn.example.com", BT_DNS_TYPE_A, &ans));
    m.b[2] &= 0x7f;                                                                 /* not a reply */
    CHECK(!bt_dns_parse(m.b, m.n, 7, "vpn.example.com", BT_DNS_TYPE_A, &ans));
    m.b[2] |= 0x80;
    m.b[5] = 2;                                                                     /* two questions */
    CHECK(!bt_dns_parse(m.b, m.n, 7, "vpn.example.com", BT_DNS_TYPE_A, &ans));
    m.b[5] = 1;
    CHECK(bt_dns_parse(m.b, m.n, 7, "vpn.example.com", BT_DNS_TYPE_A, &ans));

    /* cut inside the record, not truncated: malformed */
    CHECK(!bt_dns_parse(m.b, m.n - 2, 7, "vpn.example.com", BT_DNS_TYPE_A, &ans));

    /* a pointer to itself / forwards */
    header(&m, 1, OK_FLAGS, "a.b", BT_DNS_TYPE_A, 1);
    {
        size_t at = m.n;
        u16(&m, 0xc000 | (unsigned)at);
        u16(&m, 1); u16(&m, 1); u32(&m, 1); u16(&m, 4); u32(&m, 0x01020304);
    }
    CHECK(!bt_dns_parse(m.b, m.n, 1, "a.b", BT_DNS_TYPE_A, &ans));
    header(&m, 1, OK_FLAGS, "a.b", BT_DNS_TYPE_A, 1);
    u16(&m, 0xc000 | (unsigned)(m.n + 20));
    CHECK(!bt_dns_parse(m.b, m.n, 1, "a.b", BT_DNS_TYPE_A, &ans));

    /* a pointer FORWARD to a real copy of the name: refused even though it would lead somewhere
     * sensible (only backward pointers, so no chain can loop) */
    header(&m, 4, OK_FLAGS, "a.b", BT_DNS_TYPE_A, 1);
    {
        size_t at = m.n;
        u16(&m, 0);                                 /* patched below */
        u16(&m, 1); u16(&m, 1); u32(&m, 1); u16(&m, 4); u32(&m, 0x01020304);
        m.b[at] = (uint8_t)(0xc0 | (m.n >> 8));
        m.b[at + 1] = (uint8_t)m.n;
        name(&m, "a.b");                            /* trailing bytes after the records */
    }
    CHECK(!bt_dns_parse(m.b, m.n, 4, "a.b", BT_DNS_TYPE_A, &ans));

    /* label types 0x40 / 0x80 are not lengths */
    header(&m, 5, OK_FLAGS, "a.b", BT_DNS_TYPE_A, 1);
    u8(&m, 0x41);
    {
        int i;
        for (i = 0; i < 0x41; i++) u8(&m, 'x');
    }
    u8(&m, 0);
    u16(&m, 1); u16(&m, 1); u32(&m, 1); u16(&m, 4); u32(&m, 0x01020304);
    CHECK(!bt_dns_parse(m.b, m.n, 5, "a.b", BT_DNS_TYPE_A, &ans));

    /* ONE label "a.b" (a dot inside it) must not pass for the name a.b; nor a NUL inside a label */
    header(&m, 7, OK_FLAGS, "a.b", BT_DNS_TYPE_A, 1);
    u8(&m, 3); u8(&m, 'a'); u8(&m, '.'); u8(&m, 'b'); u8(&m, 0);
    u16(&m, 1); u16(&m, 1); u32(&m, 1); u16(&m, 4); u32(&m, 0x01020304);
    CHECK(!bt_dns_parse(m.b, m.n, 7, "a.b", BT_DNS_TYPE_A, &ans));
    header(&m, 8, OK_FLAGS, "a.b", BT_DNS_TYPE_A, 1);
    u8(&m, 2); u8(&m, 'a'); u8(&m, 0); u8(&m, 1); u8(&m, 'b'); u8(&m, 0);
    u16(&m, 1); u16(&m, 1); u32(&m, 1); u16(&m, 4); u32(&m, 0x01020304);
    CHECK(!bt_dns_parse(m.b, m.n, 8, "a.b", BT_DNS_TYPE_A, &ans));

    /* the least TTL whatever the order */
    header(&m, 6, OK_FLAGS, "a.b", BT_DNS_TYPE_A, 2);
    rr_a(&m, "@12", 60, 1, 1, 1, 1);
    rr_a(&m, "@12", 300, 1, 1, 1, 2);
    REQUIRE(bt_dns_parse(m.b, m.n, 6, "a.b", BT_DNS_TYPE_A, &ans));
    CHECK(ans.n == 2 && ans.ttl == 60);

    /* an A record of the wrong size is ignored, not trusted */
    header(&m, 2, OK_FLAGS, "a.b", BT_DNS_TYPE_A, 1);
    name(&m, "@12");
    u16(&m, 1); u16(&m, 1); u32(&m, 1); u16(&m, 5); u32(&m, 0x01020304); u8(&m, 5);
    REQUIRE(bt_dns_parse(m.b, m.n, 2, "a.b", BT_DNS_TYPE_A, &ans));
    CHECK(ans.n == 0);

    /* a record of another class is skipped */
    header(&m, 3, OK_FLAGS, "a.b", BT_DNS_TYPE_A, 1);
    name(&m, "@12");
    u16(&m, 1); u16(&m, 3); u32(&m, 1); u16(&m, 4); u32(&m, 0x01020304);
    REQUIRE(bt_dns_parse(m.b, m.n, 3, "a.b", BT_DNS_TYPE_A, &ans));
    CHECK(ans.n == 0);
}

TEST(parse_rcode_and_truncation)
{
    msg m;

    header(&m, 5, 0x8183, "nope.example", BT_DNS_TYPE_A, 0);
    REQUIRE(bt_dns_parse(m.b, m.n, 5, "nope.example", BT_DNS_TYPE_A, &ans));
    CHECK(ans.rcode == 3 && ans.n == 0);

    /* TC: two records claimed, the second cut short - the first is used */
    header(&m, 6, OK_FLAGS | 0x0200, "t.example", BT_DNS_TYPE_A, 2);
    rr_a(&m, "@12", 10, 1, 1, 1, 1);
    rr_a(&m, "@12", 10, 2, 2, 2, 2);
    REQUIRE(bt_dns_parse(m.b, m.n - 3, 6, "t.example", BT_DNS_TYPE_A, &ans));
    CHECK(ans.truncated && ans.n == 1 && ans.addrs[0].addr[0] == 1);

    /* cut inside the second record's fixed fields: still the first */
    {
        size_t second = m.n - 16;                   /* ptr(2) + 10 + rdata(4) */
        REQUIRE(bt_dns_parse(m.b, second + 5, 6, "t.example", BT_DNS_TYPE_A, &ans));
        CHECK(ans.truncated && ans.n == 1);
        m.b[2] &= (uint8_t)~0x02;                   /* the same cut without TC: malformed */
        CHECK(!bt_dns_parse(m.b, second + 5, 6, "t.example", BT_DNS_TYPE_A, &ans));
    }
}

/* ------------------------------------------------------------------ a lookup */

typedef struct {
    int     count;
    bt_addr to[16];
    uint8_t q[16][300];
    size_t  qlen[16];
} sent_log;

static void capture(void* ctx, const bt_addr* server, const uint8_t* q, size_t len)
{
    sent_log* s = (sent_log*)ctx;
    if (s->count < 16 && len <= 300) {
        s->to[s->count] = *server;
        memcpy(s->q[s->count], q, len);
        s->qlen[s->count] = len;
    }
    s->count++;
}

static int script_fn(void* ctx, void* buf, size_t len)
{
    (void)ctx;
    memset(buf, 0x11, len);
    if (len >= 4) ((uint8_t*)buf)[3] = 0x22;
    return 1;
}

static const wg_rng test_rng = { script_fn, NULL };

static bt_addr srv(uint8_t last)
{
    bt_addr a;
    memset(&a, 0, sizeof(a));
    a.family = 4;
    a.addr[0] = 192;
    a.addr[1] = 168;
    a.addr[2] = 1;
    a.addr[3] = last;
    return a;
}

static uint16_t qid(const sent_log* s, int i) { return (uint16_t)((s->q[i][0] << 8) | s->q[i][1]); }
static unsigned qtype_of(const sent_log* s, int i) { return (unsigned)((s->q[i][s->qlen[i] - 4] << 8) | s->q[i][s->qlen[i] - 3]); }

#define SEC BT_NSEC_PER_SEC
#define T0  (100 * SEC)

TEST(lookup_a_wins)
{
    bt_addr servers[2] = { srv(1), srv(2) };
    bt_lookup l;
    sent_log s;
    msg m;

    memset(&s, 0, sizeof(s));
    REQUIRE(bt_lookup_start(&l, "VPN.example.com.", servers, 2, 1, 1, &test_rng, T0));
    CHECK(bt_lookup_tick(&l, T0, capture, &s) == T0 + BT_LOOKUP_RETRY_NS);
    REQUIRE(s.count == 2);
    CHECK(bt_addr_equal(&s.to[0], &servers[0]) && bt_addr_equal(&s.to[1], &servers[0]));
    CHECK(qtype_of(&s, 0) == BT_DNS_TYPE_A && qtype_of(&s, 1) == BT_DNS_TYPE_AAAA);
    CHECK(qid(&s, 0) != qid(&s, 1));

    /* not from a server we asked, or not port 53: ignored */
    header(&m, qid(&s, 0), OK_FLAGS, "vpn.example.com", BT_DNS_TYPE_A, 1);
    rr_a(&m, "@12", 300, 198, 51, 100, 1);
    {
        bt_addr other = srv(9);
        CHECK(!bt_lookup_receive(&l, &other, 53, m.b, m.n, T0));
        CHECK(!bt_lookup_receive(&l, &servers[0], 5353, m.b, m.n, T0));
    }
    /* the second server answers the round sent to the first: fine, it is one of ours */
    CHECK(bt_lookup_receive(&l, &servers[1], 53, m.b, m.n, T0 + 1));
    CHECK(l.state == BT_LOOKUP_DONE);
    REQUIRE(l.n == 1);
    CHECK(l.addrs[0].family == 4 && l.addrs[0].addr[0] == 198);
    CHECK(l.ttl == 300);
    CHECK(bt_lookup_tick(&l, T0 + 10 * SEC, capture, &s) == BT_NEVER);
    CHECK(s.count == 2);
}

TEST(lookup_rounds_and_timeout)
{
    bt_addr servers[2] = { srv(1), srv(2) };
    bt_lookup l;
    sent_log s;
    uint64_t t = T0;
    int i;

    memset(&s, 0, sizeof(s));
    REQUIRE(bt_lookup_start(&l, "slow.example", servers, 2, 1, 0, &test_rng, T0));
    CHECK(bt_lookup_tick(&l, T0 - 1, capture, &s) == T0);          /* not due yet */
    CHECK(s.count == 0);
    for (i = 0; i < BT_LOOKUP_ATTEMPTS; i++) {
        t = bt_lookup_tick(&l, t, capture, &s);
        CHECK(bt_lookup_tick(&l, t - 1, capture, &s) == t);        /* nothing between rounds */
    }
    REQUIRE(s.count == BT_LOOKUP_ATTEMPTS);
    for (i = 0; i < BT_LOOKUP_ATTEMPTS; i++) {
        CHECK(bt_addr_equal(&s.to[i], &servers[i % 2]));
        CHECK(qtype_of(&s, i) == BT_DNS_TYPE_A);
        CHECK(qid(&s, i) == qid(&s, 0));
    }
    CHECK(l.state == BT_LOOKUP_RUNNING);
    CHECK(bt_lookup_tick(&l, t, capture, &s) == BT_NEVER);
    CHECK(l.state == BT_LOOKUP_FAILED && l.error == BT_LOOKUP_ERR_TIMEOUT);
    CHECK(t == T0 + BT_LOOKUP_ATTEMPTS * BT_LOOKUP_RETRY_NS);
}

TEST(lookup_servfail_moves_on)
{
    bt_addr servers[3] = { srv(1), srv(2), srv(3) };
    bt_lookup l;
    sent_log s;
    msg m;

    memset(&s, 0, sizeof(s));
    REQUIRE(bt_lookup_start(&l, "x.example", servers, 3, 1, 0, &test_rng, T0));
    bt_lookup_tick(&l, T0, capture, &s);
    header(&m, qid(&s, 0), 0x8182, "x.example", BT_DNS_TYPE_A, 0);
    CHECK(bt_lookup_receive(&l, &servers[0], 53, m.b, m.n, T0 + SEC / 10));
    CHECK(l.state == BT_LOOKUP_RUNNING);
    CHECK(bt_lookup_tick(&l, T0 + SEC / 10, capture, &s) == T0 + SEC / 10 + BT_LOOKUP_RETRY_NS);
    REQUIRE(s.count == 2);
    CHECK(bt_addr_equal(&s.to[1], &servers[1]));
}

TEST(lookup_nxdomain)
{
    bt_addr servers[1] = { srv(1) };
    bt_lookup l;
    sent_log s;
    msg m;

    memset(&s, 0, sizeof(s));
    REQUIRE(bt_lookup_start(&l, "gone.example", servers, 1, 1, 1, &test_rng, T0));
    bt_lookup_tick(&l, T0, capture, &s);
    header(&m, qid(&s, 1), 0x8183, "gone.example", BT_DNS_TYPE_AAAA, 0);
    CHECK(bt_lookup_receive(&l, &servers[0], 53, m.b, m.n, T0));
    CHECK(l.state == BT_LOOKUP_FAILED && l.error == BT_LOOKUP_ERR_NXDOMAIN);
    CHECK(strcmp(bt_lookup_error_text(l.error), "no such name") == 0);
}

TEST(lookup_v6_only_and_nodata)
{
    bt_addr servers[1] = { srv(1) };
    bt_lookup l;
    sent_log s;
    msg m;
    uint64_t t;

    /* A: no data; AAAA: an address -> done with the v6 address */
    memset(&s, 0, sizeof(s));
    REQUIRE(bt_lookup_start(&l, "six.example", servers, 1, 1, 1, &test_rng, T0));
    bt_lookup_tick(&l, T0, capture, &s);
    header(&m, qid(&s, 0), OK_FLAGS, "six.example", BT_DNS_TYPE_A, 0);
    CHECK(bt_lookup_receive(&l, &servers[0], 53, m.b, m.n, T0));
    CHECK(l.state == BT_LOOKUP_RUNNING);
    /* the next round asks only what is still open */
    t = bt_lookup_tick(&l, T0 + BT_LOOKUP_RETRY_NS, capture, &s);
    CHECK(s.count == 3 && qtype_of(&s, 2) == BT_DNS_TYPE_AAAA);
    header(&m, qid(&s, 1), OK_FLAGS, "six.example", BT_DNS_TYPE_AAAA, 1);
    rr_aaaa(&m, "@12", 77, 6);
    CHECK(bt_lookup_receive(&l, &servers[0], 53, m.b, m.n, t - 1));
    CHECK(l.state == BT_LOOKUP_DONE && l.n == 1 && l.addrs[0].family == 6 && l.ttl == 77);

    /* both empty -> NODATA */
    memset(&s, 0, sizeof(s));
    REQUIRE(bt_lookup_start(&l, "empty.example", servers, 1, 1, 1, &test_rng, T0));
    bt_lookup_tick(&l, T0, capture, &s);
    header(&m, qid(&s, 0), OK_FLAGS, "empty.example", BT_DNS_TYPE_A, 0);
    bt_lookup_receive(&l, &servers[0], 53, m.b, m.n, T0);
    header(&m, qid(&s, 1), OK_FLAGS, "empty.example", BT_DNS_TYPE_AAAA, 0);
    bt_lookup_receive(&l, &servers[0], 53, m.b, m.n, T0);
    CHECK(l.state == BT_LOOKUP_FAILED && l.error == BT_LOOKUP_ERR_NODATA);
}

TEST(lookup_v6_first_then_v4)
{
    bt_addr servers[1] = { srv(1) };
    bt_lookup l;
    sent_log s;
    msg m;

    memset(&s, 0, sizeof(s));
    REQUIRE(bt_lookup_start(&l, "both.example", servers, 1, 1, 1, &test_rng, T0));
    bt_lookup_tick(&l, T0, capture, &s);
    header(&m, qid(&s, 1), OK_FLAGS, "both.example", BT_DNS_TYPE_AAAA, 1);
    rr_aaaa(&m, "@12", 50, 6);
    CHECK(bt_lookup_receive(&l, &servers[0], 53, m.b, m.n, T0));
    CHECK(l.state == BT_LOOKUP_RUNNING);                /* IPv4 is preferred: wait for it */
    /* a duplicate AAAA is not ours any more */
    CHECK(!bt_lookup_receive(&l, &servers[0], 53, m.b, m.n, T0));
    header(&m, qid(&s, 0), OK_FLAGS, "both.example", BT_DNS_TYPE_A, 1);
    rr_a(&m, "@12", 40, 10, 0, 0, 4);
    CHECK(bt_lookup_receive(&l, &servers[0], 53, m.b, m.n, T0));
    CHECK(l.state == BT_LOOKUP_DONE && l.n == 2);
    CHECK(l.addrs[0].family == 4 && l.addrs[1].family == 6 && l.ttl == 40);

    /* only AAAA ever came: after the rounds, it is the answer */
    memset(&s, 0, sizeof(s));
    REQUIRE(bt_lookup_start(&l, "both.example", servers, 1, 1, 1, &test_rng, T0));
    bt_lookup_tick(&l, T0, capture, &s);
    header(&m, qid(&s, 1), OK_FLAGS, "both.example", BT_DNS_TYPE_AAAA, 1);
    rr_aaaa(&m, "@12", 50, 6);
    bt_lookup_receive(&l, &servers[0], 53, m.b, m.n, T0);
    {
        uint64_t t = T0;
        while ((t = bt_lookup_tick(&l, t, capture, &s)) != BT_NEVER) {}
    }
    CHECK(l.state == BT_LOOKUP_DONE && l.n == 1 && l.addrs[0].family == 6);
}

TEST(lookup_start_failures)
{
    bt_addr servers[1] = { srv(1) };
    bt_addr none[1];
    bt_lookup l;

    memset(none, 0, sizeof(none));
    CHECK(!bt_lookup_start(&l, "bad name", servers, 1, 1, 1, &test_rng, T0));
    CHECK(l.state == BT_LOOKUP_FAILED && l.error == BT_LOOKUP_ERR_NAME);
    CHECK(!bt_lookup_start(&l, "ok.example", none, 1, 1, 1, &test_rng, T0));
    CHECK(l.error == BT_LOOKUP_ERR_NO_SERVERS);
    CHECK(!bt_lookup_start(&l, "ok.example", servers, 0, 1, 1, &test_rng, T0));
    CHECK(!bt_lookup_start(&l, "ok.example", servers, 1, 0, 0, &test_rng, T0));
    CHECK(bt_lookup_tick(&l, T0, capture, NULL) == BT_NEVER);
}

int main(void)
{
    printf("test_resolve\n");
    RUN(query_bytes);
    RUN(name_rules);
    RUN(parse_simple);
    RUN(parse_cname_chain);
    RUN(parse_compressed_target);
    RUN(parse_rejects);
    RUN(parse_rcode_and_truncation);
    RUN(lookup_a_wins);
    RUN(lookup_rounds_and_timeout);
    RUN(lookup_servfail_moves_on);
    RUN(lookup_nxdomain);
    RUN(lookup_v6_only_and_nodata);
    RUN(lookup_v6_first_then_v4);
    RUN(lookup_start_failures);
    return t_summary("test_resolve");
}
