/*
 * ts_dns: MagicDNS's resolver (docs/TAILSCALE.md, section 8a). Queries as the phone sends them, over
 * IPv4 and IPv6, answered from a made-up tailnet - A, AAAA, NODATA, NXDOMAIN - or forwarded, with the
 * answer matched by id and question and put back; the odd ones (NOTIMP, FORMERR, SERVFAIL); what it
 * does not take; its limits (the waiting table, the timeout, the size of the tun). Every packet it
 * builds is checked byte by byte: IP header checksum, UDP checksum with the pseudo-header, lengths.
 * Then fuzzed: mutated and random packets and answers, each in a heap buffer of exactly its size, so
 * a read past one is caught.
 *
 * Seeded like the daemon's fuzzer: BT_FUZZ_SEED=<hex> picks another run.
 */

#include "test_util.h"
#include "../src/ts_dns.h"

#define NOW0    1000000000000ULL

static const uint8_t phone4[4] = { 100, 64, 0, 1 };
static const uint8_t phone6[16] = { 0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
static const uint8_t q4[4] = { 100, 100, 100, 100 };
static const uint8_t q6[16] = { 0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53 };

/* ------------------------------------------------------------------ a made-up tailnet */

static unsigned lookups;

static ts_dns_name_kind lookup(void* ctx, const char* name, size_t len, int family, uint8_t (*out)[16], size_t cap,
                               size_t* n, int* route)
{
    static const char suffix[] = ".tail.ts.net";
    size_t sl = sizeof(suffix) - 1;
    (void)ctx;
    lookups++;
    *n = 0;
    if (strlen(name) != len) return TS_DNS_NAME_OTHER;          /* the text is NUL-terminated at len */
    /* split DNS: corp.split is route 3; doh.split a route with only DoH servers */
    if (len >= 10 && strcmp(name + len - 10, "corp.split") == 0 && (len == 10 || name[len - 11] == '.')) {
        *route = 3;
        return TS_DNS_NAME_ROUTED;
    }
    if (len >= 9 && strcmp(name + len - 9, "doh.split") == 0 && (len == 9 || name[len - 10] == '.'))
        return TS_DNS_NAME_FAIL;
    if (strcmp(name, "nas.tail.ts.net") == 0 || strcmp(name, "nas") == 0) {
        if (cap < 1) return TS_DNS_NAME_OURS;
        memset(out[0], 0, 16);
        if (family == 4) {
            out[0][0] = 100;
            out[0][1] = 69;
            out[0][2] = 167;
            out[0][3] = 72;
        } else {
            memcpy(out[0], phone6, 16);
            out[0][15] = 0x72;
        }
        *n = 1;
        return TS_DNS_NAME_OURS;
    }
    if (strcmp(name, "v4only.tail.ts.net") == 0) {
        if (family == 4 && cap >= 1) {
            memset(out[0], 0, 16);
            out[0][0] = 100;
            out[0][1] = 64;
            out[0][3] = 9;
            *n = 1;
        }
        return TS_DNS_NAME_OURS;
    }
    if (strcmp(name, "many.tail.ts.net") == 0) {
        size_t i;
        for (i = 0; i < cap && i < 20; i++) {
            memset(out[i], 0, 16);
            out[i][0] = 100;
            out[i][1] = 64;
            out[i][3] = (uint8_t)(i + 1);
        }
        *n = 20;                                                /* more than asked: capped by the caller */
        return TS_DNS_NAME_OURS;
    }
    if (len > sl && strcmp(name + len - sl, suffix) == 0) return TS_DNS_NAME_NX;
    return TS_DNS_NAME_OTHER;
}

/* ------------------------------------------------------------------ packets */

static void w16(uint8_t* p, unsigned v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static unsigned r16(const uint8_t* p)
{
    return (unsigned)((p[0] << 8) | p[1]);
}

/* A DNS query for `name` (dotted), with an OPT record of `edns` size when not 0. */
static size_t dns_query(uint8_t* out, unsigned id, const char* name, unsigned qtype, unsigned edns)
{
    size_t p = 12;
    const char* s = name;

    memset(out, 0, 12);
    w16(out, id);
    w16(out + 2, 0x0100);                                       /* RD */
    w16(out + 4, 1);
    while (*s) {
        const char* dot = strchr(s, '.');
        size_t l = dot ? (size_t)(dot - s) : strlen(s);
        out[p++] = (uint8_t)l;
        memcpy(out + p, s, l);
        p += l;
        s += l;
        if (*s == '.') s++;
    }
    out[p++] = 0;
    w16(out + p, qtype);
    w16(out + p + 2, 1);
    p += 4;
    if (edns) {
        w16(out + 10, 1);
        out[p++] = 0;                                           /* root */
        w16(out + p, 41);
        w16(out + p + 2, edns);
        memset(out + p + 4, 0, 6);
        p += 10;
    }
    return p;
}

static uint32_t csum(uint32_t s, const uint8_t* p, size_t n)
{
    while (n > 1) {
        s += (uint32_t)((p[0] << 8) | p[1]);
        p += 2;
        n -= 2;
    }
    if (n) s += (uint32_t)(p[0] << 8);
    return s;
}

static unsigned folded(uint32_t s)
{
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return s;
}

/* The DNS message wrapped as the phone sends it: from phone:5000 to the resolver's port 53. */
static size_t ip_wrap(int family, const uint8_t* dns, size_t n, uint8_t* out)
{
    size_t hl = family == 4 ? 20 : 40;
    uint8_t* u = out + hl;

    memset(out, 0, hl + 8);
    if (family == 4) {
        out[0] = 0x45;
        w16(out + 2, (unsigned)(hl + 8 + n));
        out[8] = 64;
        out[9] = 17;
        memcpy(out + 12, phone4, 4);
        memcpy(out + 16, q4, 4);
    } else {
        out[0] = 0x60;
        w16(out + 4, (unsigned)(8 + n));
        out[6] = 17;
        out[7] = 64;
        memcpy(out + 8, phone6, 16);
        memcpy(out + 24, q6, 16);
    }
    w16(u, 5000);
    w16(u + 2, 53);
    w16(u + 4, (unsigned)(8 + n));
    memcpy(u + 8, dns, n);
    return hl + 8 + n;
}

/* A packet the resolver put out: from the resolver's port 53, checksums and lengths right, and with
 * `to_phone` to phone:5000. The DNS message inside, or NULL. */
static const uint8_t* reply_check(int family, const uint8_t* pkt, size_t len, int to_phone, size_t* dlen)
{
    size_t hl = family == 4 ? 20 : 40;
    const uint8_t* u = pkt + hl;
    uint32_t s;

    if (len < hl + 8 || len > TS_DNS_PKT_MAX) return NULL;
    if (family == 4) {
        if (pkt[0] != 0x45 || r16(pkt + 2) != len || pkt[9] != 17 || folded(csum(0, pkt, 20)) != 0xffff) return NULL;
        if (memcmp(pkt + 12, q4, 4) != 0 || (to_phone && memcmp(pkt + 16, phone4, 4) != 0)) return NULL;
        s = csum(0, pkt + 12, 8);
    } else {
        if ((pkt[0] >> 4) != 6 || r16(pkt + 4) + 40 != len || pkt[6] != 17) return NULL;
        if (memcmp(pkt + 8, q6, 16) != 0 || (to_phone && memcmp(pkt + 24, phone6, 16) != 0)) return NULL;
        s = csum(0, pkt + 8, 32);
    }
    if (r16(u) != 53 || (to_phone && r16(u + 2) != 5000) || r16(u + 4) != len - hl) return NULL;
    s += 17 + (uint32_t)(len - hl);
    s = csum(s, u, len - hl);
    if (folded(s) != 0xffff || r16(u + 6) == 0) return NULL;
    *dlen = len - hl - 8;
    return u + 8;
}

static const uint8_t* reply_dns(int family, const uint8_t* pkt, size_t len, size_t* dlen)
{
    return reply_check(family, pkt, len, 1, dlen);
}

static ts_dns R;
static uint8_t out[TS_DNS_PKT_MAX];
static size_t out_len;
static int last_route;                  /* ts_dns_query's *route of the last ask */

/* Into the resolver as the phone sends it, the packet in a heap buffer of its size. */
static ts_dns_action ask(int family, const uint8_t* dns, size_t n, int can_forward, uint64_t now)
{
    uint8_t pkt[2048];
    size_t len = ip_wrap(family, dns, n, pkt);
    uint8_t* exact = (uint8_t*)malloc(len);
    ts_dns_action a;

    memcpy(exact, pkt, len);
    CHECK(ts_dns_is_ours(exact, len));
    last_route = 77;
    a = ts_dns_query(&R, exact, len, can_forward, now, out, sizeof(out), &out_len, &last_route);
    free(exact);
    return a;
}

/* ------------------------------------------------------------------ answered here */

TEST(answers_from_the_tailnet)
{
    uint8_t q[512];
    size_t n, dl;
    const uint8_t* d;

    ts_dns_init(&R, lookup, NULL, 7);

    /* A over IPv4 */
    n = dns_query(q, 0x1234, "NAS.Tail.TS.net", 1, 0);
    REQUIRE(ask(4, q, n, 1, NOW0) == TS_DNS_ANSWER);
    d = reply_dns(4, out, out_len, &dl);
    REQUIRE(d != NULL);
    CHECK(r16(d) == 0x1234 && (r16(d + 2) & 0x8000) && (r16(d + 2) & 0x0400) && (r16(d + 2) & 0x0100) &&
          (r16(d + 2) & 0x0080) && (r16(d + 2) & 0x000f) == 0);
    CHECK(r16(d + 4) == 1 && r16(d + 6) == 1 && r16(d + 8) == 0 && r16(d + 10) == 0);
    CHECK(dl == n + 16 && memcmp(d + 12, q + 12, n - 12) == 0);     /* the question as asked, case and all */
    CHECK(r16(d + n) == 0xc00c && r16(d + n + 2) == 1 && r16(d + n + 4) == 1 && r16(d + n + 6) == 0 &&
          r16(d + n + 8) == 600 && r16(d + n + 10) == 4);
    CHECK(d[n + 12] == 100 && d[n + 13] == 69 && d[n + 14] == 167 && d[n + 15] == 72);

    /* AAAA over IPv6, a bare name too */
    n = dns_query(q, 7, "nas", 28, 0);
    REQUIRE(ask(6, q, n, 1, NOW0) == TS_DNS_ANSWER);
    d = reply_dns(6, out, out_len, &dl);
    REQUIRE(d != NULL);
    CHECK(r16(d + 6) == 1 && dl == n + 28 && r16(d + n + 10) == 16 && d[n + 12] == 0xfd && d[n + 27] == 0x72);

    /* a name of ours with no address of the kind asked, or another kind of record: NODATA */
    n = dns_query(q, 8, "v4only.tail.ts.net", 28, 0);
    REQUIRE(ask(4, q, n, 1, NOW0) == TS_DNS_ANSWER);
    d = reply_dns(4, out, out_len, &dl);
    REQUIRE(d != NULL);
    CHECK((r16(d + 2) & 0x000f) == 0 && r16(d + 6) == 0 && dl == n);
    n = dns_query(q, 9, "nas.tail.ts.net", 15 /* MX */, 0);
    REQUIRE(ask(4, q, n, 1, NOW0) == TS_DNS_ANSWER);
    d = reply_dns(4, out, out_len, &dl);
    REQUIRE(d != NULL);
    CHECK((r16(d + 2) & 0x000f) == 0 && r16(d + 6) == 0);

    /* under the MagicDNS domain, not in the tailnet: NXDOMAIN, authoritative */
    n = dns_query(q, 10, "nobody.tail.ts.net", 1, 0);
    REQUIRE(ask(4, q, n, 1, NOW0) == TS_DNS_ANSWER);
    d = reply_dns(4, out, out_len, &dl);
    REQUIRE(d != NULL);
    CHECK((r16(d + 2) & 0x000f) == 3 && (r16(d + 2) & 0x0400) && r16(d + 6) == 0);

    /* more addresses than an answer holds: TS_DNS_ANSWERS_MAX of them */
    n = dns_query(q, 11, "many.tail.ts.net", 1, 0);
    REQUIRE(ask(4, q, n, 1, NOW0) == TS_DNS_ANSWER);
    d = reply_dns(4, out, out_len, &dl);
    REQUIRE(d != NULL);
    CHECK(r16(d + 6) == TS_DNS_ANSWERS_MAX && dl == n + 16 * TS_DNS_ANSWERS_MAX);

    /* the odd ones: NOTIMP for another opcode, FORMERR for two questions or a pointer in one,
     * SERVFAIL for a name to forward with nowhere to forward it */
    n = dns_query(q, 12, "nas.tail.ts.net", 1, 0);
    w16(q + 2, 0x0100 | (2 << 11));
    REQUIRE(ask(4, q, n, 1, NOW0) == TS_DNS_ANSWER);
    d = reply_dns(4, out, out_len, &dl);
    REQUIRE(d != NULL);
    CHECK((r16(d + 2) & 0x000f) == 4 && ((r16(d + 2) >> 11) & 0xf) == 2 && r16(d + 4) == 0 && dl == 12);
    n = dns_query(q, 13, "nas.tail.ts.net", 1, 0);
    w16(q + 4, 2);
    REQUIRE(ask(4, q, n, 1, NOW0) == TS_DNS_ANSWER);
    d = reply_dns(4, out, out_len, &dl);
    REQUIRE(d != NULL);
    CHECK((r16(d + 2) & 0x000f) == 1);
    n = dns_query(q, 14, "nas", 1, 0);
    q[12] = 0xc0;                                               /* a pointer where the name begins */
    q[13] = 0x0c;
    REQUIRE(ask(4, q, n, 1, NOW0) == TS_DNS_ANSWER);
    d = reply_dns(4, out, out_len, &dl);
    REQUIRE(d != NULL);
    CHECK((r16(d + 2) & 0x000f) == 1);
    n = dns_query(q, 15, "example.com", 1, 0);
    REQUIRE(ask(4, q, n, 0, NOW0) == TS_DNS_ANSWER);
    d = reply_dns(4, out, out_len, &dl);
    REQUIRE(d != NULL);
    CHECK((r16(d + 2) & 0x000f) == 2 && !(r16(d + 2) & 0x0400) && r16(d + 4) == 1);
    CHECK(R.forwarded == 0);

    /* split DNS: a route we cannot follow - SERVFAIL, even with a default upstream known */
    n = dns_query(q, 16, "host.DOH.split", 1, 0);
    REQUIRE(ask(4, q, n, 1, NOW0) == TS_DNS_ANSWER);
    d = reply_dns(4, out, out_len, &dl);
    REQUIRE(d != NULL);
    CHECK((r16(d + 2) & 0x000f) == 2 && r16(d + 6) == 0);
    CHECK(R.forwarded == 0);
}

/* Split DNS: a routed name is forwarded with its route - with no default upstream as well; any other
 * name with -1 (the default servers). */
TEST(routed)
{
    uint8_t q[512];
    size_t n;

    ts_dns_init(&R, lookup, NULL, 21);
    n = dns_query(q, 1, "Wiki.Corp.Split", 1, 0);
    CHECK(ask(4, q, n, 1, NOW0) == TS_DNS_FORWARD && last_route == 3);
    n = dns_query(q, 2, "corp.split", 28, 0);
    CHECK(ask(6, q, n, 0, NOW0) == TS_DNS_FORWARD && last_route == 3);     /* no default upstream: still */
    n = dns_query(q, 3, "example.com", 1, 0);
    CHECK(ask(4, q, n, 1, NOW0) == TS_DNS_FORWARD && last_route == -1);
    n = dns_query(q, 4, "nas.tail.ts.net", 1, 0);
    CHECK(ask(4, q, n, 1, NOW0) == TS_DNS_ANSWER && last_route == -1);     /* answered here: no route */
    n = dns_query(q, 5, "xcorp.split", 1, 0);                               /* not under the route: default */
    CHECK(ask(4, q, n, 0, NOW0) == TS_DNS_ANSWER);                           /* ... and none known: SERVFAIL */
    CHECK(R.forwarded == 3);
}

/* ------------------------------------------------------------------ forwarded */

/* The upstream's answer to a forwarded query `fq`: the question as sent, one A record. */
static size_t upstream_answer(const uint8_t* fq, size_t fn, uint8_t* a)
{
    size_t qend = 12, n;
    while (fq[qend]) qend += 1u + fq[qend];
    qend += 5;
    memcpy(a, fq, qend);
    w16(a + 2, 0x8180);
    w16(a + 6, 1);
    w16(a + 8, 0);
    w16(a + 10, 0);
    n = qend;
    w16(a + n, 0xc00c);
    w16(a + n + 2, 1);
    w16(a + n + 4, 1);
    memset(a + n + 6, 0, 4);
    a[n + 9] = 60;
    w16(a + n + 10, 4);
    a[n + 12] = 93;
    a[n + 13] = 184;
    a[n + 14] = 216;
    a[n + 15] = 34;
    (void)fn;
    return n + 16;
}

static int answer_back(const uint8_t* a, size_t n)
{
    uint8_t* exact = (uint8_t*)malloc(n);
    int r;
    memcpy(exact, a, n);
    r = ts_dns_answer(&R, exact, n, out, sizeof(out), &out_len);
    free(exact);
    return r;
}

TEST(forwards_the_rest)
{
    uint8_t q[512], fq[TS_DNS_PKT_MAX], a[2048];
    size_t n, fn, an, dl, p;
    const uint8_t* d;
    unsigned gone, i;
    uint64_t next;

    ts_dns_init(&R, lookup, NULL, 99);

    /* forwarded with our id, the EDNS size cut to what fits the tun */
    n = dns_query(q, 0xabcd, "example.com", 1, 4096);
    REQUIRE(ask(4, q, n, 1, NOW0) == TS_DNS_FORWARD);
    fn = out_len;
    memcpy(fq, out, fn);
    CHECK(fn == n && memcmp(fq + 2, q + 2, 10) == 0 && memcmp(fq + 12, q + 12, n - 12 - 10 + 2) == 0);
    p = n - 10;                                                 /* the OPT record's type */
    CHECK(r16(fq + p + 2) == TS_DNS_UDP_MAX);
    CHECK(R.forwarded == 1);

    /* the answer back, under the phone's id */
    an = upstream_answer(fq, fn, a);
    REQUIRE(answer_back(a, an) == 1);
    d = reply_dns(4, out, out_len, &dl);
    REQUIRE(d != NULL);
    CHECK(r16(d) == 0xabcd && dl == an && memcmp(d + 2, a + 2, an - 2) == 0);
    /* once only */
    CHECK(answer_back(a, an) == 0);

    /* an answer under the right id to another question, or to no question waiting: not taken */
    n = dns_query(q, 1, "example.org", 1, 0);
    REQUIRE(ask(6, q, n, 1, NOW0) == TS_DNS_FORWARD);
    memcpy(fq, out, out_len);
    fn = out_len;
    an = upstream_answer(fq, fn, a);
    a[13] ^= 0x20;                                              /* "Example.org": another question */
    CHECK(answer_back(a, an) == 0);
    a[13] ^= 0x20;
    w16(a, r16(a) ^ 1);
    CHECK(answer_back(a, an) == 0);
    w16(a, r16(a) ^ 1);
    CHECK(answer_back(a, an) == 1 && reply_dns(6, out, out_len, &dl) != NULL && r16(out + 48) == 1);
    /* a query (not a response) as the answer: not taken */
    CHECK(answer_back(q, n) == 0);

    /* an answer too long for the tun: its header and question, TC set */
    n = dns_query(q, 2, "big.example", 1, 0);
    REQUIRE(ask(4, q, n, 1, NOW0) == TS_DNS_FORWARD);
    memcpy(fq, out, out_len);
    fn = out_len;
    an = upstream_answer(fq, fn, a);
    memset(a + an, 0, 1300 - an);
    REQUIRE(answer_back(a, 1300) == 1);
    d = reply_dns(4, out, out_len, &dl);
    REQUIRE(d != NULL);
    CHECK((r16(d + 2) & 0x0200) && r16(d + 6) == 0 && dl == n && r16(d) == 2);

    /* the waiting table: full, then the next is dropped; let go at the timeout */
    ts_dns_init(&R, lookup, NULL, 5);
    for (i = 0; i < TS_DNS_PENDING; i++) {
        char name[32];
        snprintf(name, sizeof(name), "n%u.example", i);
        n = dns_query(q, i, name, 1, 0);
        CHECK(ask(4, q, n, 1, NOW0 + i) == TS_DNS_FORWARD);
    }
    n = dns_query(q, 999, "one.too.many", 1, 0);
    CHECK(ask(4, q, n, 1, NOW0) == TS_DNS_DROP && R.dropped == 1);
    next = ts_dns_expire(&R, NOW0 + TS_DNS_TIMEOUT_NS - 1, &gone);
    CHECK(gone == 0 && next == NOW0 + TS_DNS_TIMEOUT_NS);
    next = ts_dns_expire(&R, NOW0 + TS_DNS_TIMEOUT_NS + 10, &gone);
    CHECK(gone == 11 && next == NOW0 + 11 + TS_DNS_TIMEOUT_NS);
    CHECK(ask(4, q, n, 1, NOW0 + 20) == TS_DNS_FORWARD);
    ts_dns_reset(&R);
    next = ts_dns_expire(&R, NOW0, &gone);
    CHECK(gone == 0 && next == ~0ULL);
    /* ids differ while they wait */
    ts_dns_init(&R, lookup, NULL, 5);
    {
        unsigned ids[TS_DNS_PENDING], j;
        int same = 0;
        for (i = 0; i < TS_DNS_PENDING; i++) {
            n = dns_query(q, 0, "x.example", 1, 0);
            REQUIRE(ask(4, q, n, 1, NOW0) == TS_DNS_FORWARD);
            ids[i] = r16(out);
            for (j = 0; j < i; j++)
                if (ids[j] == ids[i]) same = 1;
        }
        CHECK(!same);
    }
}

/* ------------------------------------------------------------------ not ours */

TEST(not_ours)
{
    uint8_t q[512], pkt[1024];
    size_t n, len;

    ts_dns_init(&R, lookup, NULL, 1);
    n = dns_query(q, 1, "nas.tail.ts.net", 1, 0);
    len = ip_wrap(4, q, n, pkt);
    CHECK(ts_dns_is_ours(pkt, len));
    pkt[19] = 8;                                                /* another address */
    CHECK(!ts_dns_is_ours(pkt, len));
    pkt[19] = 100;
    w16(pkt + 22, 5353);                                        /* another port */
    CHECK(!ts_dns_is_ours(pkt, len));
    w16(pkt + 22, 53);
    pkt[9] = 6;                                                 /* TCP */
    CHECK(!ts_dns_is_ours(pkt, len));
    pkt[9] = 17;
    w16(pkt + 6, 0x2000);                                       /* MF: a fragment */
    CHECK(!ts_dns_is_ours(pkt, len));
    w16(pkt + 6, 0);
    CHECK(!ts_dns_is_ours(pkt, len - 1));                       /* shorter than the IP header says */
    w16(pkt + 24, 4);                                           /* UDP length under its header */
    CHECK(!ts_dns_is_ours(pkt, len));
    CHECK(!ts_dns_is_ours(pkt, 0) && !ts_dns_is_ours(pkt, 19));
    /* a response sent to us: dropped */
    n = dns_query(q, 1, "nas.tail.ts.net", 1, 0);
    w16(q + 2, 0x8000);
    CHECK(ask(4, q, n, 1, NOW0) == TS_DNS_DROP);
    /* IPv6 with an extension header: not walked */
    n = dns_query(q, 1, "nas.tail.ts.net", 1, 0);
    len = ip_wrap(6, q, n, pkt);
    CHECK(ts_dns_is_ours(pkt, len));
    pkt[6] = 0;                                                 /* hop-by-hop */
    CHECK(!ts_dns_is_ours(pkt, len));
    CHECK(lookups > 0);
}

/* ------------------------------------------------------------------ fuzz */

static uint64_t xs = 0x6a09e667f3bcc909ULL;

static uint64_t rnd(void)
{
    xs ^= xs << 13;
    xs ^= xs >> 7;
    xs ^= xs << 17;
    return xs;
}

TEST(fuzz)
{
    static const char* const names[] = { "nas.tail.ts.net", "nas", "nobody.tail.ts.net", "example.com",
                                         "a.b.c.d.e.f", "many.tail.ts.net", "" };
    uint8_t q[TS_DNS_PKT_MAX], pkt[2048], a[TS_DNS_PKT_MAX + 64];
    int iter;
    uint64_t now = NOW0;

    ts_dns_init(&R, lookup, NULL, 3);
    for (iter = 0; iter < 200000; iter++) {
        int family = (rnd() & 1) ? 4 : 6, m;
        size_t n, len, an;
        uint8_t* exact;
        ts_dns_action act;

        now += rnd() % 200000000ULL;
        n = dns_query(q, (unsigned)rnd() & 0xffff, names[rnd() % (sizeof(names) / sizeof(names[0]))],
                      (unsigned)(rnd() % 3 == 0 ? rnd() & 0xff : (rnd() & 1) ? 1 : 28),
                      (rnd() & 1) ? (unsigned)(rnd() & 0xffff) : 0);
        len = ip_wrap(family, q, n, pkt);
        /* mutate: flip bytes, cut, grow with junk */
        for (m = (int)(rnd() % 4); m > 0; m--) {
            unsigned kind = (unsigned)(rnd() % 4);
            if (kind == 0 && len) pkt[rnd() % len] ^= (uint8_t)(1u << (rnd() % 8));
            else if (kind == 1 && len) pkt[rnd() % len] = (uint8_t)rnd();
            else if (kind == 2 && len) len = (size_t)(rnd() % len);
            else if (len + 64 < sizeof(pkt)) {
                size_t k, grow = (size_t)(rnd() % 64);
                for (k = 0; k < grow; k++) pkt[len + k] = (uint8_t)rnd();
                len += grow;
            }
        }
        if (rnd() % 50 == 0) {
            for (len = 0; len < (size_t)(rnd() % 600); len++) pkt[len] = (uint8_t)rnd();
        }
        exact = (uint8_t*)malloc(len ? len : 1);
        memcpy(exact, pkt, len);
        if (ts_dns_is_ours(exact, len)) {
            act = ts_dns_query(&R, exact, len, (rnd() % 8) != 0, now, out, sizeof(out), &out_len, &last_route);
            CHECK(out_len <= TS_DNS_PKT_MAX);
            if (act == TS_DNS_ANSWER) {
                size_t dl;
                CHECK(reply_check(exact[0] >> 4 == 4 ? 4 : 6, out, out_len, 0, &dl) != NULL);
            } else if (act == TS_DNS_FORWARD && rnd() % 3) {
                /* an answer back now and then, maybe mangled */
                memcpy(q, out, out_len);
                an = out_len;
                if (an >= 12) {
                    size_t k;
                    memcpy(a, q, an);
                    w16(a + 2, 0x8180);
                    if (rnd() % 4 == 0) {
                        for (k = 0; k < (size_t)(rnd() % 4); k++) a[rnd() % an] = (uint8_t)rnd();
                    }
                    if (rnd() % 10 == 0 && an + 200 < sizeof(a)) {
                        for (k = 0; k < 200; k++) a[an + k] = (uint8_t)rnd();
                        an += 200;
                    }
                    free(exact);
                    exact = (uint8_t*)malloc(an);
                    memcpy(exact, a, an);
                    if (ts_dns_answer(&R, exact, an, out, sizeof(out), &out_len)) CHECK(out_len <= TS_DNS_PKT_MAX);
                }
            }
        } else {
            /* not ours: never taken as a query */
            CHECK(ts_dns_query(&R, exact, len, 1, now, out, sizeof(out), &out_len, NULL) == TS_DNS_DROP);
        }
        free(exact);
        /* random junk as an answer */
        if (rnd() % 20 == 0) {
            size_t k, jl = (size_t)(rnd() % 300);
            exact = (uint8_t*)malloc(jl ? jl : 1);
            for (k = 0; k < jl; k++) exact[k] = (uint8_t)rnd();
            ts_dns_answer(&R, exact, jl, out, sizeof(out), &out_len);
            free(exact);
        }
        if (rnd() % 100 == 0) ts_dns_expire(&R, now, NULL);
    }
    {
        size_t i, used = 0;
        for (i = 0; i < TS_DNS_PENDING; i++) used += R.wait[i].used ? 1 : 0;
        CHECK(used <= TS_DNS_PENDING);
    }
    printf("    fuzz: answered %llu, forwarded %llu, upstream %llu, expired %llu, dropped %llu\n",
           (unsigned long long)R.answered, (unsigned long long)R.forwarded, (unsigned long long)R.upstream,
           (unsigned long long)R.expired, (unsigned long long)R.dropped);
}

int main(void)
{
    const char* seed = getenv("BT_FUZZ_SEED");

    if (seed) xs = strtoull(seed, NULL, 16) | 1;
    printf("test_ts_dns (fuzz seed %llx)\n", (unsigned long long)xs);
    RUN(answers_from_the_tailnet);
    RUN(forwards_the_rest);
    RUN(routed);
    RUN(not_ours);
    RUN(fuzz);
    return t_summary("test_ts_dns");
}
