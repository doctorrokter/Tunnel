/*
 * Everything the daemon takes from outside, fed random and mutated garbage under ASan/UBSan: the
 * control stream (a client), .meta and settings text (the disk), DNS replies (the network), names.
 * Each input sits in a heap buffer of exactly its size (plus the one writable byte the in-place
 * parsers are documented to need), so a read past it is caught. Beyond "no crash", properties:
 * blocks round-trip through the writer and reader, a parsed .meta formats back to itself, a reply
 * built from our own query parses.
 *
 * Seeded like the engine's fuzzer: BT_FUZZ_SEED=<hex> picks another run.
 */

#include "test_util.h"
#include "../src/bt_proto.h"
#include "../src/bt_resolve.h"
#include "../src/bt_store.h"

static uint64_t xs = 0x3c6ef372fe94f82bULL;

static uint64_t rnd(void)
{
    xs ^= xs >> 12;
    xs ^= xs << 25;
    xs ^= xs >> 27;
    return xs * 0x2545f4914f6cdd1dULL;
}

static void mutate(uint8_t* buf, size_t* len, size_t cap)
{
    static const uint8_t special[] = { 0, '\n', '\r', '\\', '=', ' ', '.', 0xc0, 0xff, 0x80, 'n', '1' };
    size_t n = *len, i, at;
    int k = (int)(rnd() % 6), times = 1 + (int)(rnd() % 4);

    switch (k) {
    case 0: while (n && times--) buf[rnd() % n] ^= (uint8_t)(1u << (rnd() % 8)); break;
    case 1: while (n && times--) buf[rnd() % n] = (uint8_t)rnd(); break;
    case 2: if (n) *len = rnd() % n; break;
    case 3:
        at = n + 1 + rnd() % 64;
        if (at > cap) at = cap;
        for (i = n; i < at; i++) buf[i] = (uint8_t)rnd();
        *len = at;
        break;
    case 4: while (n && times--) buf[rnd() % n] = special[rnd() % sizeof(special)]; break;
    default:
        if (n > 2) {                                    /* duplicate a slice */
            size_t from = rnd() % n, cnt = 1 + rnd() % (n - from);
            if (n + cnt <= cap) {
                memmove(buf + from + cnt, buf + from, n - from);
                *len = n + cnt;
            }
        }
        break;
    }
}

/* ------------------------------------------------------------------ the control stream */

static char rbuf[BT_BLOCK_MAX + 4];
static bt_block blk;

static void check_block(const bt_block* b)
{
    size_t i;
    for (i = 0; i < b->n; i++) {
        CHECK(bt_key_valid(b->kv[i].key, strlen(b->kv[i].key)));
        CHECK(strlen(b->kv[i].val) == b->kv[i].val_len);
    }
}

TEST(stream_garbage)
{
    static const char* seeds[] = {
        "cmd=profile.import\nid=1\nname=Home\nconf=[Interface]\\nPrivateKey = x\\n\n\n",
        "cmd=tunnel.up\r\nid=2\r\nprofile=3fa81c02\r\n\r\n",
        "event=tunnel\nstate=up\n\ncmd=watch\nstats=1\n\n",
    };
    uint8_t buf[2048];
    int iter;

    for (iter = 0; iter < 20000; iter++) {
        const char* s = seeds[rnd() % 3];
        size_t len = strlen(s), off = 0;
        bt_reader r;
        int m = (int)(rnd() % 4), rc = 0;

        memcpy(buf, s, len);
        while (m--) mutate(buf, &len, sizeof(buf));
        bt_reader_init(&r, rbuf, sizeof(rbuf));
        while (off < len && rc >= 0) {
            size_t room, step = 1 + rnd() % 64;
            char* p = bt_reader_space(&r, &room);
            if (step > len - off) step = len - off;
            if (step > room) step = room;
            memcpy(p, buf + off, step);
            bt_reader_commit(&r, step);
            off += step;
            while ((rc = bt_reader_next(&r, &blk, NULL, 0)) == 1) check_block(&blk);
        }
    }
}

TEST(block_parse_exact)
{
    uint8_t src[1024];
    int iter;

    for (iter = 0; iter < 20000; iter++) {
        size_t len = rnd() % 200, i;
        char* text;
        for (i = 0; i < len; i++) {
            static const char alpha[] = "ab=\\nr\n\r.0_ =";
            src[i] = rnd() % 4 ? (uint8_t)alpha[rnd() % (sizeof(alpha) - 1)] : (uint8_t)rnd();
        }
        text = (char*)malloc(len + 1);         /* text[len] is the documented spare byte */
        memcpy(text, src, len);
        if (bt_block_parse(&blk, text, len, NULL, 0)) check_block(&blk);
        free(text);
    }
}

TEST(roundtrip_random_values)
{
    static char wbuf[8192];
    uint8_t val[400];
    int iter;

    for (iter = 0; iter < 5000; iter++) {
        size_t len = rnd() % sizeof(val), i;
        bt_writer w;
        bt_reader r;
        size_t room;
        char* p;

        for (i = 0; i < len; i++) {
            val[i] = (uint8_t)(1 + rnd() % 255);        /* any byte but NUL */
            if (rnd() % 8 == 0) val[i] = (uint8_t)"\\\n\r="[rnd() % 4];
        }
        bt_writer_init(&w, wbuf, sizeof(wbuf));
        bt_put(&w, "cmd", "x");
        bt_put_n(&w, "v", (const char*)val, len);
        REQUIRE(bt_end(&w));
        bt_reader_init(&r, rbuf, sizeof(rbuf));
        p = bt_reader_space(&r, &room);
        memcpy(p, wbuf, w.len);
        bt_reader_commit(&r, w.len);
        REQUIRE(bt_reader_next(&r, &blk, NULL, 0) == 1);
        CHECK(blk.n == 2 && blk.kv[1].val_len == len && memcmp(blk.kv[1].val, val, len) == 0);
    }
}

/* ------------------------------------------------------------------ the disk */

TEST(meta_garbage)
{
    bt_meta m, again;
    char seed[2048], fmt[8192], fmt2[8192];
    uint8_t buf[4096];
    size_t seedlen, flen, flen2;
    int iter;

    memset(&m, 0, sizeof(m));
    strcpy(m.id, "0badc0de");
    strcpy(m.name, "Дом");
    strcpy(m.type, BT_TYPE_AMNEZIAWG);
    m.created = 1790776992;
    m.order = 2;
    m.ts_ceiling = 1790780592;
    m.n_resolved = 2;
    strcpy(m.resolved[0].host, "vpn.example.com");
    strcpy(m.resolved[0].addr, "203.0.113.7");
    strcpy(m.resolved[1].host, "vpn.example.com");
    strcpy(m.resolved[1].addr, "2001:db8::7");
    seedlen = bt_meta_format(&m, seed, sizeof(seed));
    REQUIRE(seedlen);

    for (iter = 0; iter < 20000; iter++) {
        size_t len = seedlen;
        char* text;
        int k = 1 + (int)(rnd() % 3);

        memcpy(buf, seed, len);
        while (k--) mutate(buf, &len, sizeof(buf));
        text = (char*)malloc(len + 1);
        memcpy(text, buf, len);
        if (bt_meta_parse(&m, text, len)) {
            /* what parses formats back to something that parses to the same */
            flen = bt_meta_format(&m, fmt, sizeof(fmt));
            REQUIRE(flen);
            memcpy(fmt2, fmt, flen);
            REQUIRE(bt_meta_parse(&again, fmt2, flen));
            flen2 = bt_meta_format(&again, fmt2, sizeof(fmt2));
            CHECK(flen2 == flen && memcmp(fmt, fmt2, flen) == 0);
            CHECK(bt_id_valid(m.id) && bt_name_valid(m.name, strlen(m.name)));
        }
        free(text);
    }
}

TEST(names_garbage)
{
    uint8_t buf[80];
    int iter;

    for (iter = 0; iter < 50000; iter++) {
        size_t len = rnd() % sizeof(buf), i;
        uint8_t* p;
        for (i = 0; i < len; i++) buf[i] = rnd() % 3 ? (uint8_t)(0x80 | rnd()) : (uint8_t)rnd();
        p = (uint8_t*)malloc(len ? len : 1);
        memcpy(p, buf, len);
        (void)bt_name_valid((const char*)p, len);
        free(p);
    }
}

/* ------------------------------------------------------------------ the network */

TEST(dns_garbage)
{
    /* a real-looking reply with a CNAME and compression, as the seed */
    static const char* seed_hex =
        "0007 8180 0001 0003 0000 0000"
        "03777777 076578616d706c65 03636f6d 00 0001 0001"
        "c00c 0005 0001 0000003c 0005 02 6531 c010"                 /* www -> e1.example.com */
        "c02d 0001 0001 0000003c 0004 0a010203"                     /* e1.example.com A */
        "c02d 0001 0001 0000003c 0004 0a010204";
    uint8_t seed[512], buf[BT_DNS_MSG_MAX];
    size_t seedlen = t_hex(seed, sizeof(seed), seed_hex);
    bt_dns_answer a;
    int iter;

    REQUIRE(bt_dns_parse(seed, seedlen, 7, "www.example.com", BT_DNS_TYPE_A, &a));
    REQUIRE(a.n == 2);

    for (iter = 0; iter < 50000; iter++) {
        size_t len = seedlen;
        uint8_t* p;
        int k = 1 + (int)(rnd() % 3);

        memcpy(buf, seed, len);
        while (k--) mutate(buf, &len, sizeof(buf));
        p = (uint8_t*)malloc(len ? len : 1);
        memcpy(p, buf, len);
        if (bt_dns_parse(p, len, 7, "www.example.com", BT_DNS_TYPE_A, &a)) {
            size_t i;
            CHECK(a.n <= BT_DNS_MAX_ADDRS);
            for (i = 0; i < a.n; i++) CHECK(a.addrs[i].family == 4);
        }
        free(p);
    }

    /* pure noise */
    for (iter = 0; iter < 20000; iter++) {
        size_t len = rnd() % 200, i;
        uint8_t* p = (uint8_t*)malloc(len ? len : 1);
        for (i = 0; i < len; i++) p[i] = (uint8_t)rnd();
        if (len > 12 && rnd() % 2) {
            p[0] = 0; p[1] = 7; p[4] = 0; p[5] = 1;
            p[2] |= 0x80;
            p[2] &= 0x87;
        }
        (void)bt_dns_parse(p, len, 7, "www.example.com", BT_DNS_TYPE_A, &a);
        free(p);
    }
}

TEST(query_echo_parses)
{
    char name[300];
    uint8_t q[320];
    bt_dns_answer a;
    int iter, valid = 0;

    for (iter = 0; iter < 20000; iter++) {
        size_t len = 1 + rnd() % 260, i, qlen;
        for (i = 0; i < len; i++) {
            static const char alpha[] = "abcXYZ019-_..";
            name[i] = rnd() % 50 ? alpha[rnd() % (sizeof(alpha) - 1)] : (char)(1 + rnd() % 255);
        }
        name[len] = 0;
        qlen = bt_dns_query(q, sizeof(q), 0x5151, name, BT_DNS_TYPE_AAAA);
        CHECK((qlen != 0) == bt_dns_name_valid(name));
        if (!qlen) continue;
        valid++;
        q[2] |= 0x80;                               /* our own query, turned into an empty reply */
        CHECK(bt_dns_parse(q, qlen, 0x5151, name, BT_DNS_TYPE_AAAA, &a) == 1);
        CHECK(a.rcode == 0 && a.n == 0);
    }
    CHECK(valid > 1000);
}

TEST(lookup_garbage)
{
    bt_addr server;
    bt_lookup l;
    uint8_t buf[600];
    int iter;

    memset(&server, 0, sizeof(server));
    server.family = 4;
    server.addr[0] = 10;
    for (iter = 0; iter < 20000; iter++) {
        size_t len = rnd() % sizeof(buf), i;
        uint8_t* p;
        if (iter % 50 == 0) bt_lookup_start(&l, "vpn.example.com", &server, 1, 1, 1, NULL, 0);
        for (i = 0; i < len; i++) buf[i] = (uint8_t)rnd();
        if (len >= 2 && rnd() % 2) {
            buf[0] = (uint8_t)(l.id[rnd() % 2] >> 8);
            buf[1] = (uint8_t)l.id[rnd() % 2];
        }
        p = (uint8_t*)malloc(len ? len : 1);
        memcpy(p, buf, len);
        (void)bt_lookup_receive(&l, &server, 53, p, len, (uint64_t)iter);
        free(p);
        CHECK(l.n <= BT_DNS_MAX_ADDRS);
    }
}

int main(void)
{
    const char* seed = getenv("BT_FUZZ_SEED");

    if (seed) xs = strtoull(seed, NULL, 16);
    if (!xs) xs = 1;
    printf("test_fuzz (seed %016llx)\n", (unsigned long long)xs);
    if (!wg_crypto_init()) return 2;
    RUN(stream_garbage);
    RUN(block_parse_exact);
    RUN(roundtrip_random_values);
    RUN(meta_garbage);
    RUN(names_garbage);
    RUN(dns_garbage);
    RUN(query_echo_parses);
    RUN(lookup_garbage);
    return t_summary("test_fuzz");
}
