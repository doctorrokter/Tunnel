/*
 * ts_h2: HPACK against RFC 7541 Appendix C (C.1-C.6) and against Go's encoder (vectors/h2), the
 * Huffman code symbol by symbol, the dynamic table against a model of it; the connection fed
 * hand-built frames - every frame type, flow control both ways, CONTINUATION, padding, GOAWAY,
 * malformed responses, EarlyNoise - in any pieces; fuzzing of the frame reader and of HPACK; and,
 * with TS_INTEROP / TS_INTEROP_IDLE / TS_INTEROP_SHUTDOWN, Go's own HTTP/2 server on loopback.
 *
 * Fuzz seed: TS_FUZZ_SEED=<hex>.
 */

#include "test_util.h"
#include "../src/ts_h2.h"
#include "../src/ts_http1.h"
#include "vectors/h2/kat_h2.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static uint64_t xs = 0x6a09e667f3bcc909ULL;

static uint64_t rnd(void)
{
    xs ^= xs >> 12;
    xs ^= xs << 25;
    xs ^= xs >> 27;
    return xs * 0x2545f4914f6cdd1dULL;
}

static uint8_t pat(int seed, size_t i)
{
    return (uint8_t)((i * 7 + (size_t)seed) % 251);
}

static void put32(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t get32(const uint8_t* p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* ================================================================== HPACK */

static ts_hpack H;
static ts_hpack_list L;

/* The list as "name: value\n" lines. */
static const char* list_text(const ts_hpack_list* l)
{
    static char s[1 << 16];
    size_t n = 0, i;

    s[0] = '\0';
    for (i = 0; i < l->n && n < sizeof(s) - 1; i++)
        n += (size_t)snprintf(s + n, sizeof(s) - n, "%s: %s\n", l->fields[i].name, l->fields[i].value);
    return s;
}

/* The dynamic table, newest first, as "name: value\n" lines. */
static const char* table_text(const ts_hpack* h)
{
    static char s[1 << 14];
    const uint8_t *nm, *vl;
    size_t n = 0, i, nl, vlen;

    s[0] = '\0';
    for (i = 0; ts_hpack_entry(h, i, &nm, &nl, &vl, &vlen); i++)
        n += (size_t)snprintf(s + n, sizeof(s) - n, "%.*s: %.*s\n", (int)nl, nm, (int)vlen, vl);
    return s;
}

static int dec_hex(const char* hex)
{
    static uint8_t b[4096];
    size_t n = t_hex(b, sizeof(b), hex);

    return ts_hpack_decode(&H, b, n, &L);
}

TEST(hpack_integers_c1)
{
    uint8_t b[16];
    uint64_t v;
    size_t pos;

    /* C.1.1: 10 with a 5-bit prefix; C.1.2: 1337 with a 5-bit prefix; C.1.3: 42 on a byte */
    CHECK(ts_hpack_put_int(b, sizeof(b), 0xe0, 5, 10) == 1 && b[0] == 0xea);
    CHECK(ts_hpack_put_int(b, sizeof(b), 0x00, 5, 1337) == 3 && b[0] == 0x1f && b[1] == 0x9a && b[2] == 0x0a);
    CHECK(ts_hpack_put_int(b, sizeof(b), 0x00, 8, 42) == 1 && b[0] == 0x2a);
    pos = 0;
    CHECK(ts_hpack_get_int((const uint8_t*)"\x1f\x9a\x0a", 3, &pos, 5, &v) && v == 1337 && pos == 3);
    pos = 0;
    CHECK(ts_hpack_get_int((const uint8_t*)"\xea", 1, &pos, 5, &v) && v == 10 && pos == 1);
    pos = 0;
    CHECK(ts_hpack_get_int((const uint8_t*)"\x2a", 1, &pos, 8, &v) && v == 42);
    /* the prefix value itself needs a zero continuation */
    CHECK(ts_hpack_put_int(b, sizeof(b), 0, 5, 31) == 2 && b[0] == 0x1f && b[1] == 0x00);
    pos = 0;
    CHECK(ts_hpack_get_int(b, 2, &pos, 5, &v) && v == 31);
    /* over-long but valid, as Go's readVarInt: up to 9 continuation bytes */
    pos = 0;
    CHECK(ts_hpack_get_int((const uint8_t*)"\x1f\x80\x80\x80\x80\x80\x80\x80\x80\x00", 10, &pos, 5, &v) && v == 31);
    pos = 0;
    CHECK(!ts_hpack_get_int((const uint8_t*)"\x1f\x80\x80\x80\x80\x80\x80\x80\x80\x80\x00", 11, &pos, 5, &v));
    pos = 0;
    CHECK(!ts_hpack_get_int((const uint8_t*)"\x1f\x80", 2, &pos, 5, &v));      /* runs out */
    pos = 0;
    CHECK(!ts_hpack_get_int((const uint8_t*)"", 0, &pos, 5, &v));
    CHECK(ts_hpack_put_int(b, 2, 0, 5, 1337) == 0);                           /* no room */
    CHECK(ts_hpack_put_int(b, 0, 0, 5, 1) == 0);
    /* every value up to 2^56 round-trips through every prefix (9 continuation bytes at most) */
    {
        int i, ok = 1;
        for (i = 0; i < 20000; i++) {
            unsigned n = 1 + (unsigned)(rnd() % 8);
            uint64_t want = rnd() >> (8 + rnd() % 56);
            size_t k = ts_hpack_put_int(b, sizeof(b), 0, n, want);
            pos = 0;
            ok &= k > 0 && ts_hpack_get_int(b, k, &pos, n, &v) && v == want && pos == k;
        }
        CHECK(ok);
    }
}

TEST(hpack_static_table)
{
    uint8_t b[1];
    unsigned i;

    ts_hpack_init(&H, 4096);
    for (i = 1; i <= 61; i++) {
        b[0] = (uint8_t)(0x80 | i);
        REQUIRE(ts_hpack_decode(&H, b, 1, &L) && L.n == 1);
        CHECK(strcmp(L.fields[0].name, kat_static[i][0]) == 0);
        CHECK(strcmp(L.fields[0].value, kat_static[i][1]) == 0);
    }
    CHECK(!dec_hex("80"));                          /* index 0 */
    ts_hpack_init(&H, 4096);
    CHECK(!dec_hex("be"));                          /* 62: the dynamic table is empty */
}

/* Encodes with Go's code table (kat_huff): a second encoder, to build test strings. */
static size_t huff_encode(const uint8_t* in, size_t n, uint8_t* out)
{
    uint64_t acc = 0;
    unsigned bits = 0;
    size_t o = 0, i;

    for (i = 0; i < n; i++) {
        acc = (acc << kat_huff[in[i]].bits) | kat_huff[in[i]].code;
        bits += kat_huff[in[i]].bits;
        while (bits >= 8) {
            out[o++] = (uint8_t)(acc >> (bits - 8));
            bits -= 8;
        }
    }
    if (bits) out[o++] = (uint8_t)((acc << (8 - bits)) | (0xffu >> bits));
    return o;
}

TEST(hpack_huffman)
{
    uint8_t enc[2048], dec[2048];
    size_t i, n;
    int ok = 1;

    /* every symbol of Go's table, alone and between two others */
    for (i = 0; i < 256; i++) {
        uint8_t s[3] = { 'a', (uint8_t)i, 0xff };
        n = huff_encode(s + 1, 1, enc);
        ok &= ts_hpack_huffman_decode(enc, n, dec, sizeof(dec)) == 1 && dec[0] == i;
        n = huff_encode(s, 3, enc);
        ok &= ts_hpack_huffman_decode(enc, n, dec, sizeof(dec)) == 3 && memcmp(dec, s, 3) == 0;
    }
    CHECK(ok);
    /* Go's encodings of strings decode back, and our test encoder writes the same bytes */
    for (i = 0; i < sizeof(kat_huff_str) / sizeof(kat_huff_str[0]); i++) {
        n = ts_hpack_huffman_decode((const uint8_t*)kat_huff_str[i].enc, kat_huff_str[i].enclen, dec, sizeof(dec));
        CHECK(n == kat_huff_str[i].inlen && memcmp(dec, kat_huff_str[i].in, n) == 0);
        CHECK(huff_encode((const uint8_t*)kat_huff_str[i].in, kat_huff_str[i].inlen, enc) == kat_huff_str[i].enclen);
        CHECK(memcmp(enc, kat_huff_str[i].enc, kat_huff_str[i].enclen) == 0);
    }
    /* padding: at most 7 bits, all ones; EOS inside is refused */
    n = huff_encode((const uint8_t*)"a", 1, enc);   /* 00011 + 111 */
    CHECK(n == 1 && enc[0] == 0x1f);
    CHECK(ts_hpack_huffman_decode((const uint8_t*)"\x1f\xff", 2, dec, sizeof(dec)) == (size_t)-1);   /* 11 bits */
    CHECK(ts_hpack_huffman_decode((const uint8_t*)"\x1e", 1, dec, sizeof(dec)) == (size_t)-1);       /* a 0 in it */
    CHECK(ts_hpack_huffman_decode((const uint8_t*)"\xff\xff\xff\xff", 4, dec, sizeof(dec)) == (size_t)-1); /* EOS */
    CHECK(ts_hpack_huffman_decode((const uint8_t*)"\xff\xff\xff\xfc", 4, dec, sizeof(dec)) == (size_t)-1); /* EOS + 00 */
    CHECK(ts_hpack_huffman_decode((const uint8_t*)"", 0, dec, sizeof(dec)) == 0);
    CHECK(ts_hpack_huffman_decode((const uint8_t*)"\xff", 1, dec, sizeof(dec)) == (size_t)-1);       /* 8 bits of pad */
    /* past the room: the whole length is still told, nothing written beyond */
    n = huff_encode((const uint8_t*)"www.example.com", 15, enc);
    memset(dec, 0x55, sizeof(dec));
    CHECK(ts_hpack_huffman_decode(enc, n, dec, 4) == 15 && memcmp(dec, "www.", 4) == 0 && dec[4] == 0x55);
    CHECK(ts_hpack_huffman_decode(enc, n, NULL, 0) == 15);
}

TEST(hpack_c2_single_fields)
{
    ts_hpack_init(&H, 4096);
    REQUIRE(dec_hex("400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572"));
    CHECK(strcmp(list_text(&L), "custom-key: custom-header\n") == 0);
    CHECK(H.size == 55 && strcmp(table_text(&H), "custom-key: custom-header\n") == 0);

    ts_hpack_init(&H, 4096);
    REQUIRE(dec_hex("040c 2f73 616d 706c 652f 7061 7468"));
    CHECK(strcmp(list_text(&L), ":path: /sample/path\n") == 0 && H.size == 0);

    ts_hpack_init(&H, 4096);
    REQUIRE(dec_hex("1008 7061 7373 776f 7264 0673 6563 7265 74"));
    CHECK(strcmp(list_text(&L), "password: secret\n") == 0 && H.size == 0);

    ts_hpack_init(&H, 4096);
    REQUIRE(dec_hex("82"));
    CHECK(strcmp(list_text(&L), ":method: GET\n") == 0 && H.size == 0);
}

static void c3_c4(const char* r1, const char* r2, const char* r3)
{
    ts_hpack_init(&H, 4096);
    REQUIRE(dec_hex(r1));
    CHECK(strcmp(list_text(&L), ":method: GET\n:scheme: http\n:path: /\n:authority: www.example.com\n") == 0);
    CHECK(H.size == 57 && strcmp(table_text(&H), ":authority: www.example.com\n") == 0);
    REQUIRE(dec_hex(r2));
    CHECK(strcmp(list_text(&L), ":method: GET\n:scheme: http\n:path: /\n:authority: www.example.com\n"
                                "cache-control: no-cache\n") == 0);
    CHECK(H.size == 110 && strcmp(table_text(&H), "cache-control: no-cache\n:authority: www.example.com\n") == 0);
    REQUIRE(dec_hex(r3));
    CHECK(strcmp(list_text(&L), ":method: GET\n:scheme: https\n:path: /index.html\n:authority: www.example.com\n"
                                "custom-key: custom-value\n") == 0);
    CHECK(H.size == 164);
    CHECK(strcmp(table_text(&H), "custom-key: custom-value\ncache-control: no-cache\n:authority: www.example.com\n") == 0);
}

TEST(hpack_c3_requests)
{
    c3_c4("8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d",
          "8286 84be 5808 6e6f 2d63 6163 6865",
          "8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65");
}

TEST(hpack_c4_requests_huffman)
{
    c3_c4("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff",
          "8286 84be 5886 a8eb 1064 9cbf",
          "8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf");
}

static void c5_c6(const char* r1, const char* r2, const char* r3)
{
    ts_hpack_init(&H, 256);                         /* the examples' table: 256 bytes */
    REQUIRE(dec_hex(r1));
    CHECK(strcmp(list_text(&L), ":status: 302\ncache-control: private\ndate: Mon, 21 Oct 2013 20:13:21 GMT\n"
                                "location: https://www.example.com\n") == 0);
    CHECK(H.size == 222);
    CHECK(strcmp(table_text(&H), "location: https://www.example.com\ndate: Mon, 21 Oct 2013 20:13:21 GMT\n"
                                 "cache-control: private\n:status: 302\n") == 0);
    REQUIRE(dec_hex(r2));
    CHECK(strcmp(list_text(&L), ":status: 307\ncache-control: private\ndate: Mon, 21 Oct 2013 20:13:21 GMT\n"
                                "location: https://www.example.com\n") == 0);
    CHECK(H.size == 222);
    CHECK(strcmp(table_text(&H), ":status: 307\nlocation: https://www.example.com\n"
                                 "date: Mon, 21 Oct 2013 20:13:21 GMT\ncache-control: private\n") == 0);
    REQUIRE(dec_hex(r3));
    CHECK(strcmp(list_text(&L), ":status: 200\ncache-control: private\ndate: Mon, 21 Oct 2013 20:13:22 GMT\n"
                                "location: https://www.example.com\ncontent-encoding: gzip\n"
                                "set-cookie: foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1\n") == 0);
    CHECK(H.size == 215);
    CHECK(strcmp(table_text(&H), "set-cookie: foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1\n"
                                 "content-encoding: gzip\ndate: Mon, 21 Oct 2013 20:13:22 GMT\n") == 0);
}

TEST(hpack_c5_responses)
{
    c5_c6("4803 3330 3258 0770 7269 7661 7465 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a "
          "3133 3a32 3120 474d 546e 1768 7474 7073 3a2f 2f77 7777 2e65 7861 6d70 6c65 2e63 6f6d",
          "4803 3330 37c1 c0bf",
          "88c1 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 3a32 3220 474d 54c0 5a04 "
          "677a 6970 7738 666f 6f3d 4153 444a 4b48 514b 425a 584f 5157 454f 5049 5541 5851 5745 4f49 "
          "553b 206d 6178 2d61 6765 3d33 3630 303b 2076 6572 7369 6f6e 3d31");
}

TEST(hpack_c6_responses_huffman)
{
    c5_c6("4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 66e0 82a6 2d1b ff6e "
          "919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3",
          "4883 640e ffc1 c0bf",
          "88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff c05a 839b d9ab 77ad 94e7 "
          "821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f 9587 3160 65c0 03ed "
          "4ee5 b106 3d50 07");
}

TEST(hpack_go_vectors)
{
    size_t s, b, i, blocks = 0, fields = 0;

    for (s = 0; s < sizeof(kat_hpack) / sizeof(kat_hpack[0]); s++) {
        ts_hpack_init(&H, 4096);
        for (b = 0; b < kat_hpack[s].n; b++) {
            const kat_block* k = &kat_hpack[s].blocks[b];
            uint64_t want_size = 0;
            int same = 1;

            REQUIRE(ts_hpack_decode(&H, (const uint8_t*)k->blk, k->len, &L));
            blocks++;
            CHECK(H.size <= H.max_size && H.max_size <= 4096);
            for (i = 0; i < k->n; i++) want_size += k->want[i].nlen + k->want[i].vlen + 32;
            CHECK(L.size == want_size);
            if (L.overflow) {
                /* only when the list really is over the limits */
                CHECK(want_size > TS_H2_HEADER_LIST_MAX || k->n > TS_H2_FIELDS_MAX || k->n != L.n);
                continue;
            }
            REQUIRE(L.n == k->n);
            for (i = 0; i < k->n; i++) {
                same &= L.fields[i].name_len == k->want[i].nlen && memcmp(L.fields[i].name, k->want[i].name, k->want[i].nlen) == 0;
                same &= L.fields[i].value_len == k->want[i].vlen && memcmp(L.fields[i].value, k->want[i].value, k->want[i].vlen) == 0;
                same &= L.fields[i].name[L.fields[i].name_len] == '\0' && L.fields[i].value[L.fields[i].value_len] == '\0';
            }
            fields += k->n;
            CHECK(same);
        }
    }
    CHECK(blocks == 12 * 6 && fields > 200);
}

TEST(hpack_refusals)
{
    ts_hpack_init(&H, 4096);
    CHECK(!dec_hex("80"));                          /* index 0 */
    ts_hpack_init(&H, 4096);
    CHECK(!dec_hex("bf"));                          /* 63, nothing there */
    ts_hpack_init(&H, 4096);
    CHECK(!dec_hex("7f01 0161"));                   /* a literal naming entry 64 */
    ts_hpack_init(&H, 4096);
    CHECK(!dec_hex("0003 6162"));                   /* a name running past the block */
    ts_hpack_init(&H, 4096);
    CHECK(!dec_hex("0001 61"));                     /* no value */
    ts_hpack_init(&H, 4096);
    CHECK(!dec_hex("0081 ff 01 61"));               /* a Huffman name of 8 pad bits */
    ts_hpack_init(&H, 4096);
    CHECK(!dec_hex("0084 ffff ffff 0161"));         /* EOS in a name */
    ts_hpack_init(&H, 4096);
    CHECK(!dec_hex("3fe2 1f"));                     /* a size update to 4097, over our 4096 */
    ts_hpack_init(&H, 4096);
    CHECK(dec_hex("3fe1 1f"));                      /* 4096 is fine */
    ts_hpack_init(&H, 4096);
    CHECK(!dec_hex("82 20"));                       /* a size update after a field */
    ts_hpack_init(&H, 4096);
    CHECK(dec_hex("20 3fe1 1f 82"));                /* two at the start (the smallest, then the final) */
    CHECK(H.max_size == 4096);
    ts_hpack_init(&H, 4096);
    CHECK(!dec_hex("ff80 8080 8080 8080 8080 8000"));    /* an integer of 10 continuation bytes */
    ts_hpack_init(&H, 4096);
    CHECK(!dec_hex("7f"));                          /* a truncated integer */
    ts_hpack_init(&H, 256);
    CHECK(!dec_hex("3f e2 01"));                    /* over a limit of 256 */
    /* an empty block is a valid empty list */
    ts_hpack_init(&H, 4096);
    CHECK(ts_hpack_decode(&H, NULL, 0, &L) && L.n == 0);
}

TEST(hpack_table_mechanics)
{
    char big[5000];

    /* RFC 7541 4.4: a new entry may name the entry it evicts */
    ts_hpack_init(&H, 4096);
    REQUIRE(dec_hex("3f09"));                       /* max size 40 */
    REQUIRE(dec_hex("4004 6161 6161 0178"));        /* "aaaa: x" = 37 */
    CHECK(H.size == 37 && H.count == 1);
    REQUIRE(dec_hex("7e02 7979"));                  /* name of entry 62, value "yy": 38, evicts 62 */
    CHECK(strcmp(list_text(&L), "aaaa: yy\n") == 0);
    CHECK(H.size == 38 && strcmp(table_text(&H), "aaaa: yy\n") == 0);

    /* one byte over the table: emptied, not added (and not a wrap below zero) */
    ts_hpack_init(&H, 4096);
    REQUIRE(dec_hex("3f09 4001 6101 62"));          /* max 40, "a: b" = 34 */
    REQUIRE(dec_hex("4004 6161 6161 0562 6262 6262"));    /* "aaaa: bbbbb" = 41 */
    CHECK(H.count == 0 && H.size == 0 && strcmp(list_text(&L), "aaaa: bbbbb\n") == 0);
    REQUIRE(dec_hex("4004 6161 6161 0462 6262 62"));      /* 40: fits exactly */
    CHECK(H.count == 1 && H.size == 40);

    /* an entry larger than the table empties it, and is still a field of the list */
    ts_hpack_init(&H, 4096);
    REQUIRE(dec_hex("4001 6101 62"));
    CHECK(H.count == 1);
    {
        static uint8_t b[6000];
        size_t n = 0;
        memset(big, 'v', 4070);
        b[n++] = 0x40;
        b[n++] = 0x01;
        b[n++] = 'k';
        n += ts_hpack_put_int(b + n, sizeof(b) - n, 0, 7, 4070);
        memcpy(b + n, big, 4070);
        n += 4070;
        REQUIRE(ts_hpack_decode(&H, b, n, &L));     /* 1 + 4070 + 32 > 4096 */
        CHECK(H.count == 0 && H.size == 0 && L.n == 1 && L.fields[0].value_len == 4070);
    }
    /* a size update evicts, from the oldest */
    ts_hpack_init(&H, 4096);
    REQUIRE(dec_hex("4001 6101 31 4001 6201 32 4001 6301 33"));
    CHECK(H.count == 3 && H.size == 102);
    REQUIRE(dec_hex("3f2f"));                       /* max size 31 + 47 = 78: the oldest goes */
    CHECK(H.max_size == 78 && H.count == 2 && strcmp(table_text(&H), "c: 3\nb: 2\n") == 0);
    REQUIRE(dec_hex("20"));
    CHECK(H.count == 0 && H.size == 0);
    REQUIRE(dec_hex("3fe1 1f 4001 6401 34"));       /* back up to 4096: the table fills again */
    CHECK(H.count == 1 && H.size == 34);
}

/* The dynamic table as RFC 7541 describes it, plainly: newest first. */
typedef struct { char name[300]; char value[300]; } mentry;
static mentry model[200];
static size_t mcount;
static uint32_t msize, mmax;

static void model_evict(uint32_t max)
{
    while (mcount && msize > max) {
        mcount--;
        msize -= (uint32_t)(strlen(model[mcount].name) + strlen(model[mcount].value) + 32);
    }
}

static void model_add(const char* n, const char* v)
{
    uint32_t s = (uint32_t)(strlen(n) + strlen(v) + 32);

    if (s > mmax) {
        model_evict(0);
        return;
    }
    model_evict(mmax - s);
    memmove(model + 1, model, mcount * sizeof(model[0]));
    strcpy(model[0].name, n);
    strcpy(model[0].value, v);
    mcount++;
    msize += s;
}

TEST(hpack_table_against_model)
{
    static uint8_t b[16384];
    char name[300], value[300];
    int iter, ok = 1;

    ts_hpack_init(&H, 4096);
    mcount = 0;
    msize = 0;
    mmax = 4096;
    for (iter = 0; iter < 4000; iter++) {
        size_t n = 0, k, f, nf = 1 + rnd() % 6;

        if (rnd() % 8 == 0) {
            mmax = (uint32_t)(rnd() % 4097);
            n += ts_hpack_put_int(b + n, sizeof(b) - n, 0x20, 5, mmax);
            model_evict(mmax);
        }
        for (f = 0; f < nf; f++) {
            size_t nl = rnd() % 4 ? 1 + rnd() % 12 : rnd() % 280, vl = rnd() % 4 ? rnd() % 20 : rnd() % 290;
            int by_index = mcount && rnd() % 3 == 0;
            if (by_index) {
                /* name an existing entry: the copy must survive the eviction this insert may do */
                size_t idx = rnd() % mcount;
                strcpy(name, model[idx].name);
                n += ts_hpack_put_int(b + n, sizeof(b) - n, 0x40, 6, 62 + idx);
            } else {
                for (k = 0; k < nl; k++) name[k] = (char)('a' + rnd() % 26);
                name[nl] = '\0';
                n += ts_hpack_put_int(b + n, sizeof(b) - n, 0x40, 6, 0);
                n += ts_hpack_put_int(b + n, sizeof(b) - n, 0, 7, nl);
                memcpy(b + n, name, nl);
                n += nl;
            }
            for (k = 0; k < vl; k++) value[k] = (char)('A' + rnd() % 26);
            value[vl] = '\0';
            n += ts_hpack_put_int(b + n, sizeof(b) - n, 0, 7, vl);
            memcpy(b + n, value, vl);
            n += vl;
            model_add(name, value);
        }
        REQUIRE(ts_hpack_decode(&H, b, n, &L));
        ok &= H.count == mcount && H.size == msize && H.max_size == mmax;
        for (k = 0; k < mcount && ok; k++) {
            const uint8_t *nm, *vv;
            size_t nl2, vl2;
            ok &= ts_hpack_entry(&H, k, &nm, &nl2, &vv, &vl2) && nl2 == strlen(model[k].name) &&
                  vl2 == strlen(model[k].value) && memcmp(nm, model[k].name, nl2) == 0 && memcmp(vv, model[k].value, vl2) == 0;
        }
        if (!ok) break;
    }
    CHECK(ok);
}

TEST(hpack_list_limits)
{
    static uint8_t b[40000];
    size_t n = 0, i;

    /* 65 fields: the list keeps 64 and says it overflowed; the table still took all of them */
    ts_hpack_init(&H, 4096);
    for (i = 0; i < 65; i++) {
        b[n++] = 0x40;
        b[n++] = 0x01;
        b[n++] = (uint8_t)('a' + i % 26);
        b[n++] = 0x01;
        b[n++] = (uint8_t)('0' + i % 10);
    }
    REQUIRE(ts_hpack_decode(&H, b, n, &L));
    CHECK(L.overflow && L.n == TS_H2_FIELDS_MAX && H.count == 65);
    /* over the list's size: dropped from there on, but a field the table must take is still whole */
    ts_hpack_init(&H, 4096);
    n = 0;
    for (i = 0; i < 5; i++) {                       /* 5 x (1 + 3500 + 32): over 16384 at the 5th */
        b[n++] = 0x00;
        b[n++] = 0x01;
        b[n++] = 'x';
        n += ts_hpack_put_int(b + n, sizeof(b) - n, 0, 7, 3500);
        memset(b + n, 'v', 3500);
        n += 3500;
    }
    b[n++] = 0x40;                                  /* then an indexed one, 1 + 2000 */
    b[n++] = 0x01;
    b[n++] = 'k';
    n += ts_hpack_put_int(b + n, sizeof(b) - n, 0, 7, 2000);
    memset(b + n, 'w', 2000);
    n += 2000;
    REQUIRE(ts_hpack_decode(&H, b, n, &L));
    CHECK(L.overflow && L.n == 4 && H.count == 1);
    {
        const uint8_t *nm, *vv;
        size_t nl, vl;
        CHECK(ts_hpack_entry(&H, 0, &nm, &nl, &vv, &vl) && nl == 1 && nm[0] == 'k' && vl == 2000 && vv[1999] == 'w');
    }
}

/* ================================================================== the connection */

static ts_h2 C;

/* The server's side, built by hand. */
static uint8_t wbuf[1 << 21];
static size_t wlen;

static void frame(uint8_t type, uint8_t flags, uint32_t stream, const void* p, size_t len)
{
    uint8_t* w = wbuf + wlen;

    w[0] = (uint8_t)(len >> 16);
    w[1] = (uint8_t)(len >> 8);
    w[2] = (uint8_t)len;
    w[3] = type;
    w[4] = flags;
    put32(w + 5, stream);
    if (len) memcpy(w + 9, p, len);
    wlen += 9 + len;
}

static void raw(const void* p, size_t len)
{
    memcpy(wbuf + wlen, p, len);
    wlen += len;
}

static void settings(const uint32_t* kv, size_t n)
{
    uint8_t p[96];
    size_t i;

    for (i = 0; i < n; i++) {
        p[6 * i] = (uint8_t)(kv[2 * i] >> 8);
        p[6 * i + 1] = (uint8_t)kv[2 * i];
        put32(p + 6 * i + 2, kv[2 * i + 1]);
    }
    frame(0x4, 0, 0, p, 6 * n);
}

static void window_update(uint32_t stream, uint32_t inc)
{
    uint8_t p[4];

    put32(p, inc);
    frame(0x8, 0, stream, p, 4);
}

static void rst(uint32_t stream, uint32_t code)
{
    uint8_t p[4];

    put32(p, code);
    frame(0x3, 0, stream, p, 4);
}

static void goaway_frame(uint32_t last, uint32_t code, const char* debug)
{
    uint8_t p[128];
    size_t n = debug ? strlen(debug) : 0;

    put32(p, last);
    put32(p + 4, code);
    if (n) memcpy(p + 8, debug, n);
    frame(0x7, 0, 0, p, 8 + n);
}

/* What x/net's server sends first (server.go serve): its SETTINGS, unknown ones included, and
 * the WINDOW_UPDATE up to its 1 MiB connection window. */
static void go_preface(void)
{
    static const uint32_t s[] = { 5, 1 << 20, 3, 250, 6, 1048896, 1, 4096, 4, 1 << 20, 8, 1, 9, 1 };

    settings(s, 7);
    window_update(0, (1 << 20) - 65535);
}

/* Header blocks, the server's encoder by hand. */
typedef struct {
    uint8_t b[40000];
    size_t  n;
} blk;

static blk K;

static void bk_int(uint8_t first, unsigned n, uint64_t v)
{
    K.n += ts_hpack_put_int(K.b + K.n, sizeof(K.b) - K.n, first, n, v);
}

static void bk_str(const char* s, int huff)
{
    size_t n = strlen(s);

    if (huff) {
        static uint8_t tmp[20000];
        size_t m = huff_encode((const uint8_t*)s, n, tmp);
        bk_int(0x80, 7, m);
        memcpy(K.b + K.n, tmp, m);
        K.n += m;
    } else {
        bk_int(0x00, 7, n);
        memcpy(K.b + K.n, s, n);
        K.n += n;
    }
}

/* mode 0: without indexing, 1: incremental indexing, 2: never indexed */
static void bk_lit(int mode, unsigned idx, const char* name, const char* value, int huff)
{
    if (mode == 1) bk_int(0x40, 6, idx);
    else bk_int(mode == 2 ? 0x10 : 0x00, 4, idx);
    if (!idx) bk_str(name, huff);
    bk_str(value, huff);
}

/* A response head the way Go's encoder writes one: :status indexed when the static table has it,
 * the rest literal with incremental indexing, Huffman. kv: name, value, ..., NULL. */
static void resp_head(uint32_t stream, uint8_t flags, const char* status, const char* const* kv)
{
    K.n = 0;
    if (strcmp(status, "200") == 0) bk_int(0x80, 7, 8);
    else if (strcmp(status, "404") == 0) bk_int(0x80, 7, 13);
    else bk_lit(1, 8, NULL, status, 1);
    for (; kv && *kv; kv += 2) bk_lit(1, 0, kv[0], kv[1], 1);
    frame(0x1, (uint8_t)(flags | 0x4), stream, K.b, K.n);
}

/* --- the client's side: events into a log, DATA checked or kept per stream */

static char logb[1 << 16];
static size_t logn;
static uint32_t log_last_data;
static int auto_consume;
static uint8_t store[64][4096];
static size_t got[64];
static int seed_of[64];
static int bad[64];
static size_t data_events[64];

static void logf_(const char* fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    if (logn < sizeof(logb)) logn += (size_t)vsnprintf(logb + logn, sizeof(logb) - logn, fmt, ap);
    va_end(ap);
    if (logn > sizeof(logb) - 1) logn = sizeof(logb) - 1;
}

static void record(const ts_h2_event* e)
{
    uint32_t sid = e->stream < 64 ? e->stream : 63;
    size_t i;

    if (e->type != TS_H2_EV_DATA) log_last_data = 0;
    switch (e->type) {
    case TS_H2_EV_EARLY:
        logf_("Y %.*s\n", (int)e->len, (const char*)e->data);
        break;
    case TS_H2_EV_HEADERS:
        logf_("H%u %d", (unsigned)e->stream, e->status);
        for (i = 0; i < e->n_fields; i++) logf_(" %s=%s", e->fields[i].name, e->fields[i].value);
        logf_("\n");
        break;
    case TS_H2_EV_DATA:
        if (log_last_data != e->stream) logf_("D%u\n", (unsigned)e->stream);
        log_last_data = e->stream;
        data_events[sid]++;
        for (i = 0; i < e->len; i++) {
            if (seed_of[sid] >= 0) bad[sid] |= e->data[i] != pat(seed_of[sid], got[sid] + i);
            else if (got[sid] + i < sizeof(store[0])) store[sid][got[sid] + i] = e->data[i];
        }
        got[sid] += e->len;
        if (auto_consume) ts_h2_consume(&C, e->stream, e->len);
        break;
    case TS_H2_EV_END:
        logf_("E%u\n", (unsigned)e->stream);
        break;
    case TS_H2_EV_RESET:
        logf_("R%u %u%s%s\n", (unsigned)e->stream, (unsigned)e->error, e->refused ? " refused" : "", e->local ? " local" : "");
        break;
    case TS_H2_EV_GOAWAY:
        logf_("G %u %u%s%.*s\n", (unsigned)e->last_stream, (unsigned)e->error, e->len ? " " : "", (int)e->len, (const char*)e->data);
        break;
    case TS_H2_EV_CLOSED:
        logf_("C %u%s\n", (unsigned)e->error, e->local ? " local" : "");
        break;
    default:
        logf_("?\n");
        break;
    }
}

/* Feeds p[0, n) in pieces of `step` (0: at once) and records every event, the waiting ones too. */
static void deliver(const uint8_t* p, size_t n, size_t step)
{
    size_t off = 0;

    for (;;) {
        ts_h2_event ev;
        size_t k = step ? step : n - off, used;

        if (k > n - off) k = n - off;
        used = ts_h2_input(&C, p ? p + off : NULL, k, &ev);
        CHECK(used <= k);
        off += used;
        if (ev.type == TS_H2_EV_NONE) {
            CHECK(used == k);
            if (off == n) break;
            continue;
        }
        record(&ev);
    }
}

/* The built server bytes to the client, then cleared. */
static void send_server(size_t step)
{
    deliver(wbuf, wlen, step);
    wlen = 0;
}

/* The client's output, collected; out_fd >= 0 sends it to a socket instead (interop). */
static uint8_t obuf[1 << 21];
static size_t olen;
static int out_fd = -1;
static size_t sent_window_updates, sent_data_frames, sent_bytes;

static int send_all(int fd, const void* p, size_t n);

static void count_frames(const uint8_t* p, size_t n)
{
    size_t off = 0;

    if (n >= 24 && memcmp(p, "PRI * HTTP/2.0", 14) == 0) off = 24;
    while (off + 9 <= n) {
        size_t len = ((size_t)p[off] << 16) | ((size_t)p[off + 1] << 8) | p[off + 2];
        if (p[off + 3] == 0x8) sent_window_updates++;
        if (p[off + 3] == 0x0) sent_data_frames++;
        off += 9 + len;
    }
}

static int flush(void)
{
    for (;;) {
        size_t n;
        const uint8_t* p = ts_h2_output(&C, &n);

        if (!n) return 1;
        if (out_fd >= 0) {
            count_frames(p, n);
            sent_bytes += n;
            if (!send_all(out_fd, p, n)) return 0;
        } else {
            CHECK(olen + n <= sizeof(obuf));
            if (olen + n > sizeof(obuf)) return 0;
            memcpy(obuf + olen, p, n);
            olen += n;
        }
        ts_h2_output_done(&C, n);
    }
}

/* The client's frames in obuf. */
typedef struct {
    uint8_t        type, flags;
    uint32_t       stream;
    size_t         len;
    const uint8_t* p;
} ofr;

static ofr OF[8192];
static size_t nof;

static void split_out(void)
{
    size_t off = 0;

    nof = 0;
    while (off + 9 <= olen && nof < sizeof(OF) / sizeof(OF[0])) {
        ofr* f = &OF[nof++];
        f->len = ((size_t)obuf[off] << 16) | ((size_t)obuf[off + 1] << 8) | obuf[off + 2];
        f->type = obuf[off + 3];
        f->flags = obuf[off + 4];
        f->stream = get32(obuf + off + 5) & 0x7fffffff;
        f->p = obuf + off + 9;
        off += 9 + f->len;
    }
    CHECK(off == olen);
}

static const ofr* find_out(uint8_t type, uint32_t stream, size_t nth)
{
    size_t i;

    for (i = 0; i < nof; i++)
        if (OF[i].type == type && OF[i].stream == stream && !nth--) return &OF[i];
    return NULL;
}

static size_t count_out(uint8_t type)
{
    size_t i, n = 0;

    for (i = 0; i < nof; i++) n += OF[i].type == type;
    return n;
}

static void reset_log(void)
{
    size_t i;

    logn = 0;
    logb[0] = '\0';
    log_last_data = 0;
    for (i = 0; i < 64; i++) {
        got[i] = 0;
        seed_of[i] = -1;
        bad[i] = 0;
        data_events[i] = 0;
    }
}

/* A fresh client (its preface checked and dropped from obuf) that got Go's preface. */
static void setup(uint32_t window, int early)
{
    ts_h2_init(&C, window, early);
    reset_log();
    auto_consume = 1;
    olen = 0;
    wlen = 0;
    flush();
    CHECK(olen >= 24 && memcmp(obuf, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0);
    memmove(obuf, obuf + 24, olen - 24);
    olen -= 24;
    if (!early) {
        go_preface();
        send_server(0);
    }
    flush();
    olen = 0;
    reset_log();
}

static uint32_t post(const char* path, const char* body)
{
    ts_h2_req r;
    static const ts_h2_pair f[] = { { "content-type", "application/json" } };

    memset(&r, 0, sizeof(r));
    r.method = "POST";
    r.scheme = "https";
    r.authority = "controlplane.tailscale.com";
    r.path = path;
    r.fields = f;
    r.n_fields = 1;
    r.body = (const uint8_t*)body;
    r.body_len = body ? strlen(body) : 0;
    return ts_h2_request(&C, &r);
}

static int log_is(const char* want)
{
    if (strcmp(logb, want) == 0) return 1;
    fprintf(stderr, "    log:\n%s    want:\n%s", logb, want);
    return 0;
}

/* ------------------------------------------------------------------ the preface and settings */

TEST(h2_preface_and_settings)
{
    uint8_t want[128];
    size_t n;

    ts_h2_init(&C, 0, 0);
    olen = 0;
    flush();
    n = t_hex(want, sizeof(want),
              "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a"            /* the preface */
              "000012 04 00 00000000 0002 00000000 0004 0000ffff 0006 00004000"
              "000004 08 00 00000000 0006fff9");                          /* 7 x 65535 more */
    CHECK(olen == n);
    CHECK_MEM(obuf, want, n);

    /* a larger window: in SETTINGS, and the connection's grows with it */
    ts_h2_init(&C, 1 << 20, 0);
    olen = 0;
    flush();
    CHECK(olen == n);
    CHECK(get32(obuf + 24 + 9 + 8) == (1u << 20) && get32(obuf + 24 + 27 + 9) == 8u * (1 << 20) - 65535);
    /* clamped: too small, too large */
    ts_h2_init(&C, 1, 0);
    CHECK(C.stream_window == 1024);
    ts_h2_init(&C, 0xffffffffu, 0);
    CHECK(C.stream_window == TS_H2_MAX_WINDOW);

    /* Go's SETTINGS: acknowledged, unknown ones ignored, the windows and limits taken */
    setup(0, 0);
    CHECK(C.got_settings && C.peer_max_frame == (1u << 20) && C.peer_max_streams == 250);
    CHECK(C.peer_initial_window == (1u << 20) && C.conn_send_window == (1 << 20));
    ts_h2_init(&C, 0, 0);
    reset_log();
    olen = 0;
    flush();
    memmove(obuf, obuf + 24, olen - 24);            /* the preface is no frame */
    olen -= 24;
    go_preface();
    send_server(1);
    flush();
    split_out();
    CHECK(find_out(0x4, 0, 0) && find_out(0x4, 0, 0)->flags == 0);    /* ours */
    CHECK(find_out(0x4, 0, 1) && find_out(0x4, 0, 1)->flags == 1 && find_out(0x4, 0, 1)->len == 0);
    CHECK(count_out(0x4) == 2);
    CHECK(logn == 0);
}

TEST(h2_request_on_the_wire)
{
    ts_h2_req r;
    static const ts_h2_pair f[] = { { "content-type", "application/json" }, { "ts-lb", "nodekey:abc" } };
    uint8_t want[256];
    size_t n;
    uint32_t id;
    const ofr* h;
    const ofr* d;

    setup(0, 0);
    memset(&r, 0, sizeof(r));
    r.method = "POST";
    r.scheme = "https";
    r.authority = "controlplane.tailscale.com";
    r.path = "/machine/map";
    r.fields = f;
    r.n_fields = 2;
    r.body = (const uint8_t*)"{\"a\":1}";
    r.body_len = 7;
    id = ts_h2_request(&C, &r);
    CHECK(id == 1);
    flush();
    split_out();
    REQUIRE(nof == 2);
    h = find_out(0x1, 1, 0);
    REQUIRE(h != NULL);
    CHECK(h->flags == 0x4);                         /* END_HEADERS; the body follows */
    /* literals without indexing, names by static index, raw strings - in Go's order */
    n = t_hex(want, sizeof(want),
              "01 1a 636f6e74726f6c706c616e652e7461696c7363616c652e636f6d"  /* :authority */
              "02 04 504f5354"                                              /* :method POST */
              "04 0c 2f6d616368696e652f6d6170"                              /* :path */
              "06 05 6874747073"                                            /* :scheme https */
              "0f10 10 6170706c69636174696f6e2f6a736f6e"                    /* content-type (31) */
              "00 05 74732d6c62 0b 6e6f64656b65793a616263"                  /* ts-lb: no static name */
              "0f0d 01 37");                                                /* content-length (28): 7 */
    CHECK(h->len == n);
    CHECK_MEM(h->p, want, n);
    /* the same through our decoder */
    ts_hpack_init(&H, 4096);
    REQUIRE(ts_hpack_decode(&H, h->p, h->len, &L));
    CHECK(strcmp(list_text(&L), ":authority: controlplane.tailscale.com\n:method: POST\n:path: /machine/map\n"
                                ":scheme: https\ncontent-type: application/json\nts-lb: nodekey:abc\n"
                                "content-length: 7\n") == 0);
    CHECK(H.count == 0);                            /* nothing was put into the server's table */
    d = find_out(0x0, 1, 0);
    REQUIRE(d != NULL);
    CHECK(d->flags == 0x1 && d->len == 7 && memcmp(d->p, "{\"a\":1}", 7) == 0);

    /* a GET without a body: END_STREAM on HEADERS, no content-length; a POST without one: "0" */
    olen = 0;
    memset(&r, 0, sizeof(r));
    r.method = "GET";
    r.scheme = "http";
    r.authority = "h:8080";
    r.path = "/key?v=130";
    CHECK(ts_h2_request(&C, &r) == 3);
    r.method = "POST";
    CHECK(ts_h2_request(&C, &r) == 5);
    flush();
    split_out();
    REQUIRE(nof == 2);
    CHECK(OF[0].flags == 0x5 && OF[1].flags == 0x5);
    REQUIRE(ts_hpack_decode(&H, OF[0].p, OF[0].len, &L));
    CHECK(strcmp(list_text(&L), ":authority: h:8080\n:method: GET\n:path: /key?v=130\n:scheme: http\n") == 0);
    REQUIRE(ts_hpack_decode(&H, OF[1].p, OF[1].len, &L));
    CHECK(strstr(list_text(&L), "content-length: 0\n") != NULL);
}

TEST(h2_request_refusals)
{
    ts_h2_req r;
    ts_h2_pair f[1];
    static uint8_t big[TS_H2_SEND_MAX + 1];

    setup(0, 0);
    memset(&r, 0, sizeof(r));
    r.method = "POST";
    r.scheme = "https";
    r.authority = "c";
    r.path = "/p";
    r.fields = f;
    r.n_fields = 1;
#define REFUSED(n, v) do { f[0].name = (n); f[0].value = (v); CHECK(ts_h2_request(&C, &r) == 0); } while (0)
    REFUSED("Content-Type", "x");                   /* uppercase */
    REFUSED(":path", "/x");
    REFUSED("connection", "close");
    REFUSED("transfer-encoding", "chunked");
    REFUSED("upgrade", "x");
    REFUSED("keep-alive", "1");
    REFUSED("host", "x");
    REFUSED("content-length", "5");
    REFUSED("te", "gzip");
    REFUSED("x", "a\r\nb: c");
    REFUSED("x", "a\001");
    REFUSED("", "x");
    REFUSED("a b", "x");
#undef REFUSED
    f[0].name = "te";
    f[0].value = "trailers";
    CHECK(ts_h2_request(&C, &r) == 1);
    r.n_fields = 0;
    r.path = "nopath";
    CHECK(ts_h2_request(&C, &r) == 0);
    r.path = "/a b";
    CHECK(ts_h2_request(&C, &r) == 0);
    r.path = "/ok";
    r.method = "PO ST";
    CHECK(ts_h2_request(&C, &r) == 0);
    r.method = "POST";
    r.scheme = "1https";
    CHECK(ts_h2_request(&C, &r) == 0);
    r.scheme = "https";
    r.authority = "a/b";
    CHECK(ts_h2_request(&C, &r) == 0);
    r.authority = "";
    CHECK(ts_h2_request(&C, &r) == 0);
    r.authority = "[fd7a::1]:443";
    r.body = big;
    r.body_len = sizeof(big);
    CHECK(ts_h2_request(&C, &r) == 0);
    r.body_len = 10;
    r.body = NULL;
    CHECK(ts_h2_request(&C, &r) == 0);
    r.body = big;
    CHECK(ts_h2_request(&C, &r) == 3);
    CHECK(ts_h2_request(&C, NULL) == 0);
}

/* ------------------------------------------------------------------ responses */

TEST(h2_response_any_pieces)
{
    static const char* const kv[] = { "content-type", "application/json", "date", "Thu, 01 Oct 2026 00:00:00 GMT", NULL };
    static const size_t steps[] = { 0, 1, 2, 5, 9, 10, 100 };
    static uint8_t transcript[4096];
    size_t tlen, s;
    const char* want = "H1 200 content-type=application/json date=Thu, 01 Oct 2026 00:00:00 GMT\nD1\nE1\n";

    /* the transcript once */
    setup(0, 0);
    REQUIRE(post("/machine/map", "{}") == 1);
    resp_head(1, 0, "200", kv);
    frame(0x0, 0, 1, "hello ", 6);
    frame(0x0, 0, 1, "world", 5);
    frame(0x0, 1, 1, NULL, 0);
    memcpy(transcript, wbuf, wlen);
    tlen = wlen;

    for (s = 0; s < sizeof(steps) / sizeof(steps[0]); s++) {
        setup(0, 0);
        REQUIRE(post("/machine/map", "{}") == 1);
        deliver(transcript, tlen, steps[s]);
        CHECK(log_is(want));
        CHECK(got[1] == 11 && memcmp(store[1], "hello world", 11) == 0);
        CHECK(C.st[0].id == 0);                     /* the stream is gone */
    }
    /* field lookup in the event */
    setup(0, 0);
    REQUIRE(post("/x", NULL) == 1);
    resp_head(1, 1, "429", (const char* const[]){ "retry-after", "7", "content-type", "text/plain", NULL });
    {
        ts_h2_event ev;
        size_t used = ts_h2_input(&C, wbuf, wlen, &ev), len;
        const char* v;
        uint64_t sec;

        CHECK(ev.type == TS_H2_EV_HEADERS && ev.status == 429 && used == wlen);
        v = ts_h2_field_value(&ev, "retry-after", &len);
        CHECK(v && len == 1 && ts_http_retry_after(v, len, 0, &sec) && sec == 7);
        CHECK(ts_h2_field_value(&ev, "content-type", NULL) != NULL);
        CHECK(ts_h2_field_value(&ev, "Retry-After", NULL) == NULL);   /* HTTP/2 names are lowercase */
        CHECK(ts_h2_input(&C, NULL, 0, &ev) == 0 && ev.type == TS_H2_EV_END && ev.stream == 1);
        CHECK(ts_h2_field_value(&ev, "retry-after", NULL) == NULL);
        CHECK(ts_h2_input(&C, NULL, 0, &ev) == 0 && ev.type == TS_H2_EV_NONE);
        wlen = 0;
    }
}

TEST(h2_continuation_padding_priority)
{
    uint8_t p[600];
    size_t a, b;

    setup(0, 0);
    REQUIRE(post("/x", "b") == 1);
    K.n = 0;
    bk_int(0x80, 7, 8);
    bk_lit(1, 0, "x-one", "1", 1);
    bk_lit(0, 31, NULL, "text/plain", 0);
    bk_lit(2, 0, "x-secret", "s", 0);
    a = K.n / 3;
    b = 2 * K.n / 3;
    /* HEADERS with padding (3) and priority (5), the block cut in three */
    p[0] = 3;
    put32(p + 1, 0x80000003);
    p[5] = 42;
    memcpy(p + 6, K.b, a);
    memset(p + 6 + a, 0, 3);
    frame(0x1, 0x08 | 0x20, 1, p, 6 + a + 3);
    frame(0x9, 0, 1, K.b + a, b - a);
    frame(0x9, 0x4, 1, K.b + b, K.n - b);
    /* DATA padded, then an empty padded DATA with END_STREAM */
    p[0] = 4;
    memcpy(p + 1, "abc", 3);
    memset(p + 4, 0, 4);
    frame(0x0, 0x8, 1, p, 8);
    p[0] = 0;
    frame(0x0, 0x9, 1, p, 1);
    send_server(3);
    CHECK(log_is("H1 200 x-one=1 content-type=text/plain x-secret=s\nD1\nE1\n"));
    CHECK(got[1] == 3 && memcmp(store[1], "abc", 3) == 0);
}

TEST(h2_flow_control_receive)
{
    static uint8_t chunk[16384];
    size_t i;
    const ofr* f;

    /* the stream's 65535: four frames fill it, nothing more may come until the caller takes */
    setup(0, 0);
    auto_consume = 0;
    REQUIRE(post("/m", NULL) == 1);
    resp_head(1, 0, "200", NULL);
    for (i = 0; i < 3; i++) frame(0x0, 0, 1, chunk, 16384);
    frame(0x0, 0, 1, chunk, 65535 - 3 * 16384);
    send_server(1000);
    CHECK(got[1] == 65535 && !C.dead);
    flush();
    split_out();
    CHECK(count_out(0x8) == 0);                     /* not taken: nothing given back */
    /* taken: WINDOW_UPDATE for the stream and the connection */
    ts_h2_consume(&C, 1, 40000);
    ts_h2_consume(&C, 1, 1u << 30);                 /* more than held: only what is held */
    olen = 0;
    flush();
    split_out();
    f = find_out(0x8, 1, 0);
    CHECK(f && get32(f->p) == 65535);
    f = find_out(0x8, 0, 0);
    CHECK(f && get32(f->p) == 65535);
    /* one byte over the window kills the connection */
    setup(0, 0);
    auto_consume = 0;
    REQUIRE(post("/m", NULL) == 1);
    resp_head(1, 0, "200", NULL);
    for (i = 0; i < 4; i++) frame(0x0, 0, 1, chunk, 16384);
    send_server(0);
    CHECK(log_is("H1 200\nD1\nR1 3 local\nC 3 local\n"));
    CHECK(got[1] == 3 * 16384 && C.dead);
    flush();
    split_out();
    f = find_out(0x7, 0, 0);
    CHECK(f && get32(f->p) == 0 && get32(f->p + 4) == 3);   /* GOAWAY(0, FLOW_CONTROL_ERROR) */

    /* small credits wait for 4 KiB, as Go's inflow; padding is given back at once */
    setup(0, 0);
    auto_consume = 0;
    REQUIRE(post("/m", NULL) == 1);
    resp_head(1, 0, "200", NULL);
    frame(0x0, 0, 1, chunk, 100);
    send_server(0);
    ts_h2_consume(&C, 1, 100);
    flush();
    split_out();
    CHECK(count_out(0x8) == 0);
    chunk[0] = 200;
    frame(0x0, 0x8, 1, chunk, 300);                 /* 99 data + pad length + 200 padding */
    send_server(7);
    CHECK(got[1] == 199);
    olen = 0;
    flush();
    split_out();
    CHECK(count_out(0x8) == 0);                     /* 301 owed: not yet worth a frame */
    chunk[0] = 255;
    for (i = 0; i < 15; i++) frame(0x0, 0x8, 1, chunk, 256);  /* padding only: 15 x 256 more */
    send_server(5);
    CHECK(got[1] == 199);
    olen = 0;
    flush();
    split_out();
    f = find_out(0x8, 1, 0);
    CHECK(f && get32(f->p) == 100 + 201 + 15 * 256);  /* the 100 taken, the rest never handed out */
    f = find_out(0x8, 0, 0);
    CHECK(f && get32(f->p) == 100 + 201 + 15 * 256);
    CHECK(find_out(0x8, 1, 1) == NULL);
    chunk[0] = 0;

    /* what the caller still held when the stream ended goes back to the connection at once */
    setup(0, 0);
    auto_consume = 0;
    REQUIRE(post("/m", NULL) == 1);
    resp_head(1, 0, "200", NULL);
    frame(0x0, 0, 1, chunk, 5000);
    frame(0x0, 1, 1, NULL, 0);
    send_server(0);
    CHECK(log_is("H1 200\nD1\nE1\n"));
    olen = 0;
    flush();
    split_out();
    f = find_out(0x8, 0, 0);
    CHECK(f && get32(f->p) == 5000);
    CHECK(find_out(0x8, 1, 0) == NULL);             /* the stream is over: nothing for it */
    ts_h2_consume(&C, 1, 5000);                     /* taken late: already given */
    olen = 0;
    flush();
    CHECK(olen == 0);

    /* DATA of a dropped stream counts against the connection's window until it is given back:
     * not given back, 8 x 65535 runs out at the 32nd frame of 16384 */
    setup(0, 0);
    REQUIRE(post("/m", NULL) == 1);
    REQUIRE(post("/n", NULL) == 3);
    ts_h2_cancel(&C, 1);
    for (i = 0; i < 31; i++) frame(0x0, 0, 1, chunk, 16384);
    send_server(0);
    CHECK(logn == 0 && !C.dead);
    frame(0x0, 0, 1, chunk, 16384);
    send_server(0);
    CHECK(log_is("R3 3 local\nC 3 local\n"));
    /* given back in between: no limit */
    setup(0, 0);
    REQUIRE(post("/m", NULL) == 1);
    REQUIRE(post("/n", NULL) == 3);
    ts_h2_cancel(&C, 1);
    for (i = 0; i < 31; i++) frame(0x0, 0, 1, chunk, 16384);
    send_server(0);
    olen = 0;
    flush();
    split_out();
    f = find_out(0x8, 0, 0);
    CHECK(f && get32(f->p) == 31 * 16384);
    for (i = 0; i < 31; i++) frame(0x0, 0, 1, chunk, 16384);
    send_server(0);
    CHECK(logn == 0 && !C.dead);
}

TEST(h2_flow_control_send)
{
    static const uint32_t s10[] = { 4, 10 };
    static const uint32_t s20[] = { 4, 20 };
    const char* body = "0123456789abcdefghijklmnopqrstuvwxy";   /* 35 */
    const ofr* d;

    setup(0, 0);
    settings(s10, 1);
    send_server(0);
    REQUIRE(post("/m", body) == 1);
    olen = 0;
    flush();
    split_out();
    d = find_out(0x0, 1, 0);
    CHECK(d && d->len == 10 && d->flags == 0 && memcmp(d->p, body, 10) == 0);
    CHECK(find_out(0x0, 1, 1) == NULL);
    /* the stream's window grows: 10 more */
    window_update(1, 10);
    send_server(0);
    olen = 0;
    flush();
    split_out();
    d = find_out(0x0, 1, 0);
    CHECK(d && d->len == 10 && memcmp(d->p, body + 10, 10) == 0);
    /* SETTINGS raise the initial window from 10 to 20: the open stream gets the 10 too */
    settings(s20, 1);
    send_server(0);
    olen = 0;
    flush();
    split_out();
    d = find_out(0x0, 1, 0);
    CHECK(d && d->len == 10 && memcmp(d->p, body + 20, 10) == 0);
    /* the connection's window bounds it as well */
    C.conn_send_window = 2;
    window_update(1, 100);
    send_server(0);
    olen = 0;
    flush();
    split_out();
    d = find_out(0x0, 1, 0);
    CHECK(d && d->len == 2 && d->flags == 0);
    window_update(0, 100);
    send_server(0);
    olen = 0;
    flush();
    split_out();
    d = find_out(0x0, 1, 0);
    CHECK(d && d->len == 3 && d->flags == 1 && memcmp(d->p, body + 32, 3) == 0);
    CHECK(C.send_used == 0);                        /* the body left the arena */

    /* DATA frames stay within 16 KiB even where the server takes 1 MiB (Go's MAX_FRAME_SIZE) */
    {
        static uint8_t big[40000];
        ts_h2_req r;

        setup(0, 0);
        memset(&r, 0, sizeof(r));
        r.method = "POST";
        r.scheme = "https";
        r.authority = "c";
        r.path = "/big";
        r.body = big;
        r.body_len = sizeof(big);
        REQUIRE(ts_h2_request(&C, &r) == 1);
        olen = 0;
        flush();
        split_out();
        CHECK(count_out(0x0) == 3);
        d = find_out(0x0, 1, 0);
        CHECK(d && d->len == 16384 && d->flags == 0);
        d = find_out(0x0, 1, 2);
        CHECK(d && d->len == 40000 - 2 * 16384 && d->flags == 1);
    }

    /* a window that goes below zero by SETTINGS: nothing until it is above it again */
    {
        static const uint32_t s30[] = { 4, 30 };
        setup(0, 0);
        settings(s30, 1);
        send_server(0);
        REQUIRE(post("/m", body) == 1);
        olen = 0;
        flush();
        split_out();
        d = find_out(0x0, 1, 0);
        CHECK(d && d->len == 30 && count_out(0x0) == 1);
        settings(s10, 1);                           /* 0 + (10 - 30) = -20 */
        send_server(0);
        CHECK(C.st[0].send_window == -20);
        window_update(1, 20);
        send_server(0);
        olen = 0;
        flush();
        split_out();
        CHECK(count_out(0x0) == 0);
        window_update(1, 5);
        send_server(0);
        olen = 0;
        flush();
        split_out();
        d = find_out(0x0, 1, 0);
        CHECK(d && d->len == 5 && d->flags == 1 && memcmp(d->p, body + 30, 5) == 0);
    }
}

TEST(h2_ping_and_unknown)
{
    const ofr* f;
    uint8_t p[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

    setup(0, 0);
    frame(0x6, 0, 0, p, 8);
    frame(0x6, 1, 0, p, 8);                         /* an ACK: ignored */
    frame(0xfa, 0xff, 7, "whatever", 8);            /* an unknown type: skipped, even on a stream */
    frame(0x2, 0, 9, "\x00\x00\x00\x01\x10", 5);    /* PRIORITY: ignored */
    send_server(1);
    flush();
    split_out();
    REQUIRE(nof == 1);
    f = &OF[0];
    CHECK(f->type == 0x6 && f->flags == 1 && f->stream == 0 && f->len == 8 && memcmp(f->p, p, 8) == 0);
    CHECK(logn == 0 && !C.dead);
}

TEST(h2_rst_and_goaway)
{
    static const char* const kv[] = { "content-type", "text/plain", NULL };

    setup(0, 0);
    REQUIRE(post("/a", NULL) == 1);
    REQUIRE(post("/b", NULL) == 3);
    REQUIRE(post("/c", NULL) == 5);
    rst(3, 2);
    rst(5, 7);
    rst(5, 7);                                      /* a stream that is over: ignored */
    send_server(1);
    CHECK(log_is("R3 2\nR5 7 refused\n"));
    /* GOAWAY with last stream 1: 7 was never processed */
    reset_log();
    REQUIRE(post("/d", NULL) == 7);
    goaway_frame(1, 0, "going");
    send_server(0);
    CHECK(log_is("G 1 0 going\nR7 7 refused\n"));
    CHECK(!ts_h2_usable(&C) && post("/e", NULL) == 0);
    /* stream 1 still finishes */
    reset_log();
    resp_head(1, 0, "200", kv);
    frame(0x0, 1, 1, "ok", 2);
    goaway_frame(3, 0, NULL);                       /* higher than before: it stays 1 */
    send_server(2);
    CHECK(log_is("H1 200 content-type=text/plain\nD1\nE1\nG 1 0\n"));
    CHECK(C.goaway_last == 1);
    /* the end of the transport */
    reset_log();
    ts_h2_eof(&C);
    deliver(NULL, 0, 0);
    CHECK(log_is("C 256\n"));
    ts_h2_eof(&C);                                  /* twice: nothing more */
    deliver((const uint8_t*)"junk", 4, 0);
    CHECK(log_is("C 256\n"));

    /* EOF with streams open */
    setup(0, 0);
    REQUIRE(post("/a", NULL) == 1);
    REQUIRE(post("/b", NULL) == 3);
    ts_h2_eof(&C);
    deliver(NULL, 0, 0);
    CHECK(log_is("R1 256\nR3 256\nC 256\n"));
    CHECK(post("/c", NULL) == 0);
}

TEST(h2_parallel_streams)
{
    setup(0, 0);
    REQUIRE(post("/a", NULL) == 1);
    REQUIRE(post("/b", NULL) == 3);
    resp_head(3, 0, "200", NULL);
    resp_head(1, 0, "404", NULL);
    frame(0x0, 0, 1, "a1", 2);
    frame(0x0, 0, 3, "b1", 2);
    frame(0x0, 0, 1, "a2", 2);
    frame(0x0, 1, 3, "b2", 2);
    frame(0x0, 1, 1, "a3", 2);
    send_server(5);
    CHECK(log_is("H3 200\nH1 404\nD1\nD3\nD1\nD3\nE3\nD1\nE1\n"));
    CHECK(got[1] == 6 && memcmp(store[1], "a1a2a3", 6) == 0 && got[3] == 4 && memcmp(store[3], "b1b2", 4) == 0);
    /* the slots are free again: TS_H2_MAX_STREAMS more */
    {
        int i;
        for (i = 0; i < TS_H2_MAX_STREAMS; i++) CHECK(post("/n", NULL) == 5u + 2 * (unsigned)i);
        CHECK(post("/n", NULL) == 0);
    }
    /* the server's own limit */
    {
        static const uint32_t one[] = { 3, 1 };
        setup(0, 0);
        settings(one, 1);
        send_server(0);
        CHECK(post("/a", NULL) == 1);
        CHECK(post("/b", NULL) == 0);
        rst(1, 8);
        send_server(0);
        CHECK(post("/b", NULL) == 3);
    }
}

TEST(h2_early_noise)
{
    static const char json[] = "{\"NodeKeyChallenge\":\"chalpub:00ff\"}";
    uint8_t hdr[9] = { 0xff, 0xff, 0xff, 'T', 'S' };
    size_t s;

    for (s = 0; s < 4; s++) {
        setup(0, 1);
        put32(hdr + 5, (uint32_t)strlen(json));
        raw(hdr, 9);
        raw(json, strlen(json));
        go_preface();
        send_server(s == 0 ? 0 : s == 1 ? 1 : s == 2 ? 4 : 10);
        CHECK(log_is("Y {\"NodeKeyChallenge\":\"chalpub:00ff\"}\n"));
        CHECK(C.got_settings && !C.dead);
    }
    /* without it, SETTINGS straight away */
    setup(0, 1);
    go_preface();
    send_server(2);
    CHECK(logn == 0 && C.got_settings);
    /* an empty one: the caller's JSON parser decides */
    setup(0, 1);
    put32(hdr + 5, 0);
    raw(hdr, 9);
    go_preface();
    send_server(0);
    CHECK(log_is("Y \n") && C.got_settings);
    /* longer than we take */
    setup(0, 1);
    put32(hdr + 5, TS_H2_EARLY_MAX + 1);
    raw(hdr, 9);
    send_server(0);
    CHECK(log_is("C 1 local\n"));
    /* not expected: the magic reads as a frame of 16 MiB */
    setup(0, 0);
    put32(hdr + 5, 2);
    raw(hdr, 9);
    send_server(0);
    CHECK(log_is("C 6 local\n"));
}

/* Feeds the built bytes to a fresh client with one request open and returns the log. */
static void expect_conn_error(const char* what, uint32_t code)
{
    char want[64];

    snprintf(want, sizeof(want), "R1 %u local\nC %u local\n", (unsigned)code, (unsigned)code);
    send_server(0);
    if (!log_is(want)) fprintf(stderr, "    (%s)\n", what);
    CHECK(strcmp(logb, want) == 0);
}

TEST(h2_connection_errors)
{
    uint8_t p[32];

#define CASE(what, code, ...) do { setup(0, 0); REQUIRE(post("/x", NULL) == 1); __VA_ARGS__; expect_conn_error(what, code); } while (0)
    memset(p, 0, sizeof(p));
    CASE("frame over 16384", 6, { uint8_t h[9] = { 0x00, 0x40, 0x01, 0, 0, 0, 0, 0, 1 }; raw(h, 9); });
    CASE("DATA on stream 0", 1, frame(0x0, 0, 0, "x", 1));
    CASE("DATA on an idle stream", 1, frame(0x0, 0, 3, "x", 1));
    CASE("DATA on an even stream", 1, frame(0x0, 0, 2, "x", 1));
    CASE("HEADERS on an idle stream", 1, resp_head(5, 0, "200", NULL));
    CASE("HEADERS on stream 0", 1, frame(0x1, 4, 0, "\x88", 1));
    CASE("PUSH_PROMISE", 1, frame(0x5, 4, 1, "\x00\x00\x00\x02\x88", 5));
    CASE("CONTINUATION alone", 1, frame(0x9, 4, 1, "\x88", 1));
    CASE("a frame inside a header block", 1, { frame(0x1, 0, 1, "\x88", 1); frame(0x0, 0, 1, "x", 1); });
    CASE("CONTINUATION of another stream", 1, { frame(0x1, 0, 1, "\x88", 1); frame(0x9, 4, 3, "", 0); });
    CASE("PING on a stream", 1, frame(0x6, 0, 1, p, 8));
    CASE("PING of 7", 6, frame(0x6, 0, 0, p, 7));
    CASE("SETTINGS on a stream", 1, frame(0x4, 0, 1, NULL, 0));
    CASE("SETTINGS of 5", 6, frame(0x4, 0, 0, p, 5));
    CASE("SETTINGS ACK with a payload", 6, frame(0x4, 1, 0, p, 6));
    CASE("ENABLE_PUSH 2", 1, { static const uint32_t s[] = { 2, 2 }; settings(s, 1); });
    CASE("INITIAL_WINDOW_SIZE 2^31", 3, { static const uint32_t s[] = { 4, 0x80000000u }; settings(s, 1); });
    CASE("MAX_FRAME_SIZE 100", 1, { static const uint32_t s[] = { 5, 100 }; settings(s, 1); });
    CASE("MAX_FRAME_SIZE 2^24", 1, { static const uint32_t s[] = { 5, 1u << 24 }; settings(s, 1); });
    CASE("WINDOW_UPDATE 0 on the connection", 1, window_update(0, 0));
    CASE("WINDOW_UPDATE over 2^31-1", 3, window_update(0, 0x7fffffff));
    CASE("WINDOW_UPDATE of 3", 6, frame(0x8, 0, 0, p, 3));
    CASE("WINDOW_UPDATE on an idle stream", 1, window_update(9, 1));
    CASE("RST_STREAM on stream 0", 1, rst(0, 0));
    CASE("RST_STREAM on an idle stream", 1, rst(11, 0));
    CASE("RST_STREAM of 5", 6, frame(0x3, 0, 1, p, 5));
    CASE("GOAWAY on a stream", 1, frame(0x7, 0, 1, p, 8));
    CASE("GOAWAY of 7", 6, frame(0x7, 0, 0, p, 7));
    CASE("PRIORITY on stream 0", 1, frame(0x2, 0, 0, p, 5));
    CASE("PRIORITY of 4", 6, frame(0x2, 0, 1, p, 4));
    CASE("DATA padding over the payload", 1, frame(0x0, 0x8, 1, "\x05xyz", 4));
    CASE("PADDED DATA of 0", 6, frame(0x0, 0x8, 1, NULL, 0));
    CASE("HEADERS padding over the payload", 1, frame(0x1, 0x8 | 0x4, 1, "\x02\x88", 2));
    CASE("HEADERS priority cut short", 6, frame(0x1, 0x20 | 0x4, 1, "\x00\x00", 2));
    CASE("a bad HPACK block", 9, frame(0x1, 0x4, 1, "\x80", 1));
    CASE("a header block over 16 KiB", 1, {
        static uint8_t big[16384];
        frame(0x1, 0, 1, big, sizeof(big));
        frame(0x9, 0x4, 1, big, 1);
    });
#undef CASE
    /* the first frame must be SETTINGS */
    ts_h2_init(&C, 0, 0);
    reset_log();
    wlen = 0;
    window_update(0, 1);
    send_server(0);
    CHECK(log_is("C 1 local\n"));
    ts_h2_init(&C, 0, 0);
    reset_log();
    frame(0x4, 1, 0, NULL, 0);                      /* nor a SETTINGS ACK */
    send_server(0);
    CHECK(log_is("C 1 local\n"));
    /* after CLOSED: input taken and ignored, nothing more */
    reset_log();
    frame(0x6, 0, 0, p, 8);
    send_server(0);
    CHECK(logn == 0);
}

TEST(h2_malformed_responses)
{
    static const char* const upper[] = { "Content-Type", "x", NULL };
    const ofr* f;

#define STREAM_RESET(what, want, ...) do {                                    \
        setup(0, 0); REQUIRE(post("/x", NULL) == 1); REQUIRE(post("/y", NULL) == 3); \
        __VA_ARGS__; send_server(0);                                          \
        if (!log_is(want)) fprintf(stderr, "    (%s)\n", what);               \
        CHECK(strcmp(logb, want) == 0);                                       \
        CHECK(!C.dead && ts_h2_usable(&C));                                   \
    } while (0)
    STREAM_RESET("DATA first", "R1 1 local\n", frame(0x0, 0, 1, "x", 1));
    STREAM_RESET("no :status", "R1 1 local\n", { K.n = 0; bk_lit(0, 31, NULL, "x", 0); frame(0x1, 4, 1, K.b, K.n); });
    STREAM_RESET("an uppercase name", "R1 1 local\n", resp_head(1, 0, "200", upper));
    STREAM_RESET(":status after a field", "R1 1 local\n", { K.n = 0; bk_lit(0, 31, NULL, "x", 0); bk_int(0x80, 7, 8); frame(0x1, 4, 1, K.b, K.n); });
    STREAM_RESET("two :status", "R1 1 local\n", { K.n = 0; bk_int(0x80, 7, 8); bk_int(0x80, 7, 9); frame(0x1, 4, 1, K.b, K.n); });
    STREAM_RESET("a request pseudo-field", "R1 1 local\n", { K.n = 0; bk_int(0x80, 7, 8); bk_int(0x80, 7, 4); frame(0x1, 4, 1, K.b, K.n); });
    STREAM_RESET("status 20", "R1 1 local\n", resp_head(1, 0, "20", NULL));
    STREAM_RESET("status 600", "R1 1 local\n", resp_head(1, 0, "600", NULL));
    STREAM_RESET("status 1x0", "R1 1 local\n", resp_head(1, 0, "1x0", NULL));
    STREAM_RESET("status 101", "R1 1 local\n", resp_head(1, 0, "101", NULL));
    STREAM_RESET("1xx ending the stream", "R1 1 local\n", resp_head(1, 1, "103", NULL));
    STREAM_RESET("a value with a CR", "R1 1 local\n", { K.n = 0; bk_int(0x80, 7, 8); bk_lit(0, 0, "x", "a\rb", 0); frame(0x1, 4, 1, K.b, K.n); });
    STREAM_RESET("a value with a NUL", "R1 1 local\n", { K.n = 0; bk_int(0x80, 7, 8); bk_int(0, 4, 0); bk_str("x", 0); bk_int(0, 7, 3); K.b[K.n++] = 'a'; K.b[K.n++] = 0; K.b[K.n++] = 'b'; frame(0x1, 4, 1, K.b, K.n); });
    STREAM_RESET("trailers without END_STREAM", "H1 200\nR1 1 local\n", { resp_head(1, 0, "200", NULL); K.n = 0; bk_lit(0, 0, "t", "1", 0); frame(0x1, 4, 1, K.b, K.n); });
    STREAM_RESET("trailers with :status", "H1 200\nR1 1 local\n", { resp_head(1, 0, "200", NULL); resp_head(1, 1, "200", NULL); });
    STREAM_RESET("more than content-length", "H1 200 content-length=3\nR1 1 local\n",
                 { resp_head(1, 0, "200", (const char* const[]){ "content-length", "3", NULL }); frame(0x0, 0, 1, "abcd", 4); });
    STREAM_RESET("less than content-length", "H1 200 content-length=3\nD1\nR1 1 local\n",
                 { resp_head(1, 0, "200", (const char* const[]){ "content-length", "3", NULL }); frame(0x0, 1, 1, "ab", 2); });
    STREAM_RESET("content in a 204", "H1 204\nR1 1 local\n", { resp_head(1, 0, "204", NULL); frame(0x0, 1, 1, "x", 1); });
    STREAM_RESET("WINDOW_UPDATE of 0 on a stream", "R1 1 local\n", window_update(1, 0));
    STREAM_RESET("a stream window over 2^31-1", "R1 3 local\n", window_update(1, 0x7fffffff));
#undef STREAM_RESET
    /* the RST_STREAM went out with the code, the other stream goes on */
    flush();
    split_out();
    f = find_out(0x3, 1, 0);
    CHECK(f && get32(f->p) == 3);
    resp_head(3, 1, "200", NULL);
    send_server(0);
    CHECK(strstr(logb, "H3 200\nE3\n") != NULL);

    /* what is fine: interim heads before the real one, trailers, content-length met, empty DATA */
    setup(0, 0);
    REQUIRE(post("/x", NULL) == 1);
    resp_head(1, 0, "100", NULL);
    resp_head(1, 0, "103", (const char* const[]){ "link", "</a>", NULL });
    resp_head(1, 0, "200", (const char* const[]){ "content-length", "5", NULL });
    frame(0x0, 0, 1, "ab", 2);
    frame(0x0, 0, 1, NULL, 0);
    frame(0x0, 0, 1, "cde", 3);
    K.n = 0;
    bk_lit(0, 0, "grpc-status", "0", 0);
    frame(0x1, 0x5, 1, K.b, K.n);
    send_server(1);
    CHECK(log_is("H1 200 content-length=5\nD1\nE1\n"));
    /* six interim heads are too many, as in Go */
    setup(0, 0);
    REQUIRE(post("/x", NULL) == 1);
    {
        int i;
        for (i = 0; i < 6; i++) resp_head(1, 0, "100", NULL);
    }
    send_server(0);
    CHECK(log_is("R1 1 local\n"));
    /* a head over our limits: that stream is reset (CANCEL), the table stays in step */
    setup(0, 0);
    REQUIRE(post("/x", NULL) == 1);
    REQUIRE(post("/y", NULL) == 3);
    K.n = 0;
    bk_int(0x80, 7, 8);
    {
        int i;
        char name[16];
        for (i = 0; i < TS_H2_FIELDS_MAX; i++) {
            snprintf(name, sizeof(name), "x-%d", i);
            bk_lit(1, 0, name, "v", 1);             /* into the table: the next head refers to them */
        }
    }
    frame(0x1, 0x4, 1, K.b, K.n);
    K.n = 0;
    bk_int(0x80, 7, 8);
    bk_int(0x80, 7, 62);                            /* the newest: x-63: v */
    frame(0x1, 0x5, 3, K.b, K.n);
    send_server(0);
    CHECK(log_is("R1 8 local\nH3 200 x-63=v\nE3\n"));
}

TEST(h2_early_response_and_cancel)
{
    static const uint32_t s0[] = { 4, 0 };
    const ofr* f;

    /* the whole response before our body (window 0): END, then RST_STREAM(CANCEL), body dropped */
    setup(0, 0);
    settings(s0, 1);
    send_server(0);
    REQUIRE(post("/x", "a body that cannot go") == 1);
    CHECK(C.send_used == 21);
    resp_head(1, 1, "403", NULL);
    send_server(0);
    CHECK(log_is("H1 403\nE1\n"));
    CHECK(C.send_used == 0);
    olen = 0;
    flush();
    split_out();
    f = find_out(0x3, 1, 0);
    CHECK(f && get32(f->p) == 8);
    CHECK(count_out(0x0) == 0);

    /* cancel: RST_STREAM(CANCEL), its queued events dropped, its later DATA dropped with the
     * connection's window given back */
    setup(0, 0);
    REQUIRE(post("/x", NULL) == 1);
    REQUIRE(post("/y", NULL) == 3);
    resp_head(1, 0, "200", NULL);
    resp_head(3, 0, "200", NULL);
    {
        ts_h2_event ev;
        size_t used = ts_h2_input(&C, wbuf, wlen, &ev);
        CHECK(ev.type == TS_H2_EV_HEADERS && ev.stream == 1);
        ts_h2_cancel(&C, 1);
        deliver(wbuf + used, wlen - used, 0);
        wlen = 0;
    }
    CHECK(log_is("H3 200\n"));
    frame(0x0, 0, 1, "lost", 4);
    {
        static uint8_t zeros[5000];
        frame(0x0, 0, 1, zeros, sizeof(zeros));
    }
    send_server(0);
    CHECK(log_is("H3 200\n") && got[1] == 0);
    olen = 0;
    flush();
    split_out();
    f = find_out(0x3, 1, 0);
    CHECK(f && get32(f->p) == 8);
    f = find_out(0x8, 0, 0);
    CHECK(f && get32(f->p) == 5004);
    ts_h2_cancel(&C, 1);                            /* again: nothing */
    ts_h2_cancel(&C, 99);
    olen = 0;
    flush();
    CHECK(olen == 0);

    /* events already waiting for a stream go with it: HEADERS and END came in one frame */
    setup(0, 0);
    REQUIRE(post("/x", NULL) == 1);
    REQUIRE(post("/y", NULL) == 3);
    resp_head(1, 1, "200", NULL);
    resp_head(3, 1, "200", NULL);
    {
        ts_h2_event ev;
        size_t used = ts_h2_input(&C, wbuf, wlen, &ev);
        CHECK(ev.type == TS_H2_EV_HEADERS && ev.stream == 1);
        ts_h2_cancel(&C, 1);                        /* over already: no RST_STREAM, END dropped */
        deliver(wbuf + used, wlen - used, 0);
        wlen = 0;
    }
    CHECK(log_is("H3 200\nE3\n"));
    olen = 0;
    flush();
    split_out();
    CHECK(count_out(0x3) == 0);
}

TEST(h2_table_size_update_owed)
{
    static const uint32_t t0[] = { 1, 0 };
    const ofr* h;

    setup(0, 0);
    settings(t0, 1);
    send_server(0);
    REQUIRE(post("/a", NULL) == 1);
    REQUIRE(post("/b", NULL) == 3);
    flush();
    split_out();
    h = find_out(0x1, 1, 0);
    CHECK(h && h->p[0] == 0x20);                    /* size update to 0, once */
    h = find_out(0x1, 3, 0);
    CHECK(h && h->p[0] == 0x01);
}

TEST(h2_flood_is_stopped)
{
    uint8_t p[8] = { 0 };
    int i;

    setup(0, 0);
    for (i = 0; i < 3000; i++) frame(0x6, 0, 0, p, 8);     /* PINGs and no output taken */
    send_server(0);
    CHECK(C.dead && strstr(logb, "C 11 local\n") != NULL);
}

/* ------------------------------------------------------------------ fuzzing */

static void mutate(uint8_t* buf, size_t* len, size_t cap)
{
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
    case 4:
        if (n > 2) {
            size_t from = rnd() % n, cnt = 1 + rnd() % (n - from);
            memmove(buf + from, buf + from + cnt, n - from - cnt);
            *len = n - cnt;
        }
        break;
    default:
        if (n > 2) {
            size_t from = rnd() % n, cnt = 1 + rnd() % (n - from);
            if (n + cnt <= cap) {
                memmove(buf + from + cnt, buf + from, n - from);
                *len = n + cnt;
            }
        }
        break;
    }
}

/* Events must make sense whatever came in: per stream a head before DATA, nothing after its end. */
static int fz_state[64];                            /* 0 open, 1 head seen, 2 over */
static int fz_closed;

static void fz_feed(const uint8_t* p, size_t n)
{
    size_t off = 0;

    for (;;) {
        ts_h2_event ev;
        size_t k = 1 + rnd() % 64, used;
        uint32_t s;

        if (k > n - off) k = n - off;
        used = ts_h2_input(&C, p + off, k, &ev);
        off += used;
        if (ev.type == TS_H2_EV_NONE) {
            CHECK(used == k);
            if (off == n) break;
            continue;
        }
        CHECK(!fz_closed);
        s = ev.stream;
        switch (ev.type) {
        case TS_H2_EV_HEADERS:
            CHECK(s < 64 && (s & 1) && fz_state[s] == 0 && ev.status >= 200 && ev.status <= 599);
            if (s < 64) fz_state[s] = 1;
            break;
        case TS_H2_EV_DATA:
            CHECK(s < 64 && fz_state[s] == 1 && ev.len > 0);
            if (rnd() % 2) ts_h2_consume(&C, s, ev.len);
            break;
        case TS_H2_EV_END:
            CHECK(s < 64 && fz_state[s] == 1);
            if (s < 64) fz_state[s] = 2;
            break;
        case TS_H2_EV_RESET:
            CHECK(s < 64 && fz_state[s] != 2);
            if (s < 64) fz_state[s] = 2;
            break;
        case TS_H2_EV_CLOSED:
            fz_closed = 1;
            break;
        default:
            break;
        }
        if (rnd() % 16 == 0) flush();
    }
}

/* The client's output must always be well-formed frames of the kinds a client sends. */
static void fz_check_output(void)
{
    size_t i;

    split_out();
    for (i = 0; i < nof; i++) {
        uint8_t t = OF[i].type;
        CHECK(t == 0x0 || t == 0x1 || t == 0x3 || t == 0x4 || t == 0x6 || t == 0x7 || t == 0x8);
        CHECK(OF[i].len <= TS_H2_FRAME_MAX);
        if (t == 0x8) CHECK(OF[i].len == 4 && (get32(OF[i].p) & 0x7fffffff) != 0);
        if (t == 0x6) CHECK(OF[i].flags == 1 && OF[i].len == 8);
        if (t == 0x3) CHECK(OF[i].len == 4 && OF[i].stream != 0);
    }
    olen = 0;
}

static void fz_start(int early)
{
    size_t i;

    setup(0, early);
    for (i = 0; i < 64; i++) fz_state[i] = 0;
    fz_closed = 0;
    post("/a", "x");
    post("/b", NULL);
    post("/c", "yy");
    flush();
    olen = 0;
}

TEST(fuzz_frames)
{
    static uint8_t seed[1 << 16], buf[1 << 16];
    size_t seedlen, iter;
    static const char* const kv[] = { "content-type", "application/json", "x-a", "1", NULL };

    /* a real-looking transcript: heads (Huffman, the dynamic table), DATA, padding, CONTINUATION,
     * a PING, WINDOW_UPDATEs, an RST, a trailer */
    setup(0, 0);
    wlen = 0;
    resp_head(1, 0, "200", kv);
    resp_head(3, 0, "404", kv);
    frame(0x0, 0, 1, "hello", 5);
    frame(0x6, 0, 0, "12345678", 8);
    frame(0x0, 0x8, 3, "\x02xy\0\0", 5);
    window_update(0, 1000);
    window_update(1, 50);
    K.n = 0;
    bk_lit(0, 0, "t", "1", 0);
    frame(0x1, 0x1, 1, K.b, K.n / 2);
    frame(0x9, 0x4, 1, K.b + K.n / 2, K.n - K.n / 2);
    rst(3, 8);
    resp_head(5, 1, "204", NULL);
    goaway_frame(5, 0, "bye");
    memcpy(seed, wbuf, wlen);
    seedlen = wlen;
    wlen = 0;

    for (iter = 0; iter < 6000; iter++) {
        size_t len = seedlen;
        uint8_t* p;
        int m = 1 + (int)(rnd() % 4);

        memcpy(buf, seed, len);
        while (m--) mutate(buf, &len, sizeof(buf));
        p = (uint8_t*)malloc(len ? len : 1);
        memcpy(p, buf, len);
        fz_start(0);
        fz_feed(p, len);
        if (rnd() % 2) {
            ts_h2_eof(&C);
            fz_feed(p, 0);
        }
        flush();
        fz_check_output();
        free(p);
    }
    /* frames from nothing: random types, flags, streams and lengths */
    for (iter = 0; iter < 6000; iter++) {
        int nf = 1 + (int)(rnd() % 12), f;
        uint8_t* p;

        fz_start((int)(rnd() % 2));
        wlen = 0;
        if (C.early && rnd() % 2) {
            uint8_t h[9] = { 0xff, 0xff, 0xff, 'T', 'S', 0, 0, 0, 3 };
            raw(h, 9);
            raw("{x}", 3);
        }
        go_preface();
        for (f = 0; f < nf; f++) {
            static const uint32_t ids[] = { 0, 1, 3, 5, 2, 7, 0x7fffffff };
            uint8_t pay[300];
            size_t len = rnd() % 4 ? rnd() % 40 : rnd() % sizeof(pay), i;
            uint8_t type = (uint8_t)(rnd() % 3 ? rnd() % 10 : rnd());
            for (i = 0; i < len; i++) pay[i] = (uint8_t)rnd();
            if (type == 0x1 && rnd() % 2) {
                resp_head(ids[rnd() % 4], (uint8_t)(rnd() % 2), rnd() % 2 ? "200" : "500", kv);
                continue;
            }
            frame(type, (uint8_t)rnd(), ids[rnd() % 7], pay, len);
        }
        p = (uint8_t*)malloc(wlen ? wlen : 1);
        memcpy(p, wbuf, wlen);
        fz_feed(p, wlen);
        flush();
        fz_check_output();
        free(p);
        wlen = 0;
    }
}

TEST(fuzz_hpack)
{
    static uint8_t buf[8192];
    static ts_hpack H2;
    static ts_hpack_list L2;
    size_t iter;

    for (iter = 0; iter < 30000; iter++) {
        const kat_seq* s = &kat_hpack[rnd() % (sizeof(kat_hpack) / sizeof(kat_hpack[0]))];
        const kat_block* b = &s->blocks[rnd() % s->n];
        size_t len = b->len < sizeof(buf) ? b->len : sizeof(buf), i;
        int m = 1 + (int)(rnd() % 3), r1, r2;
        uint8_t* p;

        if (rnd() % 4 == 0) {
            len = rnd() % 200;
            for (i = 0; i < len; i++) buf[i] = (uint8_t)rnd();
        } else {
            memcpy(buf, b->blk, len);
            while (m--) mutate(buf, &len, sizeof(buf));
        }
        p = (uint8_t*)malloc(len ? len : 1);
        memcpy(p, buf, len);
        if (iter % 50 == 0) ts_hpack_init(&H, (uint32_t)(rnd() % 2 ? 4096 : rnd() % 4097));
        H2 = H;                                     /* the same state twice: the same outcome */
        r1 = ts_hpack_decode(&H, p, len, &L);
        r2 = ts_hpack_decode(&H2, p, len, &L2);
        CHECK(r1 == r2 && H.size == H2.size && H.count == H2.count);
        if (r1) {
            uint64_t sum = 0;
            const uint8_t *nm, *vl;
            size_t nl, vlen;
            CHECK(L.n == L2.n && L.overflow == L2.overflow && L.n <= TS_H2_FIELDS_MAX);
            for (i = 0; i < L.n; i++) {
                CHECK(L.fields[i].name_len == L2.fields[i].name_len && L.fields[i].value_len == L2.fields[i].value_len);
                CHECK(L.fields[i].name[L.fields[i].name_len] == '\0');
            }
            for (i = 0; ts_hpack_entry(&H, i, &nm, &nl, &vl, &vlen); i++) sum += nl + vlen + 32;
            CHECK(sum == H.size && i == H.count && H.size <= H.max_size && H.max_size <= H.limit);
        } else {
            ts_hpack_init(&H, 4096);                /* an error ends the connection: start over */
        }
        free(p);
    }
}

/* ------------------------------------------------------------------ interop (Go's server) */

static int send_all(int fd, const void* p, size_t n)
{
    const uint8_t* b = (const uint8_t*)p;

    while (n) {
        ssize_t k = send(fd, b, n, 0);
        if (k <= 0) return 0;
        b += k;
        n -= (size_t)k;
    }
    return 1;
}

static int tcp_connect(const char* hostport)
{
    char host[64];
    const char* colon = hostport ? strrchr(hostport, ':') : NULL;
    struct sockaddr_in sa;
    struct timeval tv;
    int fd;

    if (!colon || (size_t)(colon - hostport) >= sizeof(host)) return -1;
    memcpy(host, hostport, (size_t)(colon - hostport));
    host[colon - hostport] = '\0';
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)atoi(colon + 1));
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) return -1;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* One read from the server, its events recorded, our answer sent. 0 once the server is gone. */
static int pump(void)
{
    static uint8_t buf[20000];
    ssize_t k = recv(out_fd, buf, (size_t)(1 + rnd() % sizeof(buf)), 0);

    if (k <= 0) {
        ts_h2_eof(&C);
        deliver(NULL, 0, 0);
        return 0;
    }
    deliver(buf, (size_t)k, 0);
    flush();
    return 1;
}

static int h2_open(const char* where)
{
    out_fd = tcp_connect(where);
    if (out_fd < 0) return 0;
    ts_h2_init(&C, 0, 0);
    reset_log();
    auto_consume = 1;
    sent_window_updates = sent_data_frames = sent_bytes = 0;
    return flush();
}

static void h2_close(void)
{
    if (out_fd >= 0) close(out_fd);
    out_fd = -1;
}

/* Pumps until the log has `text` (or the server is gone). */
static int pump_until(const char* text)
{
    while (!strstr(logb, text))
        if (!pump()) return strstr(logb, text) != NULL;
    return 1;
}

static uint32_t req(const char* method, const char* path, const uint8_t* body, size_t len)
{
    static const ts_h2_pair f[] = { { "content-type", "application/json" }, { "ts-lb", "nodekey:0123" } };
    ts_h2_req r;
    uint32_t id;

    memset(&r, 0, sizeof(r));
    r.method = method;
    r.scheme = "https";
    r.authority = "controlplane.tailscale.com";
    r.path = path;
    r.fields = f;
    r.n_fields = body ? 2 : 0;
    r.body = body;
    r.body_len = len;
    id = ts_h2_request(&C, &r);
    flush();
    return id;
}

static const char* interop, *interop_idle, *interop_shutdown;

TEST(interop_post_echo)
{
    static uint8_t body[60000];
    char want[64];
    size_t i;
    uint32_t id;

    REQUIRE(h2_open(interop));
    for (i = 0; i < 3000; i++) body[i] = (uint8_t)"{\"Version\":130,\"Keys\":[\"a\",\"b\"]}"[i % 33];
    id = req("POST", "/echo", body, 3000);
    REQUIRE(id == 1);
    CHECK(pump_until("E1\n"));
    CHECK(strstr(logb, "H1 200 ") != NULL);
    CHECK(strstr(logb, "x-got-content-type=application/json") != NULL);
    CHECK(strstr(logb, "x-got-content-length=3000") != NULL);
    CHECK(strstr(logb, "x-got-method=POST") != NULL);
    CHECK(strstr(logb, "x-got-host=controlplane.tailscale.com") != NULL);
    CHECK(strstr(logb, "x-got-path=/echo") != NULL);
    CHECK(strstr(logb, "x-got-lb=nodekey:0123") != NULL);
    CHECK(got[1] == 3000 && memcmp(store[1], body, 3000) == 0);

    /* a body of several DATA frames, beyond the first 16 KiB */
    for (i = 0; i < sizeof(body); i++) body[i] = pat(77, i);
    id = req("POST", "/echo", body, sizeof(body));
    REQUIRE(id == 3);
    seed_of[3] = 77;
    snprintf(want, sizeof(want), "E%u\n", (unsigned)id);
    CHECK(pump_until(want));
    CHECK(got[3] == sizeof(body) && !bad[3]);
    CHECK(strstr(logb, "x-got-content-length=60000") != NULL);
    CHECK(sent_data_frames >= 5);
    h2_close();
}

TEST(interop_long_stream)
{
    uint32_t id;

    REQUIRE(h2_open(interop));
    id = req("GET", "/stream?n=1572864&seed=11", NULL, 0);
    REQUIRE(id == 1);
    seed_of[1] = 11;
    CHECK(pump_until("E1\n"));
    CHECK(got[1] == 1572864 && !bad[1]);
    /* 1.5 MiB through a 64 KiB window: the window was given back many times */
    CHECK(sent_window_updates >= 40);
    CHECK(!C.dead);
    h2_close();
}

TEST(interop_parallel_streams)
{
    uint32_t a, b;
    int interleaved;

    REQUIRE(h2_open(interop));
    a = req("GET", "/stream?n=700000&seed=21", NULL, 0);
    b = req("GET", "/stream?n=900000&seed=22", NULL, 0);
    REQUIRE(a == 1 && b == 3);
    seed_of[1] = 21;
    seed_of[3] = 22;
    while (!(strstr(logb, "E1\n") && strstr(logb, "E3\n")))
        if (!pump()) break;
    CHECK(got[1] == 700000 && !bad[1] && got[3] == 900000 && !bad[3]);
    /* the two came interleaved, not one after the other */
    interleaved = strstr(logb, "D1\nD3\nD1\n") || strstr(logb, "D3\nD1\nD3\n");
    CHECK(interleaved);
    h2_close();
}

TEST(interop_ratelimit_and_headers)
{
    const char* p;
    uint64_t sec;
    int i;

    REQUIRE(h2_open(interop));
    REQUIRE(req("POST", "/ratelimit", (const uint8_t*)"{}", 2) == 1);
    CHECK(pump_until("E1\n"));
    p = strstr(logb, "H1 429 ");
    CHECK(p != NULL);
    p = strstr(logb, "retry-after=");
    CHECK(p && ts_http_retry_after(p + 12, 1, 0, &sec) && sec == 7);
    CHECK(got[1] == 13 && memcmp(store[1], "rate limited\n", 13) == 0);

    /* the same twenty fields twice: the second head comes out of Go's dynamic table */
    for (i = 0; i < 2; i++) {
        char want[512];
        int k;
        uint32_t id = req("GET", "/headers?n=20&seed=3", NULL, 0);
        char end[16];

        REQUIRE(id == 3u + 2 * (unsigned)i);
        snprintf(end, sizeof(end), "E%u\n", (unsigned)id);
        CHECK(pump_until(end));
        for (k = 0; k < 20; k++) {
            char v[128];
            int j, n = snprintf(v, sizeof(v), "v3-%d-", k);
            for (j = 0; j < k && n < (int)sizeof(v) - 4; j++) n += snprintf(v + n, sizeof(v) - (size_t)n, "abc");
            snprintf(want, sizeof(want), "x-h-%02d=%s", k, v);
            CHECK(strstr(logb, want) != NULL);
        }
    }
    CHECK(C.hpack.count > 20);
    h2_close();
}

TEST(interop_goaway_idle)
{
    REQUIRE(h2_open(interop_idle));
    REQUIRE(req("GET", "/quick", NULL, 0) == 1);
    CHECK(pump_until("E1\n"));
    /* idle for 300 ms: GOAWAY(NO_ERROR) naming stream 1, then the server closes */
    CHECK(pump_until("G 1 0\n"));
    CHECK(!ts_h2_usable(&C) && req("GET", "/quick", NULL, 0) == 0);
    while (pump()) {}
    CHECK(strstr(logb, "G 1 0\nC 256\n") != NULL);
    CHECK(got[1] == 5 && memcmp(store[1], "quick", 5) == 0);
    h2_close();
}

TEST(interop_goaway_in_flight)
{
    const char* g;
    const char* h;

    REQUIRE(h2_open(interop_shutdown));
    REQUIRE(req("GET", "/hold?ms=700", NULL, 0) == 1);
    while (pump()) {}
    g = strstr(logb, "G 1 0");
    h = strstr(logb, "H1 200");
    /* the GOAWAY came while the stream was open, and the stream still finished */
    if (!(g != NULL && h != NULL && g < h)) fprintf(stderr, "    log:\n%s", logb);
    CHECK(g != NULL && h != NULL && g < h);
    CHECK(strstr(logb, "E1\n") != NULL && got[1] == 4 && memcmp(store[1], "held", 4) == 0);
    CHECK(strstr(logb, "C 256\n") != NULL);
    h2_close();
}

int main(void)
{
    const char* seed = getenv("TS_FUZZ_SEED");

    if (seed) xs = strtoull(seed, NULL, 16);
    if (!xs) xs = 1;
    printf("test_ts_h2 (seed %016llx)\n", (unsigned long long)xs);
    RUN(hpack_integers_c1);
    RUN(hpack_static_table);
    RUN(hpack_huffman);
    RUN(hpack_c2_single_fields);
    RUN(hpack_c3_requests);
    RUN(hpack_c4_requests_huffman);
    RUN(hpack_c5_responses);
    RUN(hpack_c6_responses_huffman);
    RUN(hpack_go_vectors);
    RUN(hpack_refusals);
    RUN(hpack_table_mechanics);
    RUN(hpack_table_against_model);
    RUN(hpack_list_limits);
    RUN(h2_preface_and_settings);
    RUN(h2_request_on_the_wire);
    RUN(h2_request_refusals);
    RUN(h2_response_any_pieces);
    RUN(h2_continuation_padding_priority);
    RUN(h2_flow_control_receive);
    RUN(h2_flow_control_send);
    RUN(h2_ping_and_unknown);
    RUN(h2_rst_and_goaway);
    RUN(h2_parallel_streams);
    RUN(h2_early_noise);
    RUN(h2_connection_errors);
    RUN(h2_malformed_responses);
    RUN(h2_early_response_and_cancel);
    RUN(h2_table_size_update_owed);
    RUN(h2_flood_is_stopped);
    RUN(fuzz_frames);
    RUN(fuzz_hpack);
    interop = getenv("TS_INTEROP");
    interop_idle = getenv("TS_INTEROP_IDLE");
    interop_shutdown = getenv("TS_INTEROP_SHUTDOWN");
    if (interop) {
        printf("  interop against %s\n", interop);
        RUN(interop_post_echo);
        RUN(interop_long_stream);
        RUN(interop_parallel_streams);
        RUN(interop_ratelimit_and_headers);
        if (interop_idle) RUN(interop_goaway_idle);
        if (interop_shutdown) RUN(interop_goaway_in_flight);
    } else {
        printf("  interop: skipped (no TS_INTEROP)\n");
    }
    return t_summary("test_ts_h2");
}
