/*
 * bt_proto: blocks built, framed out of a byte stream and parsed; every rule that makes a client
 * be dropped.
 */

#include "test_util.h"
#include "../src/bt_proto.h"

static char rbuf[BT_BLOCK_MAX + 4];
static char wbuf[BT_BLOCK_MAX + 4];
static bt_block blk;

/* Feeds `len` bytes in pieces of `step` and collects every block's first value into `firsts`. */
static int feed(bt_reader* r, const char* data, size_t len, size_t step, char firsts[][64], int max)
{
    size_t off = 0;
    int got = 0, rc;

    while (off < len) {
        size_t room, n;
        char* p = bt_reader_space(r, &room);
        n = len - off < step ? len - off : step;
        if (n > room) n = room;
        memcpy(p, data + off, n);
        bt_reader_commit(r, n);
        off += n;
        while ((rc = bt_reader_next(r, &blk, NULL, 0)) == 1) {
            if (got < max) snprintf(firsts[got], 64, "%s=%s", blk.kv[0].key, blk.kv[0].val);
            got++;
        }
        if (rc < 0) return -1;
    }
    return got;
}

TEST(roundtrip_escapes)
{
    static const char* vals[] = { "", "plain", "a\nb", "\r\n", "back\\slash", "\\n is not a newline",
                                  "=equals=", "trailing\\", "\n\n\n" };
    bt_writer w;
    bt_reader r;
    size_t i, room;
    char* p;

    bt_writer_init(&w, wbuf, sizeof(wbuf));
    bt_put(&w, "cmd", "test");
    for (i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) bt_put(&w, "v", vals[i]);
    REQUIRE(bt_end(&w));
    /* The block stays lines: exactly one empty line, at the end. */
    CHECK(strstr(wbuf, "\n\n") == wbuf + w.len - 2);

    bt_reader_init(&r, rbuf, sizeof(rbuf));
    p = bt_reader_space(&r, &room);
    memcpy(p, wbuf, w.len);
    bt_reader_commit(&r, w.len);
    REQUIRE(bt_reader_next(&r, &blk, NULL, 0) == 1);
    REQUIRE(blk.n == 1 + sizeof(vals) / sizeof(vals[0]));
    CHECK(strcmp(bt_block_kind(&blk), "cmd") == 0);
    for (i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {
        CHECK(strcmp(blk.kv[1 + i].key, "v") == 0);
        CHECK(strcmp(blk.kv[1 + i].val, vals[i]) == 0);
        CHECK(blk.kv[1 + i].val_len == strlen(vals[i]));
    }
    CHECK(bt_reader_next(&r, &blk, NULL, 0) == 0);
}

TEST(stream_pieces)
{
    const char* s = "cmd=a\nid=1\n\n\n\r\ncmd=b\r\nid=2\r\n\r\nevent=c\n\n";
    char firsts[8][64];
    size_t step;

    /* Any way the bytes arrive, the same three blocks come out. */
    for (step = 1; step <= strlen(s); step++) {
        bt_reader r;
        bt_reader_init(&r, rbuf, sizeof(rbuf));
        CHECK(feed(&r, s, strlen(s), step, firsts, 8) == 3);
        CHECK(strcmp(firsts[0], "cmd=a") == 0);
        CHECK(strcmp(firsts[1], "cmd=b") == 0);
        CHECK(strcmp(firsts[2], "event=c") == 0);
    }
}

TEST(incomplete_waits)
{
    bt_reader r;
    size_t room;
    char* p;

    bt_reader_init(&r, rbuf, sizeof(rbuf));
    p = bt_reader_space(&r, &room);
    memcpy(p, "cmd=a\nid=1\n", 11);
    bt_reader_commit(&r, 11);
    CHECK(bt_reader_next(&r, &blk, NULL, 0) == 0);
    CHECK(bt_reader_next(&r, &blk, NULL, 0) == 0);      /* asking again changes nothing */
    p = bt_reader_space(&r, &room);
    memcpy(p, "\n", 1);
    bt_reader_commit(&r, 1);
    REQUIRE(bt_reader_next(&r, &blk, NULL, 0) == 1);
    CHECK(blk.n == 2);
    CHECK(strcmp(bt_get(&blk, "id"), "1") == 0);
}

static int parse_str(const char* s, char* err)
{
    static char text[1024];
    size_t n = strlen(s);
    memcpy(text, s, n + 1);
    return bt_block_parse(&blk, text, n, err, 128);
}

TEST(parse_rules)
{
    char err[128];

    CHECK(parse_str("cmd=x\nkey.with_dots_09=v", err) == 1);
    CHECK(strcmp(bt_get(&blk, "key.with_dots_09"), "v") == 0);      /* no line end after the last */
    CHECK(parse_str("cmd=x\nno equals", err) == 0);
    CHECK(strstr(err, "=") != NULL);
    CHECK(parse_str("Cmd=x", err) == 0);
    CHECK(parse_str("=x", err) == 0);
    CHECK(parse_str("cmd-x=1", err) == 0);
    CHECK(parse_str("abcdefghijabcdefghijabcdefghij12=1", err) == 1);    /* 32 */
    CHECK(parse_str("abcdefghijabcdefghijabcdefghij123=1", err) == 0);   /* 33 */
    CHECK(parse_str("cmd=a\\tb", err) == 0);
    CHECK(parse_str("cmd=ab\\", err) == 0);
    CHECK(parse_str("cmd=a\rb", err) == 0);
    CHECK(parse_str("cmd=a\n\nid=1", err) == 0);
    CHECK(parse_str("cmd=a=b", err) == 1);
    CHECK(strcmp(bt_get(&blk, "cmd"), "a=b") == 0);
    {
        char text[16] = "cmd=a\0b";
        CHECK(bt_block_parse(&blk, text, 7, err, sizeof(err)) == 0);
    }
}

TEST(too_many_lines)
{
    static char text[BT_BLOCK_MAX_LINES * 8 + 16];
    size_t len = 0;
    int i;
    char err[64];

    for (i = 0; i < BT_BLOCK_MAX_LINES; i++) len += (size_t)sprintf(text + len, "k=%d\n", i);
    CHECK(bt_block_parse(&blk, text, len, err, sizeof(err)) == 1);
    CHECK(blk.n == BT_BLOCK_MAX_LINES);
    len = 0;
    for (i = 0; i <= BT_BLOCK_MAX_LINES; i++) len += (size_t)sprintf(text + len, "k=%d\n", i);
    CHECK(bt_block_parse(&blk, text, len, err, sizeof(err)) == 0);
}

TEST(numbers)
{
    uint64_t v = 7;
    int b;

    REQUIRE(parse_str("cmd=x\na=0\nb=18446744073709551615\nc=18446744073709551616\nd=-1\ne=\nf=2\ng=1\nh=007", NULL));
    CHECK(bt_get_u64(&blk, "a", ~0ULL, &v) == 1 && v == 0);
    CHECK(bt_get_u64(&blk, "b", ~0ULL, &v) == 1 && v == ~0ULL);
    CHECK(bt_get_u64(&blk, "c", ~0ULL, &v) == -1);
    CHECK(bt_get_u64(&blk, "d", ~0ULL, &v) == -1);
    CHECK(bt_get_u64(&blk, "e", ~0ULL, &v) == -1);
    CHECK(bt_get_u64(&blk, "missing", ~0ULL, &v) == 0);
    CHECK(bt_get_u64(&blk, "f", 1, &v) == -1);
    CHECK(bt_get_u64(&blk, "b", 0xffffffffULL, &v) == -1);
    CHECK(bt_get_u64(&blk, "h", 100, &v) == 1 && v == 7);
    CHECK(bt_get_bool(&blk, "g", &b) == 1 && b == 1);
    CHECK(bt_get_bool(&blk, "a", &b) == 1 && b == 0);
    CHECK(bt_get_bool(&blk, "f", &b) == -1);
}

TEST(lists)
{
    size_t i;
    int count = 0;

    REQUIRE(parse_str("reply=x\nallowed=1\nother=z\nallowed=2\nallowed=3", NULL));
    for (i = bt_find(&blk, "allowed", 0); i < blk.n; i = bt_find(&blk, "allowed", i + 1)) {
        count++;
        CHECK(blk.kv[i].val[0] == (char)('0' + count));
    }
    CHECK(count == 3);
    CHECK(strcmp(bt_get(&blk, "allowed"), "1") == 0);
}

TEST(writer_failures)
{
    char small[16];
    bt_writer w;

    bt_writer_init(&w, wbuf, sizeof(wbuf));
    bt_put_n(&w, "v", "a\0b", 3);
    CHECK(w.failed);
    CHECK(!bt_end(&w));

    bt_writer_init(&w, wbuf, sizeof(wbuf));
    bt_put(&w, "Bad", "x");
    CHECK(w.failed);

    bt_writer_init(&w, small, sizeof(small));
    bt_put(&w, "k", "1234567890123");    /* "k=" + 13 + "\n" = 16: fits, no room for the end */
    CHECK(!w.failed);
    CHECK(!bt_end(&w));

    bt_writer_init(&w, small, sizeof(small));
    bt_put(&w, "k", "a\\\\\\\\\\\\\\");    /* a and 7 backslashes: 15 bytes escaped, 18 in all */
    CHECK(w.failed);

    bt_writer_init(&w, wbuf, sizeof(wbuf));
    bt_put_i64(&w, "n", (int64_t)(-9223372036854775807LL - 1));
    bt_put_i64(&w, "p", 42);
    bt_put_u64(&w, "u", ~0ULL);
    REQUIRE(bt_end(&w));
    {
        const char* want = "n=-9223372036854775808\np=42\nu=18446744073709551615\n\n";
        CHECK(w.len == strlen(want) && memcmp(wbuf, want, w.len) == 0);
    }
}

TEST(largest_block)
{
    static char big[BT_BLOCK_MAX];
    bt_writer w;
    bt_reader r;
    size_t vlen = BT_BLOCK_MAX - strlen("cmd=x\nv=\n"), room;
    char* p;
    char err[64];

    /* A block of exactly BT_BLOCK_MAX bytes goes through a reader of the documented size. */
    memset(big, 'z', vlen);
    bt_writer_init(&w, wbuf, sizeof(wbuf));
    bt_put(&w, "cmd", "x");
    bt_put_n(&w, "v", big, vlen);
    REQUIRE(bt_end(&w));
    REQUIRE(w.len == BT_BLOCK_MAX + 1);
    bt_reader_init(&r, rbuf, sizeof(rbuf));
    p = bt_reader_space(&r, &room);
    REQUIRE(room >= w.len);
    memcpy(p, wbuf, w.len);
    bt_reader_commit(&r, w.len);
    REQUIRE(bt_reader_next(&r, &blk, err, sizeof(err)) == 1);
    CHECK(blk.kv[1].val_len == vlen);

    /* One byte more, and it is refused - before the end ever arrives. */
    bt_reader_init(&r, rbuf, sizeof(rbuf));
    p = bt_reader_space(&r, &room);
    memcpy(p, "cmd=x\nv=", 8);
    memset(p + 8, 'z', vlen + 1);
    p[8 + vlen + 1] = '\n';
    bt_reader_commit(&r, 8 + vlen + 2);
    CHECK(bt_reader_next(&r, &blk, err, sizeof(err)) == -1);
    CHECK(strstr(err, "too long") != NULL);

    /* A line without an end that never stops: refused once the buffer is full. */
    bt_reader_init(&r, rbuf, sizeof(rbuf));
    for (;;) {
        int rc;
        p = bt_reader_space(&r, &room);
        if (!room) break;
        memset(p, 'q', room > 1000 ? 1000 : room);
        bt_reader_commit(&r, room > 1000 ? 1000 : room);
        rc = bt_reader_next(&r, &blk, err, sizeof(err));
        if (rc != 0) {
            CHECK(rc == -1);
            break;
        }
    }
    CHECK(bt_reader_next(&r, &blk, err, sizeof(err)) == -1);
}

TEST(malformed_in_stream)
{
    char firsts[4][64];
    bt_reader r;

    bt_reader_init(&r, rbuf, sizeof(rbuf));
    CHECK(feed(&r, "cmd=a\n\ngarbage\n\n", 16, 5, firsts, 4) == -1);
}

int main(void)
{
    printf("test_proto\n");
    RUN(roundtrip_escapes);
    RUN(stream_pieces);
    RUN(incomplete_waits);
    RUN(parse_rules);
    RUN(too_many_lines);
    RUN(numbers);
    RUN(lists);
    RUN(writer_failures);
    RUN(largest_block);
    RUN(malformed_in_stream);
    return t_summary("test_proto");
}
