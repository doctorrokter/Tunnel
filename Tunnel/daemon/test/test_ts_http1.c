/*
 * ts_http1: the three requests byte for byte against what Go's net/http writes for tailscaled
 * (vectors/h2/kat_h2.h), responses parsed in any pieces (Content-Length, chunked, to the close, 101
 * with the next protocol's bytes behind it, 1xx, every refusal), Retry-After, a fuzzer over the
 * parser, and - with TS_INTEROP=host:port - the same against the Go server of vectors/h2.
 *
 * Fuzz seed: TS_FUZZ_SEED=<hex>.
 */

#include "test_util.h"
#include "../src/ts_http1.h"
#include "vectors/h2/kat_h2.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static uint8_t hs[101];                 /* the handshake the vectors carry: 0, 1, ..., 100 */

static uint8_t pat(int seed, size_t i)
{
    return (uint8_t)((i * 7 + (size_t)seed) % 251);
}

/* ------------------------------------------------------------------ requests */

TEST(requests_match_go)
{
    char buf[1024];
    size_t n;

    n = ts_http1_key_request(buf, sizeof(buf), "controlplane.tailscale.com", 443, 1, 130);
    CHECK(n == strlen(kat_req_key) && strcmp(buf, kat_req_key) == 0);
    n = ts_http1_key_request(buf, sizeof(buf), "controlplane.tailscale.com", 0, 1, 130);
    CHECK(n == strlen(kat_req_key) && strcmp(buf, kat_req_key) == 0);
    n = ts_http1_key_request(buf, sizeof(buf), "10.1.2.3", 8080, 0, 130);
    CHECK(n == strlen(kat_req_key_stand) && strcmp(buf, kat_req_key_stand) == 0);

    n = ts_http1_ts2021_request(buf, sizeof(buf), "controlplane.tailscale.com", 443, hs, sizeof(hs));
    CHECK(n == strlen(kat_req_ts2021) && strcmp(buf, kat_req_ts2021) == 0);
    n = ts_http1_ts2021_request(buf, sizeof(buf), "fd7a:115c:a1e0::1", 8080, hs, sizeof(hs));
    CHECK(n == strlen(kat_req_ts2021_v6) && strcmp(buf, kat_req_ts2021_v6) == 0);

    n = ts_http1_derp_request(buf, sizeof(buf), "derp1.tailscale.com", 0, 1, NULL);
    CHECK(n == strlen(kat_req_derp) && strcmp(buf, kat_req_derp) == 0);
    n = ts_http1_derp_request(buf, sizeof(buf), "derp1.tailscale.com", 443, 1, NULL);
    CHECK(n == strlen(kat_req_derp) && strcmp(buf, kat_req_derp) == 0);
    n = ts_http1_derp_request(buf, sizeof(buf), "derp.example.com", 8443, 1, "900a");
    CHECK(n == strlen(kat_req_derp_ideal) && strcmp(buf, kat_req_derp_ideal) == 0);
    n = ts_http1_derp_request(buf, sizeof(buf), "10.1.2.3", 3340, 0, NULL);
    CHECK(n == strlen(kat_req_derp_stand) && strcmp(buf, kat_req_derp_stand) == 0);
}

TEST(requests_room_and_refusals)
{
    char buf[1024], big[300];
    size_t want = strlen(kat_req_key);

    /* the NUL needs its byte too */
    CHECK(ts_http1_key_request(buf, want, "controlplane.tailscale.com", 443, 1, 130) == 0);
    CHECK(ts_http1_key_request(buf, want + 1, "controlplane.tailscale.com", 443, 1, 130) == want);
    CHECK(ts_http1_key_request(buf, 10, "controlplane.tailscale.com", 443, 1, 130) == 0);

    /* hosts that would bend the head */
    CHECK(ts_http1_key_request(buf, sizeof(buf), "", 443, 1, 130) == 0);
    CHECK(ts_http1_key_request(buf, sizeof(buf), "a b", 443, 1, 130) == 0);
    CHECK(ts_http1_key_request(buf, sizeof(buf), "x\r\nInjected: 1", 443, 1, 130) == 0);
    CHECK(ts_http1_key_request(buf, sizeof(buf), "[::1]", 443, 1, 130) == 0);
    CHECK(ts_http1_key_request(buf, sizeof(buf), "a/b", 443, 1, 130) == 0);
    CHECK(ts_http1_key_request(buf, sizeof(buf), "host:80", 443, 1, 130) == 0);   /* one colon: no v6 */
    CHECK(ts_http1_key_request(buf, sizeof(buf), NULL, 443, 1, 130) == 0);
    memset(big, 'a', 254);
    big[254] = '\0';
    CHECK(ts_http1_key_request(buf, sizeof(buf), big, 443, 1, 130) == 0);
    big[253] = '\0';
    CHECK(ts_http1_key_request(buf, sizeof(buf), big, 443, 1, 130) != 0);
    CHECK(ts_http1_derp_request(buf, sizeof(buf), "::1", 443, 1, NULL) != 0);
    CHECK(strstr(buf, "Host: [::1]\r\n") != NULL);
    CHECK(ts_http1_derp_request(buf, sizeof(buf), "::ffff:1.2.3.4", 8443, 1, NULL) != 0);
    CHECK(strstr(buf, "Host: [::ffff:1.2.3.4]:8443\r\n") != NULL);

    /* ts2021: a port, a handshake within bounds */
    CHECK(ts_http1_ts2021_request(buf, sizeof(buf), "h", 0, hs, sizeof(hs)) == 0);
    CHECK(ts_http1_ts2021_request(buf, sizeof(buf), "h", 80, hs, 0) == 0);
    CHECK(ts_http1_ts2021_request(buf, sizeof(buf), "h", 80, NULL, 5) == 0);
    {
        static uint8_t init[TS_HTTP1_HANDSHAKE_MAX + 1];
        static char out[2048];
        CHECK(ts_http1_ts2021_request(out, sizeof(out), "h", 80, init, TS_HTTP1_HANDSHAKE_MAX + 1) == 0);
        CHECK(ts_http1_ts2021_request(out, sizeof(out), "h", 80, init, TS_HTTP1_HANDSHAKE_MAX) != 0);
    }

    /* DERP: the ideal node only as a plain name */
    CHECK(ts_http1_derp_request(buf, sizeof(buf), "d", 443, 1, "") == 0);
    CHECK(ts_http1_derp_request(buf, sizeof(buf), "d", 443, 1, "1a\r\nX: y") == 0);
    CHECK(ts_http1_derp_request(buf, sizeof(buf), "d", 443, 1, "a b") == 0);
    memset(big, 'n', 65);
    big[65] = '\0';
    CHECK(ts_http1_derp_request(buf, sizeof(buf), "d", 443, 1, big) == 0);
    big[64] = '\0';
    CHECK(ts_http1_derp_request(buf, sizeof(buf), "d", 443, 1, big) != 0);
}

/* The X-Tailscale-Handshake value of a ts2021 request for `in`. */
static const char* handshake_value(char* buf, size_t cap, const char* in)
{
    char* v;
    char* e;

    if (!ts_http1_ts2021_request(buf, cap, "h", 80, (const uint8_t*)in, strlen(in))) return "";
    v = strstr(buf, "X-Tailscale-Handshake: ");
    if (!v) return "";
    v += strlen("X-Tailscale-Handshake: ");
    e = strstr(v, "\r\n");
    if (e) *e = '\0';
    return v;
}

TEST(base64_rfc4648)
{
    char buf[512];

    CHECK(strcmp(handshake_value(buf, sizeof(buf), "f"), "Zg==") == 0);
    CHECK(strcmp(handshake_value(buf, sizeof(buf), "fo"), "Zm8=") == 0);
    CHECK(strcmp(handshake_value(buf, sizeof(buf), "foo"), "Zm9v") == 0);
    CHECK(strcmp(handshake_value(buf, sizeof(buf), "foob"), "Zm9vYg==") == 0);
    CHECK(strcmp(handshake_value(buf, sizeof(buf), "fooba"), "Zm9vYmE=") == 0);
    CHECK(strcmp(handshake_value(buf, sizeof(buf), "foobar"), "Zm9vYmFy") == 0);
    CHECK(strcmp(handshake_value(buf, sizeof(buf), "\xff\xfe\xfd"), "//79") == 0);
}

/* ------------------------------------------------------------------ responses */

static ts_http1_resp R, R2;
static uint8_t body[200000], body2[200000];

/* Feeds `s` in pieces of `step` bytes (0: at once) until the response is no longer MORE; *taken
 * is how many bytes were used. */
static ts_http1_state feed(ts_http1_resp* r, const void* s, size_t n, size_t step, size_t* taken)
{
    const uint8_t* p = (const uint8_t*)s;
    size_t off = 0;
    ts_http1_state st = r->state;

    while (off < n && st == TS_HTTP1_MORE) {
        size_t k = step ? step : n, used;
        if (k > n - off) k = n - off;
        st = ts_http1_resp_feed(r, p + off, k, &used);
        off += used;
        if (used < k) break;
    }
    if (taken) *taken = off;
    return st;
}

/* The same for a C string. */
static ts_http1_state feeds(ts_http1_resp* r, const char* s, size_t step, size_t* taken)
{
    return feed(r, s, strlen(s), step, taken);
}

static ts_http1_state parse(const char* s, size_t step)
{
    size_t taken;

    ts_http1_resp_init(&R, body, sizeof(body));
    return feed(&R, s, strlen(s), step, &taken);
}

TEST(response_content_length)
{
    static const char resp[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Date: Thu, 01 Oct 2026 00:00:00 GMT\r\n"
        "Content-Length: 13\r\n"
        "\r\n"
        "{\"a\":\"b\"}wxyzTRAILING";
    size_t steps[] = { 0, 1, 2, 3, 7, 50 }, i, taken, len;
    const char* v;

    for (i = 0; i < sizeof(steps) / sizeof(steps[0]); i++) {
        ts_http1_resp_init(&R, body, sizeof(body));
        CHECK(feed(&R, resp, strlen(resp), steps[i], &taken) == TS_HTTP1_DONE);
        CHECK(R.status == 200 && R.minor == 1 && strcmp(R.reason, "OK") == 0);
        CHECK(R.body_len == 13 && memcmp(body, "{\"a\":\"b\"}wxyz", 13) == 0);
        CHECK(taken == strlen(resp) - strlen("TRAILING"));
        v = ts_http1_resp_field(&R, "content-type", &len);
        CHECK(v && len == 16 && strcmp(v, "application/json") == 0);
        CHECK(ts_http1_resp_field(&R, "CONTENT-LENGTH", NULL) != NULL);
        CHECK(ts_http1_resp_field(&R, "Content-Typ", NULL) == NULL);
        CHECK(R.n_fields == 3);
    }
    /* once done, nothing more is taken */
    {
        size_t used = 99;
        CHECK(ts_http1_resp_feed(&R, (const uint8_t*)"x", 1, &used) == TS_HTTP1_DONE && used == 0);
        CHECK(ts_http1_resp_eof(&R) == TS_HTTP1_DONE);
    }
    /* same Content-Length twice is fine, as in Go */
    CHECK(parse("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok", 0) == TS_HTTP1_DONE);
    CHECK(R.body_len == 2);
    /* zero */
    CHECK(parse("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 1) == TS_HTTP1_DONE && R.body_len == 0);
}

TEST(response_upgrade)
{
    /* controlhttpserver: Go writes its header map sorted; the Noise response right behind */
    static const char head[] =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Connection: upgrade\r\n"
        "Upgrade: tailscale-control-protocol\r\n"
        "\r\n";
    /* derp/derpserver/handler.go, then a ServerKey frame */
    static const char derp[] =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: DERP\r\n"
        "Connection: Upgrade\r\n"
        "Derp-Version: 2\r\n"
        "Derp-Public-Key: abab\r\n\r\n"
        "\x01\x00\x00\x00\x28" "DERP\xf0\x9f\x94\x91";
    uint8_t in[512];
    size_t n, taken, step;

    memcpy(in, head, strlen(head));
    memset(in + strlen(head), 0xa5, 51);
    n = strlen(head) + 51;
    for (step = 0; step < 9; step++) {
        ts_http1_resp_init(&R, NULL, 0);
        CHECK(feed(&R, in, n, step, &taken) == TS_HTTP1_UPGRADED);
        CHECK(taken == strlen(head));                  /* the 51 bytes belong to Noise */
        CHECK(R.status == 101 && strcmp(R.reason, "Switching Protocols") == 0);
        CHECK(ts_http1_resp_upgraded(&R, "tailscale-control-protocol"));
        CHECK(ts_http1_resp_upgraded(&R, "Tailscale-Control-Protocol"));
        CHECK(!ts_http1_resp_upgraded(&R, "DERP"));
        CHECK(!ts_http1_resp_upgraded(&R, "tailscale-control"));
    }
    ts_http1_resp_init(&R, NULL, 0);
    CHECK(feed(&R, derp, sizeof(derp) - 1, 0, &taken) == TS_HTTP1_UPGRADED);
    CHECK(taken == sizeof(derp) - 1 - 13);          /* the frame's first 13 bytes are DERP's */
    CHECK(ts_http1_resp_upgraded(&R, "DERP"));
    CHECK(strcmp(ts_http1_resp_field(&R, "derp-version", NULL), "2") == 0);

    /* a 101 is an upgrade only with Connection: upgrade (Go's transport needs it) */
    CHECK(parse("HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\n\r\n", 0) == TS_HTTP1_UPGRADED);
    CHECK(!ts_http1_resp_upgraded(&R, "DERP"));
    CHECK(parse("HTTP/1.1 101 X\r\nUpgrade: DERP\r\nConnection: keep-alive\r\n\r\n", 0) == TS_HTTP1_UPGRADED);
    CHECK(!ts_http1_resp_upgraded(&R, "DERP"));
    CHECK(parse("HTTP/1.1 101 X\r\nUpgrade: DERP\r\nConnection: upgrades, xupgrade\r\n\r\n", 0) == TS_HTTP1_UPGRADED);
    CHECK(!ts_http1_resp_upgraded(&R, "DERP"));
    CHECK(parse("HTTP/1.1 101 X\r\nUpgrade: DERP\r\nConnection: keep-alive , Upgrade\r\n\r\n", 0) == TS_HTTP1_UPGRADED);
    CHECK(ts_http1_resp_upgraded(&R, "DERP"));
    CHECK(parse("HTTP/1.1 101 X\r\nUpgrade: DERP\r\nConnection: keep-alive\r\nConnection: upgrade\r\n\r\n", 0) == TS_HTTP1_UPGRADED);
    CHECK(ts_http1_resp_upgraded(&R, "DERP"));
    CHECK(parse("HTTP/1.1 101 X\r\nUpgrade: DERP, h2c\r\nConnection: upgrade\r\n\r\n", 0) == TS_HTTP1_UPGRADED);
    CHECK(!ts_http1_resp_upgraded(&R, "DERP"));
    CHECK(parse("HTTP/1.1 200 OK\r\nUpgrade: DERP\r\nConnection: upgrade\r\nContent-Length: 0\r\n\r\n", 0) == TS_HTTP1_DONE);
    CHECK(!ts_http1_resp_upgraded(&R, "DERP"));
}

TEST(response_refusal_with_body_dropped)
{
    /* derper's refusal: with no body buffer the page is read past, the status stays */
    static const char r426[] =
        "HTTP/1.1 426 Upgrade Required\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Content-Length: 33\r\n"
        "\r\n"
        "DERP requires connection upgrade\n";
    size_t taken;

    ts_http1_resp_init(&R, NULL, 0);
    CHECK(feed(&R, r426, strlen(r426), 3, &taken) == TS_HTTP1_DONE);
    CHECK(R.status == 426 && R.body_len == 0 && taken == strlen(r426));
    ts_http1_resp_init(&R, NULL, 0);
    CHECK(feeds(&R, "HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nnope!\r\n0\r\n\r\n", 1, &taken)
          == TS_HTTP1_DONE);
    CHECK(R.status == 403 && R.body_len == 0);
    ts_http1_resp_init(&R, NULL, 0);
    CHECK(feeds(&R, "HTTP/1.1 451 X\r\n\r\nblocked", 0, &taken) == TS_HTTP1_MORE);
    CHECK(ts_http1_resp_eof(&R) == TS_HTTP1_DONE && R.status == 451);
    /* with a buffer, the same body over it fails */
    ts_http1_resp_init(&R, body, 10);
    CHECK(feed(&R, r426, strlen(r426), 0, &taken) == TS_HTTP1_FAILED && R.error == TS_HTTP1_ERR_BODY_TOO_BIG);
    CHECK(R.status == 426);
}

TEST(response_chunked)
{
    static const char resp[] =
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: Chunked\r\n"
        "\r\n"
        "5\r\nhello\r\n"
        "6;name=val;x\r\n world\r\n"
        "A  \r\n0123456789\r\n"
        "1\n!\r\n"                                  /* a bare LF after the size, as Go takes */
        "0\r\n"
        "Trailer-One: 1\r\n"
        "Trailer-Two: 2\r\n"
        "\r\n";
    size_t step, taken;

    for (step = 0; step < 12; step++) {
        ts_http1_resp_init(&R, body, sizeof(body));
        CHECK(feed(&R, resp, strlen(resp), step, &taken) == TS_HTTP1_DONE);
        CHECK(R.body_len == 22 && memcmp(body, "hello world0123456789!", 22) == 0);
        CHECK(taken == strlen(resp));
    }
    /* the last chunk without trailers, LF only */
    CHECK(parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\n\n", 1) == TS_HTTP1_DONE);
    CHECK(R.body_len == 3);
    /* hex in both cases, leading zeros */
    CHECK(parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n00000000000000b\r\nabcdefghijk\r\n0\r\n\r\n", 0)
          == TS_HTTP1_DONE);
    CHECK(R.body_len == 11);
}

TEST(response_chunked_refusals)
{
    static const char* bad[] = {
        "x\r\n",                    /* no digits */
        ";ext\r\n",
        "1000000000000000\r\n",     /* 16 hex digits */
        "5\r\nhelloX\r\n",          /* data not followed by CRLF */
        "5\r\nhello\n",             /* a bare LF after the data: Go wants CRLF */
        "5 x\r\nhello\r\n",         /* junk after the size */
        "5\r\rhello\r\n",
        "0\r\nBad\x01Trailer\r\n\r\n",
        "0\r\nTrailer\rX\r\n\r\n",
    };
    char buf[256];
    size_t i;

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        snprintf(buf, sizeof(buf), "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n%s", bad[i]);
        CHECK(parse(buf, 0) == TS_HTTP1_FAILED && R.error == TS_HTTP1_ERR_FRAMING);
    }
    /* a chunk-size line beyond TS_HTTP1_CHUNK_LINE_MAX (extensions) */
    {
        static char line[TS_HTTP1_CHUNK_LINE_MAX + 200];
        size_t n = (size_t)snprintf(line, sizeof(line), "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;");
        memset(line + n, 'e', TS_HTTP1_CHUNK_LINE_MAX);
        line[n + TS_HTTP1_CHUNK_LINE_MAX] = '\0';
        CHECK(parse(line, 0) == TS_HTTP1_FAILED && R.error == TS_HTTP1_ERR_FRAMING);
    }
    /* too many trailers */
    {
        static char t[8192];
        size_t n = (size_t)snprintf(t, sizeof(t), "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n");
        for (i = 0; i <= TS_HTTP1_MAX_FIELDS; i++) n += (size_t)snprintf(t + n, sizeof(t) - n, "T: %u\r\n", (unsigned)i);
        snprintf(t + n, sizeof(t) - n, "\r\n");
        CHECK(parse(t, 0) == TS_HTTP1_FAILED && R.error == TS_HTTP1_ERR_TOO_BIG);
    }
    /* the body over the buffer, found at the size line */
    ts_http1_resp_init(&R, body, 4);
    CHECK(feeds(&R, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n", 0, NULL)
          == TS_HTTP1_FAILED);
    CHECK(R.error == TS_HTTP1_ERR_BODY_TOO_BIG && R.body_len == 3);
}

TEST(response_until_close)
{
    size_t taken;

    ts_http1_resp_init(&R, body, sizeof(body));
    CHECK(feeds(&R, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nabc", 2, &taken) == TS_HTTP1_MORE);
    CHECK(feeds(&R, "defg", 1, &taken) == TS_HTTP1_MORE);
    CHECK(ts_http1_resp_eof(&R) == TS_HTTP1_DONE && R.body_len == 7 && memcmp(body, "abcdefg", 7) == 0);
    /* HTTP/1.0 */
    CHECK(parse("HTTP/1.0 200 OK\r\n\r\nold", 0) == TS_HTTP1_MORE);
    CHECK(ts_http1_resp_eof(&R) == TS_HTTP1_DONE && R.minor == 0 && R.body_len == 3);
    /* over the buffer */
    ts_http1_resp_init(&R, body, 5);
    CHECK(feeds(&R, "HTTP/1.1 200 OK\r\n\r\n123456", 0, &taken) == TS_HTTP1_FAILED);
    CHECK(R.error == TS_HTTP1_ERR_BODY_TOO_BIG);
    /* the close before the end */
    CHECK(parse("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n12345", 0) == TS_HTTP1_MORE);
    CHECK(ts_http1_resp_eof(&R) == TS_HTTP1_FAILED && R.error == TS_HTTP1_ERR_TRUNCATED);
    CHECK(parse("HTTP/1.1 200 OK\r\nContent-Le", 0) == TS_HTTP1_MORE);
    CHECK(ts_http1_resp_eof(&R) == TS_HTTP1_FAILED && R.error == TS_HTTP1_ERR_TRUNCATED);
    CHECK(parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab", 0) == TS_HTTP1_MORE);
    CHECK(ts_http1_resp_eof(&R) == TS_HTTP1_FAILED && R.error == TS_HTTP1_ERR_TRUNCATED);
    ts_http1_resp_init(&R, body, sizeof(body));
    CHECK(ts_http1_resp_eof(&R) == TS_HTTP1_FAILED);
}

TEST(response_no_body_statuses_and_interim)
{
    size_t taken;

    /* 204 and 304 have no body, whatever they say */
    CHECK(parse("HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n", 0) == TS_HTTP1_DONE);
    CHECK(R.body_len == 0);
    CHECK(parse("HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n", 0) == TS_HTTP1_DONE);
    /* 100 and 103 before the real one */
    ts_http1_resp_init(&R, body, sizeof(body));
    CHECK(feeds(&R, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n"
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi", 1, &taken) == TS_HTTP1_DONE);
    CHECK(R.status == 200 && R.body_len == 2 && R.n_fields == 1);
    CHECK(ts_http1_resp_field(&R, "Link", NULL) == NULL);
    /* but not without end */
    {
        char t[1024];
        size_t n = 0, i;
        for (i = 0; i <= TS_HTTP1_MAX_INTERIM; i++) n += (size_t)snprintf(t + n, sizeof(t) - n, "HTTP/1.1 100 Continue\r\n\r\n");
        snprintf(t + n, sizeof(t) - n, "HTTP/1.1 200 OK\r\n\r\n");
        CHECK(parse(t, 0) == TS_HTTP1_FAILED && R.error == TS_HTTP1_ERR_TOO_BIG);
    }
}

TEST(response_head_syntax)
{
    static const char* bad[] = {
        "HTTP/2 200 OK\r\n\r\n",
        "HTTP/1.1 99 Low\r\n\r\n",
        "HTTP/1.1 600 High\r\n\r\n",
        "HTTP/1.1 2000\r\n\r\n",
        "HTTP/1.1 20x OK\r\n\r\n",
        "http/1.1 200 OK\r\n\r\n",
        "HTTP/1.1  200 OK\r\n\r\n",
        "HTTP/1.x 200 OK\r\n\r\n",
        "HTTP/1.1 200 O\x01K\r\n\r\n",
        "\r\nHTTP/1.1 200 OK\r\n\r\n",                /* an empty line first */
        "HTTP/1.1 200 OK\r\n continued\r\n\r\n",     /* whitespace before the first field */
        "HTTP/1.1 200 OK\r\nBad Name: x\r\n\r\n",
        "HTTP/1.1 200 OK\r\nName : x\r\n\r\n",
        "HTTP/1.1 200 OK\r\n: x\r\n\r\n",
        "HTTP/1.1 200 OK\r\nNoColon\r\n\r\n",
        "HTTP/1.1 200 OK\r\nX: a\x01b\r\n\r\n",
        "HTTP/1.1 200 OK\r\nX: a\x7f\r\n\r\n",
        "HTTP/1.1 200 OK\r\nX: a\rb\r\n\r\n",       /* a bare CR */
        "HTTP/1.1 200\rOK\r\n\r\n",
    };
    size_t i;

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        CHECK(parse(bad[i], 0) == TS_HTTP1_FAILED && R.error == TS_HTTP1_ERR_SYNTAX);
        CHECK(parse(bad[i], 1) == TS_HTTP1_FAILED && R.error == TS_HTTP1_ERR_SYNTAX);
    }
    /* a NUL in the head */
    {
        static const char nul[] = "HTTP/1.1 200 OK\r\nX: a\0b\r\n\r\n";
        ts_http1_resp_init(&R, body, sizeof(body));
        CHECK(feed(&R, nul, sizeof(nul) - 1, 0, NULL) == TS_HTTP1_FAILED && R.error == TS_HTTP1_ERR_SYNTAX);
    }
    /* what is fine: no reason, an empty reason, bare LF line ends, obs-text, a folded value, HTTP/1.2 */
    CHECK(parse("HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n", 0) == TS_HTTP1_DONE && strcmp(R.reason, "") == 0);
    CHECK(parse("HTTP/1.1 200 \r\nContent-Length: 0\r\n\r\n", 0) == TS_HTTP1_DONE && strcmp(R.reason, "") == 0);
    CHECK(parse("HTTP/1.1 200 OK\nContent-Length: 1\n\nz", 1) == TS_HTTP1_DONE && R.body_len == 1);
    CHECK(parse("HTTP/1.1 200 \xc3\xa9t\xc3\xa9\r\nX: \xff\x80\r\nContent-Length: 0\r\n\r\n", 0) == TS_HTTP1_DONE);
    CHECK(parse("HTTP/1.2 200 OK\r\nContent-Length: 0\r\n\r\n", 0) == TS_HTTP1_DONE && R.minor == 1);
    CHECK(parse("HTTP/1.1 200 OK\r\nX-Long: a\r\n  b\r\n\tc \r\nContent-Length: 0\r\n\r\n", 1) == TS_HTTP1_DONE);
    /* "a" CRLF "  b" CRLF "\tc ": each line break becomes two spaces, the end is trimmed */
    CHECK(strcmp(ts_http1_resp_field(&R, "x-long", NULL), "a    b  \tc") == 0);
    CHECK(parse("HTTP/1.1 200 OK\r\nX:\r\nY:   \r\nContent-Length: 0\r\n\r\n", 0) == TS_HTTP1_DONE);
    CHECK(strcmp(ts_http1_resp_field(&R, "X", NULL), "") == 0 && strcmp(ts_http1_resp_field(&R, "Y", NULL), "") == 0);
}

TEST(response_framing_refusals)
{
    static const char* bad[] = {
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nab",
        "HTTP/1.1 200 OK\r\nContent-Length: 2, 2\r\n\r\nab",
        "HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\nab",
        "HTTP/1.1 200 OK\r\nContent-Length: 2 2\r\n\r\nab",
        "HTTP/1.1 200 OK\r\nContent-Length: \r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 9999999999999999999\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
        "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
    };
    size_t i;

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        CHECK(parse(bad[i], 0) == TS_HTTP1_FAILED && R.error == TS_HTTP1_ERR_FRAMING);
    /* a Content-Length over the buffer fails at once, without waiting for the body */
    ts_http1_resp_init(&R, body, 100);
    CHECK(feeds(&R, "HTTP/1.1 200 OK\r\nContent-Length: 101\r\n\r\n", 0, NULL) == TS_HTTP1_FAILED);
    CHECK(R.error == TS_HTTP1_ERR_BODY_TOO_BIG);
}

TEST(response_limits)
{
    static char t[TS_HTTP1_HEAD_MAX * 2];
    size_t n, i;

    /* TS_HTTP1_MAX_FIELDS fields fit, one more does not */
    n = (size_t)snprintf(t, sizeof(t), "HTTP/1.1 200 OK\r\n");
    for (i = 0; i < TS_HTTP1_MAX_FIELDS - 1; i++) n += (size_t)snprintf(t + n, sizeof(t) - n, "F%u: v\r\n", (unsigned)i);
    snprintf(t + n, sizeof(t) - n, "Content-Length: 0\r\n\r\n");
    CHECK(parse(t, 0) == TS_HTTP1_DONE && R.n_fields == TS_HTTP1_MAX_FIELDS);
    n += (size_t)snprintf(t + n, sizeof(t) - n, "One: more\r\n");
    snprintf(t + n, sizeof(t) - n, "Content-Length: 0\r\n\r\n");
    CHECK(parse(t, 0) == TS_HTTP1_FAILED && R.error == TS_HTTP1_ERR_TOO_BIG);

    /* the head: TS_HTTP1_HEAD_MAX bytes exactly is fine, one more is not */
    n = (size_t)snprintf(t, sizeof(t), "HTTP/1.1 200 OK\r\nX: ");
    while (n < TS_HTTP1_HEAD_MAX - 4) t[n++] = 'v';
    memcpy(t + n, "\r\n\r\n", 5);
    CHECK(strlen(t) == TS_HTTP1_HEAD_MAX);
    CHECK(parse(t, 0) == TS_HTTP1_MORE);            /* a body to the close follows */
    memmove(t + 20, t + 19, strlen(t + 19) + 1);
    CHECK(parse(t, 7) == TS_HTTP1_FAILED && R.error == TS_HTTP1_ERR_TOO_BIG);
}

/* ------------------------------------------------------------------ Retry-After */

TEST(retry_after)
{
    uint64_t s;
    const uint64_t rfc = 784111777;                 /* Sun, 06 Nov 1994 08:49:37 GMT */

    CHECK(ts_http_retry_after("7", 1, 0, &s) && s == 7);
    CHECK(ts_http_retry_after(" 120\t", 5, 0, &s) && s == 120);
    CHECK(ts_http_retry_after("0", 1, 0, &s) && s == 0);
    CHECK(ts_http_retry_after("2147483648", 10, 0, &s) && s == 2147483648ULL);
    CHECK(ts_http_retry_after("99999999999999999999999", 23, 0, &s) && s == 2147483648ULL);
    CHECK(!ts_http_retry_after("", 0, 0, &s));
    CHECK(!ts_http_retry_after("  ", 2, 0, &s));
    CHECK(!ts_http_retry_after("-1", 2, 0, &s));
    CHECK(!ts_http_retry_after("1.5", 3, 0, &s));
    CHECK(!ts_http_retry_after("7s", 2, 0, &s));
    CHECK(!ts_http_retry_after("7 7", 3, 0, &s));

    CHECK(ts_http_retry_after("Sun, 06 Nov 1994 08:49:37 GMT", 29, rfc, &s) && s == 0);
    CHECK(ts_http_retry_after("Sun, 06 Nov 1994 08:49:37 GMT", 29, rfc - 10, &s) && s == 10);
    CHECK(ts_http_retry_after("Sun, 06 Nov 1994 08:49:37 GMT", 29, rfc + 3600, &s) && s == 0);
    CHECK(ts_http_retry_after("Thu, 01 Oct 2026 00:00:00 GMT", 29, 1790812800ULL - 61, &s) && s == 61);
    CHECK(ts_http_retry_after("Thu, 29 Feb 2024 23:59:60 GMT", 29, 0, &s));     /* leap day, leap second */
    CHECK(ts_http_retry_after("Sat, 29 Feb 2000 00:00:00 GMT", 29, 0, &s));
    CHECK(!ts_http_retry_after("Wed, 29 Feb 2023 00:00:00 GMT", 29, 0, &s));
    CHECK(!ts_http_retry_after("Mon, 29 Feb 1900 00:00:00 GMT", 29, 0, &s));
    CHECK(!ts_http_retry_after("Thu, 31 Apr 2026 00:00:00 GMT", 29, 0, &s));
    CHECK(!ts_http_retry_after("Thu, 00 Oct 2026 00:00:00 GMT", 29, 0, &s));
    CHECK(!ts_http_retry_after("Thu, 01 Oct 2026 24:00:00 GMT", 29, 0, &s));
    CHECK(!ts_http_retry_after("Thu, 01 Oct 2026 00:60:00 GMT", 29, 0, &s));
    CHECK(!ts_http_retry_after("Thu, 01 Oct 2026 00:00:00 UTC", 29, 0, &s));
    CHECK(!ts_http_retry_after("Xyz, 01 Oct 2026 00:00:00 GMT", 29, 0, &s));
    CHECK(!ts_http_retry_after("Thu, 01 Okt 2026 00:00:00 GMT", 29, 0, &s));
    CHECK(!ts_http_retry_after("Thu,  1 Oct 2026 00:00:00 GMT", 29, 0, &s));
    /* the obsolete formats Go's ParseTime also takes: refused here, the caller's default applies */
    CHECK(!ts_http_retry_after("Sunday, 06-Nov-94 08:49:37 GMT", 30, 0, &s));
    CHECK(!ts_http_retry_after("Sun Nov  6 08:49:37 1994", 24, 0, &s));
}

/* ------------------------------------------------------------------ fuzzing */

static uint64_t xs = 0x9e3779b97f4a7c15ULL;

static uint64_t rnd(void)
{
    xs ^= xs >> 12;
    xs ^= xs << 25;
    xs ^= xs >> 27;
    return xs * 0x2545f4914f6cdd1dULL;
}

static void mutate(uint8_t* buf, size_t* len, size_t cap)
{
    static const uint8_t special[] = { 0, '\r', '\n', ' ', '\t', ':', ';', '0', 'f', 'F', 0x7f, 0xff, ',', '1' };
    size_t n = *len, i, at;
    int k = (int)(rnd() % 7), times = 1 + (int)(rnd() % 4);

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
    case 5:
        if (n > 2) {                                /* delete a slice */
            size_t from = rnd() % n, cnt = 1 + rnd() % (n - from);
            memmove(buf + from, buf + from + cnt, n - from - cnt);
            *len = n - cnt;
        }
        break;
    default:
        if (n > 2) {                                /* duplicate a slice */
            size_t from = rnd() % n, cnt = 1 + rnd() % (n - from);
            if (n + cnt <= cap) {
                memmove(buf + from + cnt, buf + from, n - from);
                *len = n + cnt;
            }
        }
        break;
    }
}

/* Feeds in[0, n) whole into R and in random pieces into R2 (with an end of the connection after
 * both when they still want more): the outcomes must be the same. */
static void same_in_pieces(const uint8_t* in, size_t n, size_t cap)
{
    size_t taken1, taken2 = 0;
    ts_http1_state s1, s2 = TS_HTTP1_MORE;

    ts_http1_resp_init(&R, cap ? body : NULL, cap);
    ts_http1_resp_init(&R2, cap ? body2 : NULL, cap);
    s1 = feed(&R, in, n, 0, &taken1);
    while (taken2 < n && s2 == TS_HTTP1_MORE) {
        size_t k = 1 + rnd() % 40, used;
        if (k > n - taken2) k = n - taken2;
        s2 = ts_http1_resp_feed(&R2, in + taken2, k, &used);
        taken2 += used;
        if (used < k) break;
    }
    if (getenv("TS_FUZZ_VERBOSE") && (s1 != s2 || taken1 != taken2)) {
        fprintf(stderr, "    whole: state %d error %d taken %zu body %zu; pieces: state %d error %d taken %zu body %zu\n",
                s1, R.error, taken1, R.body_len, s2, R2.error, taken2, R2.body_len);
        t_dump("    input", in, n);
    }
    CHECK(s1 == s2 && taken1 == taken2);
    if (s1 == TS_HTTP1_MORE) {
        s1 = ts_http1_resp_eof(&R);
        s2 = ts_http1_resp_eof(&R2);
        CHECK(s1 == s2);
    }
    CHECK(R.error == R2.error && R.body_len == R2.body_len);
    CHECK(R.body_len <= cap);
    if (s1 == TS_HTTP1_DONE || s1 == TS_HTTP1_UPGRADED) {
        size_t i;
        CHECK(R.status == R2.status && R.n_fields == R2.n_fields);
        CHECK(R.status >= 100 && R.status <= 599);
        CHECK(memcmp(body, body2, R.body_len) == 0);
        for (i = 0; i < R.n_fields; i++) {
            CHECK(strcmp(R.fields[i].name, R2.fields[i].name) == 0);
            CHECK(R.fields[i].value_len == strlen(R.fields[i].value));
        }
        if (s1 == TS_HTTP1_UPGRADED) CHECK(R.status == 101);
    }
}

TEST(fuzz_responses)
{
    static const char* seeds[] = {
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"a\":\"b\"}xyz",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;e=1\r\n world\r\n0\r\nT: 1\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: tailscale-control-protocol\r\n\r\nNOISE",
        "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 429 Too Many Requests\r\nRetry-After: 7\r\nContent-Length: 4\r\n\r\nslow",
        "HTTP/1.0 200 OK\r\nX-Fold: a\r\n b\r\n\r\nbody to the end",
        "HTTP/1.1 204 No Content\r\nContent-Length: 9\r\n\r\n",
    };
    static uint8_t buf[2048];
    int iter;

    for (iter = 0; iter < 40000; iter++) {
        const char* s = seeds[rnd() % (sizeof(seeds) / sizeof(seeds[0]))];
        size_t len = strlen(s), cap = rnd() % 4 == 0 ? 0 : 1 + rnd() % 64;
        uint8_t* p;
        int m = (int)(rnd() % 4);

        memcpy(buf, s, len);
        while (m--) mutate(buf, &len, sizeof(buf));
        p = (uint8_t*)malloc(len ? len : 1);       /* exactly its size: ASan sees a read past it */
        memcpy(p, buf, len);
        same_in_pieces(p, len, cap);
        free(p);
    }
    /* noise, and noise after a real status line */
    for (iter = 0; iter < 20000; iter++) {
        size_t len = rnd() % 300, i, off = 0;
        uint8_t* p = (uint8_t*)malloc(len + 32);
        if (rnd() % 2) {
            memcpy(p, "HTTP/1.1 200 OK\r\n", 17);
            off = 17;
        }
        for (i = off; i < len + off; i++) p[i] = rnd() % 3 ? (uint8_t)"abc:\r\n 0123;,"[rnd() % 14] : (uint8_t)rnd();
        same_in_pieces(p, len + off, 1 + rnd() % 300);
        free(p);
    }
}

TEST(fuzz_builders)
{
    static char out[2048];
    char host[300], node[80];
    uint8_t init[200];
    int iter, valid = 0;

    for (iter = 0; iter < 30000; iter++) {
        size_t hl = rnd() % 4 ? rnd() % 20 : rnd() % 260, nl = rnd() % 70, il = rnd() % sizeof(init), i, n;
        static const char alpha[] = "abcxyzXYZ019.-_:[]% \r\n/\x01\xc3";

        for (i = 0; i < hl; i++) host[i] = rnd() % 8 ? alpha[rnd() % 11] : alpha[rnd() % (sizeof(alpha) - 1)];
        host[hl] = '\0';
        for (i = 0; i < nl; i++) node[i] = rnd() % 10 ? alpha[rnd() % 11] : alpha[rnd() % (sizeof(alpha) - 1)];
        node[nl] = '\0';
        for (i = 0; i < il; i++) init[i] = (uint8_t)rnd();
        switch (iter % 3) {
        case 0: n = ts_http1_key_request(out, sizeof(out), host, (uint16_t)rnd(), (int)(rnd() % 2), (unsigned)rnd()); break;
        case 1: n = ts_http1_ts2021_request(out, sizeof(out), host, (uint16_t)rnd(), init, il); break;
        default: n = ts_http1_derp_request(out, sizeof(out), host, (uint16_t)rnd(), (int)(rnd() % 2), rnd() % 2 ? node : NULL); break;
        }
        if (!n) continue;
        valid++;
        /* whatever went in, what came out is one head: lines end with CRLF, nothing else is a
         * control byte, it ends with the empty line and nowhere before */
        CHECK(n == strlen(out));
        CHECK(n >= 4 && memcmp(out + n - 4, "\r\n\r\n", 4) == 0);
        CHECK(strstr(out, "\r\n\r\n") == out + n - 4);
        for (i = 0; i < n; i++) {
            unsigned char ch = (unsigned char)out[i];
            if (ch == '\r') CHECK(out[i + 1] == '\n');
            else if (ch == '\n') CHECK(i > 0 && out[i - 1] == '\r');
            else CHECK(ch >= 0x20 && ch < 0x7f);
        }
        /* and it parses as a head with Host */
        CHECK(strstr(out, "\r\nHost: ") != NULL);
    }
    CHECK(valid > 3000);
}

TEST(fuzz_retry_after)
{
    char s[40];
    int iter;

    for (iter = 0; iter < 30000; iter++) {
        size_t len = rnd() % 36, i;
        uint64_t sec = 0;
        static const char alpha[] = "0123456789 ,:SunMonThuOctFebGMT-";
        for (i = 0; i < len; i++) s[i] = rnd() % 4 ? alpha[rnd() % (sizeof(alpha) - 1)] : (char)rnd();
        if (rnd() % 3 == 0 && len >= 29) memcpy(s, "Thu, 01 Oct 2026 00:00:00 GMT", 29);
        if (ts_http_retry_after(s, len, 1790812800ULL, &sec)) CHECK(sec <= 2147483648ULL || len >= 29);
    }
}

/* ------------------------------------------------------------------ interop (TS_INTEROP) */

static const char* interop;

static int tcp_connect(void)
{
    char host[64];
    const char* colon = strrchr(interop, ':');
    struct sockaddr_in sa;
    struct timeval tv;
    int fd;

    if (!colon || (size_t)(colon - interop) >= sizeof(host)) return -1;
    memcpy(host, interop, (size_t)(colon - interop));
    host[colon - interop] = '\0';
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

/* Reads into the parser until the response ends; what came behind it lands in rest[0, *rest_len). */
static ts_http1_state read_response(int fd, ts_http1_resp* r, uint8_t* rest, size_t* rest_len)
{
    static uint8_t buf[4096];
    ts_http1_state st = TS_HTTP1_MORE;

    *rest_len = 0;
    while (st == TS_HTTP1_MORE) {
        ssize_t k = recv(fd, buf, (size_t)(1 + rnd() % sizeof(buf)), 0);  /* reads of any size */
        size_t used;
        if (k <= 0) return ts_http1_resp_eof(r);
        st = ts_http1_resp_feed(r, buf, (size_t)k, &used);
        if (st != TS_HTTP1_MORE && used < (size_t)k) {
            memcpy(rest, buf + used, (size_t)k - used);
            *rest_len = (size_t)k - used;
        }
    }
    return st;
}

static int recv_exact(int fd, uint8_t* p, size_t n)
{
    while (n) {
        ssize_t k = recv(fd, p, n, 0);
        if (k <= 0) return 0;
        p += k;
        n -= (size_t)k;
    }
    return 1;
}

static uint16_t interop_port(void)
{
    return (uint16_t)atoi(strrchr(interop, ':') + 1);
}

TEST(interop_key_chunked_eof)
{
    static const char key_json[] =
        "{\"legacyPublicKey\":\"mkey:1111111111111111111111111111111111111111111111111111111111111111\","
        "\"publicKey\":\"mkey:2222222222222222222222222222222222222222222222222222222222222222\"}";
    char req[512];
    uint8_t rest[4096];
    size_t rest_len, n, i;
    int fd, ok = 1;

    /* GET /key: Content-Length */
    REQUIRE((fd = tcp_connect()) >= 0);
    n = ts_http1_key_request(req, sizeof(req), "127.0.0.1", interop_port(), 0, 130);
    REQUIRE(n && send_all(fd, req, n));
    ts_http1_resp_init(&R, body, 64 << 10);
    CHECK(read_response(fd, &R, rest, &rest_len) == TS_HTTP1_DONE);
    close(fd);
    CHECK(R.status == 200);
    CHECK(ts_http1_resp_field(&R, "Content-Length", NULL) != NULL);
    CHECK(R.body_len == strlen(key_json) && memcmp(body, key_json, R.body_len) == 0);
    CHECK(strcmp(ts_http1_resp_field(&R, "content-type", NULL), "application/json") == 0);

    /* chunked */
    REQUIRE((fd = tcp_connect()) >= 0);
    n = (size_t)snprintf(req, sizeof(req), "GET /chunked HTTP/1.1\r\nHost: %s\r\nUser-Agent: " TS_HTTP1_USER_AGENT "\r\n\r\n", interop);
    REQUIRE(send_all(fd, req, n));
    ts_http1_resp_init(&R, body, sizeof(body));
    CHECK(read_response(fd, &R, rest, &rest_len) == TS_HTTP1_DONE);
    close(fd);
    CHECK(R.status == 200 && ts_http1_resp_field(&R, "Transfer-Encoding", NULL) != NULL);
    CHECK(R.body_len == 100000);
    for (i = 0; i < R.body_len && i < 100000; i++) ok &= body[i] == pat(5, i);
    CHECK(ok);

    /* a body only the close ends */
    REQUIRE((fd = tcp_connect()) >= 0);
    n = (size_t)snprintf(req, sizeof(req), "GET /eof HTTP/1.1\r\nHost: %s\r\n\r\n", interop);
    REQUIRE(send_all(fd, req, n));
    ts_http1_resp_init(&R, body, sizeof(body));
    CHECK(read_response(fd, &R, rest, &rest_len) == TS_HTTP1_DONE);
    close(fd);
    CHECK(R.status == 200 && R.body_len == 5000);
    for (ok = 1, i = 0; i < R.body_len && i < 5000; i++) ok &= body[i] == pat(9, i);
    CHECK(ok);
}

TEST(interop_upgrades)
{
    char req[1024];
    uint8_t rest[4096], more[64];
    size_t rest_len, n, i;
    int fd, ok = 1;

    /* ts2021: the server checks the head and decodes the handshake (base64 by Go) */
    REQUIRE((fd = tcp_connect()) >= 0);
    n = ts_http1_ts2021_request(req, sizeof(req), "127.0.0.1", interop_port(), hs, sizeof(hs));
    REQUIRE(n && send_all(fd, req, n));
    usleep(50000);                                  /* let the head and the first bytes meet */
    ts_http1_resp_init(&R, NULL, 0);
    CHECK(read_response(fd, &R, rest, &rest_len) == TS_HTTP1_UPGRADED);
    CHECK(ts_http1_resp_upgraded(&R, "tailscale-control-protocol"));
    REQUIRE(rest_len <= 51);
    CHECK(recv_exact(fd, rest + rest_len, 51 - rest_len));
    for (i = 0; i < 51; i++) ok &= rest[i] == pat(3, i);
    CHECK(ok);
    CHECK(send_all(fd, "after the upgrade", 17) && recv_exact(fd, more, 17) && memcmp(more, "after the upgrade", 17) == 0);
    close(fd);

    /* DERP: the ServerKey frame comes in the same flush as the head */
    REQUIRE((fd = tcp_connect()) >= 0);
    n = ts_http1_derp_request(req, sizeof(req), "127.0.0.1", interop_port(), 0, "1a");
    REQUIRE(n && send_all(fd, req, n));
    usleep(50000);
    ts_http1_resp_init(&R, NULL, 0);
    CHECK(read_response(fd, &R, rest, &rest_len) == TS_HTTP1_UPGRADED);
    CHECK(ts_http1_resp_upgraded(&R, "DERP"));
    CHECK(strcmp(ts_http1_resp_field(&R, "Derp-Version", NULL), "2") == 0);
    REQUIRE(rest_len <= 45);
    CHECK(recv_exact(fd, rest + rest_len, 45 - rest_len));
    CHECK(rest[0] == 0x01 && rest[4] == 40 && memcmp(rest + 5, "DERP\xf0\x9f\x94\x91", 8) == 0);
    for (ok = 1, i = 0; i < 32; i++) ok &= rest[13 + i] == pat(4, i);
    CHECK(ok);
    CHECK(send_all(fd, "x", 1) && recv_exact(fd, more, 1) && more[0] == 'x');
    close(fd);

    /* no upgrade asked: Go's 426 with a page, read past with no body buffer */
    REQUIRE((fd = tcp_connect()) >= 0);
    n = (size_t)snprintf(req, sizeof(req), "GET /derp HTTP/1.1\r\nHost: %s\r\nUser-Agent: " TS_HTTP1_USER_AGENT "\r\n\r\n", interop);
    REQUIRE(send_all(fd, req, n));
    ts_http1_resp_init(&R, NULL, 0);
    CHECK(read_response(fd, &R, rest, &rest_len) == TS_HTTP1_DONE);
    CHECK(R.status == 426 && !ts_http1_resp_upgraded(&R, "DERP"));
    close(fd);
}

int main(void)
{
    const char* seed = getenv("TS_FUZZ_SEED");
    size_t i;

    for (i = 0; i < sizeof(hs); i++) hs[i] = (uint8_t)i;
    if (seed) xs = strtoull(seed, NULL, 16);
    if (!xs) xs = 1;
    printf("test_ts_http1 (seed %016llx)\n", (unsigned long long)xs);
    RUN(requests_match_go);
    RUN(requests_room_and_refusals);
    RUN(base64_rfc4648);
    RUN(response_content_length);
    RUN(response_upgrade);
    RUN(response_refusal_with_body_dropped);
    RUN(response_chunked);
    RUN(response_chunked_refusals);
    RUN(response_until_close);
    RUN(response_no_body_statuses_and_interim);
    RUN(response_head_syntax);
    RUN(response_framing_refusals);
    RUN(response_limits);
    RUN(retry_after);
    RUN(fuzz_responses);
    RUN(fuzz_builders);
    RUN(fuzz_retry_after);
    interop = getenv("TS_INTEROP");
    if (interop) {
        printf("  interop against %s\n", interop);
        RUN(interop_key_chunked_eof);
        RUN(interop_upgrades);
    } else {
        printf("  interop: skipped (no TS_INTEROP)\n");
    }
    return t_summary("test_ts_http1");
}
