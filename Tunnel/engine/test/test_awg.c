/*
 * wg_awg: AmneziaWG's wire format piece by piece - the I-packet tag language, the rules for a
 * parameter set, header protection byte for byte against pyca/cryptography
 * (test/vectors/gen_awg_vectors.py), classification, trailers, padding and the UDP window, and what
 * goes out ahead of an initiation. The whole codec between two devices is test_stack's.
 */

#include "test_util.h"
#include "../src/wg_awg.h"
#include "../src/wg_device.h"

static wg_device D;
static wg_awg A;

/* ------------------------------------------------------------------------------ randomness */

/* Real randomness, or a script served in order; a draw past the script's end fails. */
static uint8_t g_script[512];
static size_t g_script_len, g_script_pos;
static int g_scripted, g_draws;

static int test_rng(void* ctx, void* buf, size_t len)
{
    (void)ctx;
    g_draws++;
    if (!g_scripted) return wg_random(buf, len);
    if (g_script_pos + len > g_script_len) return 0;
    memcpy(buf, g_script + g_script_pos, len);
    g_script_pos += len;
    return 1;
}

static void script(const char* hex)
{
    g_script_len = t_hex(g_script, sizeof(g_script), hex);
    g_script_pos = 0;
    g_scripted = 1;
}

static void unscripted(void)
{
    g_scripted = 0;
}

static const uint64_t WALL = 0x68d9b4a0;   /* 2025-09-29 */

static void wall(void* ctx, uint64_t* sec, uint32_t* nsec)
{
    (void)ctx;
    *sec = WALL;
    *nsec = 0;
}

static void setup(const wg_awg_params* p)
{
    wg_device_init(&D);
    D.local.rng.fn = test_rng;
    D.wall_clock = wall;
    unscripted();
    g_draws = 0;
    wg_awg_attach(&A, p, &D);
}

/* ------------------------------------------------------------------------------ helpers */

static int parses(const char* spec, int nops, size_t len)
{
    wg_awg_chain c;
    const char* why = NULL;
    int ok = wg_awg_parse_chain(&c, spec, strlen(spec), &why);

    if (!ok) fprintf(stderr, "    \"%s\": %s\n", spec, why);
    return ok && c.nops == nops && c.len == len;
}

static int refused(const char* spec)
{
    wg_awg_chain c;
    const char* why = NULL;
    return !wg_awg_parse_chain(&c, spec, strlen(spec), &why) && why && why[0];
}

static int classify(uint8_t* d, size_t len, uint32_t* type, size_t* off, size_t* mlen)
{
    return wg_codec_awg.classify(&A, d, len, type, off, mlen);
}

static size_t wrap(uint32_t type, const uint8_t* msg, size_t len, uint8_t* out, size_t cap)
{
    return wg_codec_awg.wrap(&A, type, msg, len, out, cap);
}

static size_t padding(size_t len)
{
    return wg_codec_awg.padding(&A, len, 1420);
}

static const size_t MSG[5] = { 0, WG_INIT_LEN, WG_RESP_LEN, WG_COOKIE_MSG_LEN, 64 };

/* A message of `type` as the device would hand it over: stamped, the rest arbitrary. */
static void message(uint32_t type, uint8_t* msg, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) msg[i] = (uint8_t)(i * 31 + type);
    wg_codec_awg.stamp(&A, type, msg, len);
}

/* ------------------------------------------------------------------------------ I-packets */

TEST(chain_tags)
{
    CHECK(parses("<b 0xc6000000010843290a47ba8ba2ed000044d0><r 16><t><rc 5><rd 3><dz 4><d><ds>", 8,
                 18 + 16 + 4 + 5 + 3 + 4));
    CHECK(parses("", 0, 0));                            /* no tags: not sent */
    CHECK(parses("just text", 0, 0));
    CHECK(parses("x <b 0x01> y <r 2> z", 2, 3));        /* text between tags is ignored */
    CHECK(parses("<b 0xABcd>", 1, 2));                  /* either case of hex */
    CHECK(parses("<b 01ff>", 1, 2));                    /* 0x is optional */
    CHECK(parses("<  b   0x01  0x02 >", 1, 1));         /* words as strings.Fields splits them */
    CHECK(parses("<r +5><rc 007><rd 0>", 3, 12));       /* strconv.Atoi's numbers */
    CHECK(parses("<t whatever><d x><ds y>", 3, 4));     /* arguments they do not take */
    CHECK(parses("<r 65535>", 1, 65535));

    CHECK(refused("<r 10"));                            /* missing > */
    CHECK(refused("<>"));
    CHECK(refused("<   >"));
    CHECK(refused("<x 1>"));
    CHECK(refused("<rr 1>"));
    CHECK(refused("<b>"));
    CHECK(refused("<b 0x>"));
    CHECK(refused("<b 0xabc>"));
    CHECK(refused("<b 0xgg>"));
    CHECK(refused("<b 0X01>"));                         /* only a lowercase 0x is a prefix */
    CHECK(refused("<r>"));
    CHECK(refused("<r -1>"));                           /* the reference accepts it, then crashes */
    CHECK(refused("<dz ten>"));
    CHECK(refused("<r 65536>"));
    CHECK(refused("<r 4294967297>"));                   /* 2^32 + 1 must not wrap round to 1 */
    CHECK(refused("<dz 99999999999999999999>"));
    CHECK(refused("<r 65535><r 1>"));                   /* the packet as a whole, too */
    CHECK(refused("<r 1><x>"));                         /* one bad tag spoils the lot */
}

TEST(chain_limits)
{
    char spec[4200];
    size_t n = 0;
    int i;

    for (i = 0; i < WG_AWG_CHAIN_OPS; i++) n += (size_t)sprintf(spec + n, "<r 1>");
    CHECK(parses(spec, WG_AWG_CHAIN_OPS, WG_AWG_CHAIN_OPS));
    sprintf(spec + n, "<r 1>");
    CHECK(refused(spec));

    n = (size_t)sprintf(spec, "<b 0x");
    for (i = 0; i < WG_AWG_CHAIN_BYTES; i++) n += (size_t)sprintf(spec + n, "5a");
    sprintf(spec + n, ">");
    CHECK(parses(spec, 1, WG_AWG_CHAIN_BYTES));
    sprintf(spec + n, "5a>");
    CHECK(refused(spec));
}

TEST(chain_output)
{
    static const char spec[] = "<b 0x0102><t><r 3><rc 4><rd 4><dz 2><d>";
    wg_awg_params p;
    wg_awg_chain c;
    const char* why;
    uint8_t out[64], want[64];
    size_t n;

    wg_awg_params_default(&p);
    setup(&p);
    REQUIRE(wg_awg_parse_chain(&c, spec, strlen(spec), &why));
    /* <r> takes its bytes as they come, <rc> and <rd> map them to letters and digits */
    script("aabbcc" "003334ff" "00090aff");
    n = wg_awg_chain_build(&A, &c, out);
    t_hex(want, sizeof(want), "0102" "68d9b4a0" "aabbcc" "615a6156" "30393035" "0000");
    CHECK(n == 19 && n == c.len);
    CHECK_MEM(out, want, 19);
    CHECK(g_script_pos == g_script_len);
}

/* ------------------------------------------------------------------------------ parameters */

TEST(parameter_rules)
{
    wg_awg_params p;
    const char* why = NULL;
    int i;

    wg_awg_params_default(&p);
    CHECK(wg_awg_check(&p, &why) && wg_awg_is_plain(&p));

    /* H1-H4 apart, their defaults included */
    p.h[1].lo = p.h[1].hi = 3;
    CHECK(!wg_awg_check(&p, &why));
    wg_awg_params_default(&p);
    p.h[1].lo = 5;
    p.h[1].hi = 10;
    p.h[2].lo = 10;
    p.h[2].hi = 20;
    CHECK(!wg_awg_check(&p, &why));
    p.h[2].lo = 11;
    p.h[3].lo = p.h[3].hi = 0;
    CHECK(wg_awg_check(&p, &why));
    p.h[4].lo = 30;
    p.h[4].hi = 29;
    CHECK(!wg_awg_check(&p, &why));

    /* S1-S4: within the wire buffer; at least 12 each under header protection */
    wg_awg_params_default(&p);
    p.s[3] = WG_AWG_MAX_PREFIX;
    CHECK(wg_awg_check(&p, &why));
    p.s[3] = WG_AWG_MAX_PREFIX + 1;
    CHECK(!wg_awg_check(&p, &why));
    wg_awg_params_default(&p);
    p.hp_key[5] = 1;
    CHECK(!wg_awg_check(&p, &why));
    for (i = 1; i <= 4; i++) p.s[i] = 12;
    CHECK(wg_awg_check(&p, &why));
    p.s[2] = 11;
    CHECK(!wg_awg_check(&p, &why));

    /* junk sizes: only when junk is sent */
    wg_awg_params_default(&p);
    p.jmin = 10;
    p.jmax = 9;
    CHECK(wg_awg_check(&p, &why));
    p.jc = 1;
    CHECK(!wg_awg_check(&p, &why));

    /* plain: every setting at WireGuard's */
#define NOT_PLAIN(stmt)                                                          \
    do {                                                                         \
        wg_awg_params_default(&p);                                               \
        stmt;                                                                    \
        CHECK(!wg_awg_is_plain(&p));                                             \
    } while (0)
    NOT_PLAIN(p.jc = 1);
    NOT_PLAIN(p.s[3] = 1);
    NOT_PLAIN(p.h[4].hi = 5);
    NOT_PLAIN(p.h[1].lo = p.h[1].hi = 7);
    NOT_PLAIN(p.hp_key[31] = 1);
    NOT_PLAIN(p.content_padding.hi = 1);
    NOT_PLAIN(p.random_trailers = 1);
    NOT_PLAIN(p.i[5].nops = 1);
#undef NOT_PLAIN
    wg_awg_params_default(&p);
    p.jmin = 40;                                        /* no Jc: no junk, still plain */
    p.jmax = 70;
    CHECK(wg_awg_is_plain(&p));
}

/* ------------------------------------------------------------------------------ the wire */

TEST(header_protection_is_chacha20)
{
    /* test/vectors/gen_awg_vectors.py */
    static const char RESP_PREFIX[] = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
    static const char RESP_MSG[] =
        "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc"
        "e3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bc"
        "c3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980";
    static const char RESP_WIRE[] =
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaff4b0e6fcd33dd39a98a7c10ece9445f3"
        "21705f2fb60fe791d43712aed3cea44bba600a6e8994e1f7832254d86105d95c"
        "8d184984cee9e89457d8d0f4cfd9228fcf61a98792002f595b0dfa04ebe4d8d7"
        "ae6492f70c3c3dc7dfaaa231";
    static const char DATA_PREFIX[] = "b0b1b2b3b4b5b6b7b8b9babb";
    static const char DATA_MSG[] =
        "05121f2c394653606d7a8794a1aebbc8d5e2effc091623303d4a5764717e8b98"
        "a5b2bfccd9e6f3000d1a2734414e5b68";
    static const char DATA_WIRE[] =
        "b0b1b2b3b4b5b6b7b8b9babbadcfa261ce4a27da2bab8d11eba839e1d5e2effc"
        "091623303d4a5764717e8b98a5b2bfccd9e6f3000d1a2734414e5b68";
    wg_awg_params p;
    uint8_t msg[128], want[128], out[256];
    size_t n, off = 0, mlen = 0;
    uint32_t type = 0;
    int i;

    wg_awg_params_default(&p);
    for (i = 0; i < WG_KEY_LEN; i++) p.hp_key[i] = (uint8_t)i;
    p.s[1] = p.s[3] = 12;
    p.s[2] = 16;
    p.s[4] = 12;
    p.h[2].lo = p.h[2].hi = 0x18110a03u;                /* the vectors' type fields */
    p.h[4].lo = p.h[4].hi = 0x2c1f1205u;
    setup(&p);
    CHECK(A.hp);

    /* A response: the whole message behind its prefix, nonce = the prefix's first 12 bytes */
    t_hex(msg, sizeof(msg), RESP_MSG);
    script(RESP_PREFIX);
    n = wrap(WG_MSG_RESPONSE, msg, WG_RESP_LEN, out, sizeof(out));
    t_hex(want, sizeof(want), RESP_WIRE);
    CHECK(n == 16 + WG_RESP_LEN && g_script_pos == g_script_len);
    CHECK_MEM(out, want, 16 + WG_RESP_LEN);
    unscripted();
    CHECK(classify(out, n, &type, &off, &mlen) && type == WG_MSG_RESPONSE && off == 16 && mlen == WG_RESP_LEN);
    CHECK_MEM(out + off, msg, WG_RESP_LEN);             /* as its macs saw it */

    /* A data message: its 16-byte header only */
    t_hex(msg, sizeof(msg), DATA_MSG);
    script(DATA_PREFIX);
    n = wrap(WG_MSG_DATA, msg, 48, out, sizeof(out));
    t_hex(want, sizeof(want), DATA_WIRE);
    CHECK(n == 60);
    CHECK_MEM(out, want, 60);
    unscripted();
    CHECK(classify(out, n, &type, &off, &mlen) && type == WG_MSG_DATA && off == 12 && mlen == 48);
    CHECK_MEM(out + off, msg, 48);

    /* Another key reads nonsense: nothing is recognised */
    t_hex(out, sizeof(out), RESP_WIRE);
    A.p.hp_key[0] ^= 1;
    CHECK(!classify(out, 16 + WG_RESP_LEN, &type, &off, &mlen));
}

TEST(classification)
{
    wg_awg_params p;
    uint8_t msg[256], out[1024];
    size_t n, off = 0, mlen = 0;
    uint32_t type = 0, t, h;
    int i, ok = 1, junk = 0;

    wg_awg_params_default(&p);
    p.s[1] = 5;
    p.s[2] = 7;
    p.s[3] = 9;
    p.s[4] = 11;
    p.h[1].lo = 100;
    p.h[1].hi = 200;
    p.h[2].lo = p.h[2].hi = 300;
    p.h[3].lo = 400;
    p.h[3].hi = 450;
    p.h[4].lo = 1000;
    p.h[4].hi = 5000;
    setup(&p);

    /* whatever stamp and wrap make, classify reads back */
    for (i = 0; i < 400; i++) {
        t = (uint32_t)(i % 4) + 1;
        message(t, msg, MSG[t]);
        h = wg_load32(msg);
        if (h < p.h[t].lo || h > p.h[t].hi) ok = 0;
        n = wrap(t, msg, MSG[t], out, sizeof(out));
        if (n != p.s[t] + MSG[t]) ok = 0;
        if (!classify(out, n, &type, &off, &mlen) || type != t || off != p.s[t] || mlen != MSG[t]) ok = 0;
        if (memcmp(out + off, msg, MSG[t]) != 0) ok = 0;
    }
    CHECK(ok);

    /* a type value outside its range */
    message(WG_MSG_INITIATION, msg, WG_INIT_LEN);
    wg_store32(msg, 99);
    n = wrap(WG_MSG_INITIATION, msg, WG_INIT_LEN, out, sizeof(out));
    CHECK(!classify(out, n, &type, &off, &mlen));

    /* handshake lengths are exact, unless trailers are allowed */
    message(WG_MSG_RESPONSE, msg, WG_RESP_LEN);
    n = wrap(WG_MSG_RESPONSE, msg, WG_RESP_LEN, out, sizeof(out));
    CHECK(!classify(out, n + 1, &type, &off, &mlen));
    CHECK(!classify(out, n - 1, &type, &off, &mlen));
    A.p.random_trailers = 1;
    CHECK(classify(out, n + 1, &type, &off, &mlen) && type == WG_MSG_RESPONSE && mlen == WG_RESP_LEN);
    CHECK(classify(out, n + 300, &type, &off, &mlen) && type == WG_MSG_RESPONSE);
    CHECK(!classify(out, n - 1, &type, &off, &mlen));
    A.p.random_trailers = 0;

    /* data: any length from its prefix plus 32 */
    message(WG_MSG_DATA, msg, 32);
    n = wrap(WG_MSG_DATA, msg, 32, out, sizeof(out));
    CHECK(classify(out, n, &type, &off, &mlen) && type == WG_MSG_DATA && mlen == 32);
    CHECK(classify(out, n + 100, &type, &off, &mlen) && type == WG_MSG_DATA && mlen == 132);
    CHECK(!classify(out, n - 1, &type, &off, &mlen));

    /* In the reference's order, the first match wins. A datagram of an initiation's size whose
     * bytes at S1 = 5 read as H1 and at S4 = 11 as H4 is an initiation; with no H1 there, data. */
    memset(out, 0x77, 5 + WG_INIT_LEN);
    wg_store32(out + 5, 150);
    wg_store32(out + 11, 2000);
    CHECK(classify(out, 5 + WG_INIT_LEN, &type, &off, &mlen) && type == WG_MSG_INITIATION && off == 5);
    wg_store32(out + 5, 2000);
    CHECK(classify(out, 5 + WG_INIT_LEN, &type, &off, &mlen) && type == WG_MSG_DATA && off == 11);

    /* too short for anything, even with a matching type */
    memset(out, 0, sizeof(out));
    wg_store32(out + 11, 2000);
    CHECK(!classify(out, 31, &type, &off, &mlen));

    /* noise */
    for (i = 0; i < 20000; i++) {
        n = (size_t)(i % 300);
        wg_random(out, n);
        if (classify(out, n, &type, &off, &mlen)) junk++;
    }
    CHECK(junk <= 3);                                   /* ~0.02 expected: H4 is 4001 of 2^32 */
}

TEST(trailers_window_and_padding)
{
    wg_awg_params p;
    uint8_t msg[256], out[70000];
    size_t n, pad, max_init = 0, max_cookie = 0, i, lens_seen = 0, last = 0;
    int ok = 1;

    wg_awg_params_default(&p);
    for (i = 1; i <= 4; i++) p.s[i] = 10;
    p.random_trailers = 1;
    setup(&p);
    CHECK(A.udp_window == WG_AWG_UDP_WINDOW);

    /* A handshake message's trailer stays within the window: 500 to begin with */
    message(WG_MSG_INITIATION, msg, WG_INIT_LEN);
    for (i = 0; i < 2000; i++) {
        n = wrap(WG_MSG_INITIATION, msg, WG_INIT_LEN, out, sizeof(out));
        if (n < 10 + WG_INIT_LEN || n >= WG_AWG_UDP_WINDOW) ok = 0;
        if (n > max_init) max_init = n;
        if (n != last) lens_seen++;
        last = n;
    }
    CHECK(ok && max_init > 400 && lens_seen > 100);

    /* The window grows with authentic data (the datagram less its tag)... */
    wg_codec_awg.authentic(&A, WG_MSG_DATA, 1400, 0);
    CHECK(A.udp_window == 10 + 1400 - 16);
    wg_codec_awg.authentic(&A, WG_MSG_DATA, 100, 0);    /* only grows */
    CHECK(A.udp_window == 10 + 1400 - 16);
    wg_codec_awg.authentic(&A, WG_MSG_INITIATION, WG_INIT_LEN, 0);     /* handshakes teach nothing */
    CHECK(A.udp_window == 10 + 1400 - 16);
    for (i = 0, max_init = 0; i < 2000; i++) {
        n = wrap(WG_MSG_INITIATION, msg, WG_INIT_LEN, out, sizeof(out));
        if (n >= A.udp_window) ok = 0;
        if (n > max_init) max_init = n;
    }
    CHECK(ok && max_init > 1000);

    /* ...but a cookie reply goes by the fixed 500: it answers someone not yet known */
    message(WG_MSG_COOKIE, msg, WG_COOKIE_MSG_LEN);
    for (i = 0; i < 2000; i++) {
        n = wrap(WG_MSG_COOKIE, msg, WG_COOKIE_MSG_LEN, out, sizeof(out));
        if (n < 10 + WG_COOKIE_MSG_LEN || n >= WG_AWG_UDP_WINDOW) ok = 0;
        if (n > max_cookie) max_cookie = n;
    }
    CHECK(ok && max_cookie > 400);

    /* A move starts over */
    wg_codec_awg.authentic(&A, WG_MSG_RESPONSE, WG_RESP_LEN, 1);
    CHECK(A.udp_window == WG_AWG_UDP_WINDOW);
    wg_codec_awg.authentic(&A, WG_MSG_DATA, 1000, 1);   /* moved, then this packet counts */
    CHECK(A.udp_window == 10 + 1000 - 16);

    /* Data never gets a trailer: its padding is inside the seal. With trailers on, a random
     * amount up to the window, which the packet itself widens first. */
    wg_codec_awg.authentic(&A, WG_MSG_DATA, 32, 1);     /* an empty keepalive: the window stays */
    CHECK(A.udp_window == WG_AWG_UDP_WINDOW);
    for (i = 0; i < 2000; i++) {
        pad = padding(100);
        if (pad >= WG_AWG_UDP_WINDOW - (100 + 32 + 10)) ok = 0;
    }
    CHECK(ok);
    CHECK(padding(1300) == 0 && A.udp_window == 1300 + 32 + 10);     /* the widest yet: no room */
    message(WG_MSG_DATA, msg, 48);
    CHECK(wrap(WG_MSG_DATA, msg, 48, out, sizeof(out)) == 10 + 48);

    /* ContentPaddingAddition first: a value of its range, cut to the window */
    A.p.random_trailers = 0;
    A.p.content_padding.lo = 16;
    A.p.content_padding.hi = 32;
    for (i = 0; i < 1000; i++) {
        pad = padding(100);
        if (pad < 16 || pad > 32) ok = 0;
    }
    CHECK(ok);
    A.p.content_padding.lo = 30;
    A.p.content_padding.hi = 40;
    CHECK(padding(1300 - 20) == 20);                    /* 20 bytes left in the window */
    A.p.content_padding.lo = 0;                         /* a range from 0 is on all the same */
    A.p.content_padding.hi = 3;
    for (i = 0, lens_seen = 0; i < 400; i++) {
        pad = padding(100);                             /* WireGuard's would be 12 */
        if (pad > 3) ok = 0;
        if (pad == 0) lens_seen |= 1;
        if (pad == 3) lens_seen |= 2;
    }
    CHECK(ok && lens_seen == 3);
    A.p.content_padding.lo = A.p.content_padding.hi = 0;

    /* Neither: WireGuard's */
    CHECK(padding(100) == wg_data_padding(100, 1420) && padding(1417) == wg_data_padding(1417, 1420));

    /* Without trailers a handshake message is exactly prefix + message */
    message(WG_MSG_INITIATION, msg, WG_INIT_LEN);
    CHECK(wrap(WG_MSG_INITIATION, msg, WG_INIT_LEN, out, sizeof(out)) == 10 + WG_INIT_LEN);

    /* and nothing is ever built past the buffer it is given */
    A.p.random_trailers = 1;
    CHECK(wrap(WG_MSG_INITIATION, msg, WG_INIT_LEN, out, 10 + WG_INIT_LEN - 1) == 0);
}

TEST(a_single_value_costs_no_randomness)
{
    wg_awg_params p;
    uint8_t msg[WG_INIT_LEN];
    int i, ok = 1, seen[4] = { 0, 0, 0, 0 };

    wg_awg_params_default(&p);
    p.h[1].lo = p.h[1].hi = 0xdeadbeefu;
    setup(&p);
    script("");
    wg_codec_awg.stamp(&A, WG_MSG_INITIATION, msg, sizeof(msg));
    CHECK(wg_load32(msg) == 0xdeadbeefu && g_draws == 0);

    unscripted();
    A.p.h[1].lo = 100;
    A.p.h[1].hi = 103;
    for (i = 0; i < 1000; i++) {
        wg_codec_awg.stamp(&A, WG_MSG_INITIATION, msg, sizeof(msg));
        if (wg_load32(msg) < 100 || wg_load32(msg) > 103) ok = 0;
        seen[wg_load32(msg) - 100 < 4 ? wg_load32(msg) - 100 : 0] = 1;
    }
    CHECK(ok && g_draws == 1000);
    CHECK(seen[0] && seen[1] && seen[2] && seen[3]);    /* both ends included */
}

TEST(wire_randomness)
{
    /* With the device's default source the codec serves its own ChaCha20 keystream: every byte is
     * that stream under the codec's key, block after block, and the key changes every
     * WG_AWG_REKEY_BLOCKS blocks. */
    static const uint8_t nonce[12] = { 0 };
    wg_awg_params p;
    uint8_t msg[48], out[256], want[128], key0[WG_KEY_LEN];
    int i;

    wg_awg_params_default(&p);
    p.s[4] = 40;
    setup(&p);
    D.local.rng.fn = NULL;
    message(WG_MSG_DATA, msg, sizeof(msg));
    for (i = 0; i < 3; i++) {                           /* 3 x 40 bytes: across a block's end */
        CHECK(wrap(WG_MSG_DATA, msg, sizeof(msg), out + i * 40, 88) == 40 + sizeof(msg));
    }
    memset(want, 0, sizeof(want));
    wg_chacha20_xor(want, want, sizeof(want), A.rkey, nonce, 0);
    CHECK_MEM(out, want, 40);
    CHECK_MEM(out + 40, want + 40, 40);
    CHECK_MEM(out + 80, want + 80, 40);
    CHECK(A.rblocks == 2 && A.rleft == 8);

    /* the last block under a key, then a fresh key */
    A.p.s[4] = 64;
    A.rleft = 0;
    A.rblocks = WG_AWG_REKEY_BLOCKS - 1;
    memcpy(key0, A.rkey, sizeof(key0));
    CHECK(wrap(WG_MSG_DATA, msg, sizeof(msg), out, sizeof(out)) == 64 + sizeof(msg));
    memset(want, 0, 64);
    wg_chacha20_xor(want, want, 64, key0, nonce, WG_AWG_REKEY_BLOCKS - 1);
    CHECK_MEM(out, want, 64);
    CHECK(A.rblocks == 0);
    CHECK(wrap(WG_MSG_DATA, msg, sizeof(msg), out, sizeof(out)) == 64 + sizeof(msg));
    CHECK(A.rblocks == 1 && memcmp(A.rkey, key0, sizeof(key0)) != 0);
    memset(want, 0, 64);
    wg_chacha20_xor(want, want, 64, A.rkey, nonce, 0);
    CHECK_MEM(out, want, 64);
}

/* ------------------------------------------------------------------------------ ahead of an initiation */

static struct {
    uint8_t data[2048];
    size_t  len;
} g_out[32];
static int g_nout;

static void catch_dgram(void* ctx, const uint8_t* d, size_t len)
{
    (void)ctx;
    if (g_nout == 32) return;
    memcpy(g_out[g_nout].data, d, len < 2048 ? len : 2048);
    g_out[g_nout++].len = len;
}

static void ahead(size_t cap)
{
    static uint8_t buf[4096];
    g_nout = 0;
    wg_codec_awg.before_initiation(&A, buf, cap, catch_dgram, NULL);
}

TEST(ahead_of_an_initiation)
{
    static const char i1[] = "<b 0x0102><r 4>", i3[] = "<dz 3>", i5[] = "<d>";
    wg_awg_params p;
    const char* why;
    int i, ok = 1;

    wg_awg_params_default(&p);
    p.jc = 3;
    p.jmin = 40;
    p.jmax = 70;
    CHECK(wg_awg_parse_chain(&p.i[1], i1, strlen(i1), &why));
    CHECK(wg_awg_parse_chain(&p.i[3], i3, strlen(i3), &why));
    CHECK(wg_awg_parse_chain(&p.i[5], i5, strlen(i5), &why));
    setup(&p);

    /* I1..I5 in order (those with tags, even if empty), then Jc junk of Jmin..Jmax-1 bytes */
    ahead(4096);
    REQUIRE(g_nout == 6);
    CHECK(g_out[0].len == 6 && g_out[0].data[0] == 1 && g_out[0].data[1] == 2);
    CHECK(g_out[1].len == 3 && g_out[1].data[0] == 0 && g_out[1].data[2] == 0);
    CHECK(g_out[2].len == 0);
    for (i = 0; i < 300; i++) {
        ahead(4096);
        if (g_nout != 6 || g_out[3].len < 40 || g_out[3].len >= 70 || g_out[5].len < 40 || g_out[5].len >= 70)
            ok = 0;
    }
    CHECK(ok);

    /* Jmin == Jmax: exactly that */
    A.p.jmin = A.p.jmax = 50;
    ahead(4096);
    CHECK(g_nout == 6 && g_out[3].len == 50 && g_out[4].len == 50 && g_out[5].len == 50);

    /* never past the buffer: what does not fit is not sent */
    A.p.jmin = A.p.jmax = 100;
    ahead(80);
    CHECK(g_nout == 3);
    ahead(5);
    CHECK(g_nout == 2 && g_out[0].len == 3);            /* I1 (6 bytes) skipped, I3 and I5 go */

    /* nothing configured: nothing sent */
    wg_awg_params_default(&p);
    setup(&p);
    ahead(4096);
    CHECK(g_nout == 0);
}

int main(void)
{
    if (!wg_crypto_init()) {
        fprintf(stderr, "wg_crypto_init failed\n");
        return 2;
    }
    RUN(chain_tags);
    RUN(chain_limits);
    RUN(chain_output);
    RUN(parameter_rules);
    RUN(header_protection_is_chacha20);
    RUN(classification);
    RUN(trailers_window_and_padding);
    RUN(a_single_value_costs_no_randomness);
    RUN(wire_randomness);
    RUN(ahead_of_an_initiation);
    wg_crypto_cleanup();
    return t_summary("test_awg");
}
