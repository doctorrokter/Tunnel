/*
 * wg_cookie: mac1 and mac2 on real handshake messages, the cookie reply round trip under load,
 * its refusals, the timing, and a byte-exact cookie exchange from test/vectors/gen_noise_vectors.py.
 */

#include "test_util.h"
#include "../src/wg_cookie.h"
#include "vectors/kat_noise.h"

#define SEC WG_NSEC_PER_SEC
#define T0  (1000 * SEC)

static const uint8_t SRC_A[6] = { 192, 0, 2, 1, 0xca, 0x6c };      /* 192.0.2.1:51820 */
static const uint8_t SRC_B[6] = { 192, 0, 2, 2, 0xca, 0x6c };      /* 192.0.2.2:51820 */

/* Scripted randomness for the checker: served in order, and running dry is a failure. */
typedef struct {
    uint8_t buf[128];
    size_t  len, pos;
} script;

static int rng_script(void* ctx, void* out, size_t len)
{
    script* s = (script*)ctx;
    if (s->pos + len > s->len) return 0;
    memcpy(out, s->buf + s->pos, len);
    s->pos += len;
    return 1;
}

/* A receiver ("responder") key pair, its checker, and a maker for a sender talking to it. */
typedef struct {
    wg_key sk, pk;
    wg_cookie_checker checker;
    wg_cookie_maker maker;
} setup;

static void setup_init(setup* s)
{
    CHECK(wg_key_generate(&s->sk, &s->pk));
    wg_cookie_checker_init(&s->checker);
    CHECK(wg_cookie_checker_set_key(&s->checker, &s->pk));
    CHECK(wg_cookie_maker_init(&s->maker, &s->pk));
}

/* Something shaped like an initiation; the macs do not care what is in front of them. */
static void fake_initiation(uint8_t msg[WG_INIT_LEN], uint8_t fill)
{
    memset(msg, fill, WG_INIT_LEN);
    wg_store32(msg + WG_INIT_OFF_TYPE, WG_MSG_INITIATION);
    wg_store32(msg + WG_INIT_OFF_SENDER, 0x01020304);
}

TEST(mac1_round_trip)
{
    setup s;
    uint8_t msg[WG_INIT_LEN], bad[WG_INIT_LEN], zero[WG_MAC_LEN];
    int i, refused = 0;

    setup_init(&s);
    fake_initiation(msg, 0x33);
    CHECK(wg_cookie_add_macs(&s.maker, msg, sizeof(msg), T0));
    memset(zero, 0, sizeof(zero));
    CHECK_MEM(msg + WG_INIT_OFF_MAC2, zero, WG_MAC_LEN);       /* no cookie yet */
    CHECK(wg_cookie_validate(&s.checker, msg, sizeof(msg), SRC_A, sizeof(SRC_A), 0, T0)
          == WG_MAC_VALID_NO_COOKIE);

    /* mac1 covers every byte before it, the type field and the sender index included. */
    for (i = 0; i < WG_INIT_OFF_MAC2; i++) {
        memcpy(bad, msg, sizeof(bad));
        bad[i] ^= 0x01;
        if (wg_cookie_validate(&s.checker, bad, sizeof(bad), SRC_A, sizeof(SRC_A), 0, T0) == WG_MAC_INVALID)
            refused++;
    }
    CHECK(refused == WG_INIT_OFF_MAC2);

    /* mac2 is not looked at when the receiver is not under load. */
    memcpy(bad, msg, sizeof(bad));
    bad[WG_INIT_OFF_MAC2] ^= 0x01;
    CHECK(wg_cookie_validate(&s.checker, bad, sizeof(bad), SRC_A, sizeof(SRC_A), 0, T0)
          == WG_MAC_VALID_NO_COOKIE);

    /* The same macs work on a response: they are found at the end of the message. */
    memset(bad, 0x44, WG_RESP_LEN);
    CHECK(wg_cookie_add_macs(&s.maker, bad, WG_RESP_LEN, T0));
    CHECK(wg_cookie_validate(&s.checker, bad, WG_RESP_LEN, SRC_A, sizeof(SRC_A), 0, T0)
          == WG_MAC_VALID_NO_COOKIE);
}

TEST(mac1_is_bound_to_the_receiver)
{
    setup s, other;
    uint8_t msg[WG_INIT_LEN];

    setup_init(&s);
    setup_init(&other);
    fake_initiation(msg, 0x33);
    CHECK(wg_cookie_add_macs(&s.maker, msg, sizeof(msg), T0));
    CHECK(wg_cookie_validate(&other.checker, msg, sizeof(msg), SRC_A, sizeof(SRC_A), 0, T0) == WG_MAC_INVALID);

    /* A checker without a key refuses everything; so does a runt. */
    wg_cookie_checker_init(&other.checker);
    CHECK(wg_cookie_validate(&other.checker, msg, sizeof(msg), SRC_A, sizeof(SRC_A), 0, T0) == WG_MAC_INVALID);
    CHECK(wg_cookie_validate(&s.checker, msg, WG_MACS_LEN - 1, SRC_A, sizeof(SRC_A), 0, T0) == WG_MAC_INVALID);
}

TEST(cookie_round_trip_under_load)
{
    setup s;
    uint8_t msg[WG_INIT_LEN], reply[WG_COOKIE_MSG_LEN];

    setup_init(&s);
    fake_initiation(msg, 0x55);
    CHECK(wg_cookie_add_macs(&s.maker, msg, sizeof(msg), T0));

    /* Under load, no mac2: the receiver answers with a cookie reply to the sender index. */
    CHECK(wg_cookie_validate(&s.checker, msg, sizeof(msg), SRC_A, sizeof(SRC_A), 1, T0)
          == WG_MAC_VALID_NO_COOKIE);
    CHECK(wg_cookie_create_reply(&s.checker, reply, msg, sizeof(msg), SRC_A, sizeof(SRC_A), T0));
    CHECK(wg_load32(reply + WG_COOKIE_OFF_TYPE) == WG_MSG_COOKIE);
    CHECK(wg_load32(reply + WG_COOKIE_OFF_RECEIVER) == 0x01020304);

    /* The sender takes the cookie and repeats; now mac2 carries it. */
    CHECK(wg_cookie_consume_reply(&s.maker, reply, T0 + SEC));
    CHECK(wg_cookie_add_macs(&s.maker, msg, sizeof(msg), T0 + SEC));
    CHECK(wg_cookie_validate(&s.checker, msg, sizeof(msg), SRC_A, sizeof(SRC_A), 1, T0 + SEC)
          == WG_MAC_VALID_WITH_COOKIE);

    /* The cookie is bound to the source address. */
    CHECK(wg_cookie_validate(&s.checker, msg, sizeof(msg), SRC_B, sizeof(SRC_B), 1, T0 + SEC)
          == WG_MAC_VALID_NO_COOKIE);
}

TEST(cookie_reply_refusals)
{
    setup s;
    uint8_t m1[WG_INIT_LEN], m2[WG_INIT_LEN], reply[WG_COOKIE_MSG_LEN], bad[WG_COOKIE_MSG_LEN];

    setup_init(&s);

    /* Nothing sent yet: no mac1 to open a reply against. */
    fake_initiation(m1, 0x66);
    CHECK(wg_cookie_add_macs(&s.maker, m1, sizeof(m1), T0));
    CHECK(wg_cookie_create_reply(&s.checker, reply, m1, sizeof(m1), SRC_A, sizeof(SRC_A), T0));
    {
        wg_cookie_maker fresh;
        CHECK(wg_cookie_maker_init(&fresh, &s.pk));
        CHECK(!wg_cookie_consume_reply(&fresh, reply, T0));
    }

    /* A reply to an older message: the sender has moved on to m2, whose mac1 is the AD now. */
    fake_initiation(m2, 0x77);
    CHECK(wg_cookie_add_macs(&s.maker, m2, sizeof(m2), T0));
    CHECK(!wg_cookie_consume_reply(&s.maker, reply, T0));
    CHECK(!s.maker.has_cookie);

    /* A forged reply to m2 */
    CHECK(wg_cookie_create_reply(&s.checker, reply, m2, sizeof(m2), SRC_A, sizeof(SRC_A), T0));
    memcpy(bad, reply, sizeof(bad));
    bad[WG_COOKIE_OFF_NONCE] ^= 0x01;
    CHECK(!wg_cookie_consume_reply(&s.maker, bad, T0));
    memcpy(bad, reply, sizeof(bad));
    bad[WG_COOKIE_OFF_COOKIE] ^= 0x01;
    CHECK(!wg_cookie_consume_reply(&s.maker, bad, T0));

    /* The genuine one, once. */
    CHECK(wg_cookie_consume_reply(&s.maker, reply, T0));
    CHECK(!wg_cookie_consume_reply(&s.maker, reply, T0));
    CHECK(s.maker.has_cookie);
}

TEST(cookie_timing)
{
    setup s;
    uint8_t msg[WG_INIT_LEN], reply[WG_COOKIE_MSG_LEN], zero[WG_MAC_LEN];

    setup_init(&s);
    memset(zero, 0, sizeof(zero));
    fake_initiation(msg, 0x88);
    CHECK(wg_cookie_add_macs(&s.maker, msg, sizeof(msg), T0));
    CHECK(wg_cookie_create_reply(&s.checker, reply, msg, sizeof(msg), SRC_A, sizeof(SRC_A), T0));
    CHECK(wg_cookie_consume_reply(&s.maker, reply, T0));

    /* The sender uses its cookie for 115 s (the secret's 120 s minus 5 s of latency)... */
    CHECK(wg_cookie_add_macs(&s.maker, msg, sizeof(msg), T0 + 115 * SEC - 1));
    CHECK(memcmp(msg + WG_INIT_OFF_MAC2, zero, WG_MAC_LEN) != 0);
    CHECK(wg_cookie_validate(&s.checker, msg, sizeof(msg), SRC_A, sizeof(SRC_A), 1, T0 + 115 * SEC - 1)
          == WG_MAC_VALID_WITH_COOKIE);

    /* ...and then sends zeroes rather than a cookie about to die. */
    CHECK(wg_cookie_add_macs(&s.maker, msg, sizeof(msg), T0 + 115 * SEC));
    CHECK_MEM(msg + WG_INIT_OFF_MAC2, zero, WG_MAC_LEN);
}

TEST(secret_rotation)
{
    setup s;
    script sc;
    uint8_t msg[WG_INIT_LEN], reply[WG_COOKIE_MSG_LEN];

    setup_init(&s);
    memset(&sc, 0, sizeof(sc));
    memset(sc.buf, 0xa1, 32);               /* first secret */
    memset(sc.buf + 32, 0xb2, 24);          /* the reply's nonce */
    memset(sc.buf + 56, 0xc3, 32);          /* the next secret */
    sc.len = 88;
    s.checker.rng.fn = rng_script;
    s.checker.rng.ctx = &sc;

    fake_initiation(msg, 0x99);
    CHECK(wg_cookie_add_macs(&s.maker, msg, sizeof(msg), T0));
    CHECK(wg_cookie_create_reply(&s.checker, reply, msg, sizeof(msg), SRC_A, sizeof(SRC_A), T0));
    CHECK(wg_cookie_consume_reply(&s.maker, reply, T0));
    CHECK(wg_cookie_add_macs(&s.maker, msg, sizeof(msg), T0 + 100 * SEC));
    CHECK(sc.pos == 56);

    /* Still the first secret at 119 s... */
    CHECK(wg_cookie_validate(&s.checker, msg, sizeof(msg), SRC_A, sizeof(SRC_A), 1, T0 + 119 * SEC)
          == WG_MAC_VALID_WITH_COOKIE);
    CHECK(sc.pos == 56);

    /* ...a new one at 120 s, and the old cookie is worthless. */
    CHECK(wg_cookie_validate(&s.checker, msg, sizeof(msg), SRC_A, sizeof(SRC_A), 1, T0 + 120 * SEC)
          == WG_MAC_VALID_NO_COOKIE);
    CHECK(sc.pos == 88);

    /* With the randomness gone, no reply goes out - not with a guessable nonce, not with a
     * secret past its age. */
    CHECK(!wg_cookie_create_reply(&s.checker, reply, msg, sizeof(msg), SRC_A, sizeof(SRC_A), T0 + 121 * SEC));
    CHECK(!wg_cookie_create_reply(&s.checker, reply, msg, sizeof(msg), SRC_A, sizeof(SRC_A), T0 + 250 * SEC));
    CHECK(!s.checker.has_secret);
}

TEST(cookie_transcript)
{
    wg_key rpub;
    script sc;
    wg_cookie_checker checker;
    wg_cookie_maker maker;
    uint8_t init[WG_INIT_LEN], want_init[WG_INIT_LEN], src[6], reply[WG_COOKIE_MSG_LEN], want[WG_COOKIE_MSG_LEN];
    uint8_t cookie[WG_COOKIE_LEN], with_mac2[WG_INIT_LEN];

    CHECK(t_hex(rpub.b, WG_KEY_LEN, KAT_R_STATIC_PUB) == WG_KEY_LEN);
    CHECK(t_hex(init, sizeof(init), KAT_PSK_INIT) == WG_INIT_LEN);
    memcpy(want_init, init, sizeof(want_init));
    CHECK(t_hex(src, sizeof(src), KAT_COOKIE_SRC) == sizeof(src));
    CHECK(t_hex(want, sizeof(want), KAT_COOKIE_REPLY) == WG_COOKIE_MSG_LEN);
    CHECK(t_hex(cookie, sizeof(cookie), KAT_COOKIE) == WG_COOKIE_LEN);
    CHECK(t_hex(with_mac2, sizeof(with_mac2), KAT_INIT_WITH_MAC2) == WG_INIT_LEN);

    /* The responder, under load, with the reference's secret and nonce */
    memset(&sc, 0, sizeof(sc));
    sc.len = t_hex(sc.buf, sizeof(sc.buf), KAT_COOKIE_SECRET);
    sc.len += t_hex(sc.buf + sc.len, sizeof(sc.buf) - sc.len, KAT_COOKIE_NONCE);
    wg_cookie_checker_init(&checker);
    CHECK(wg_cookie_checker_set_key(&checker, &rpub));
    checker.rng.fn = rng_script;
    checker.rng.ctx = &sc;

    CHECK(wg_cookie_validate(&checker, init, sizeof(init), src, sizeof(src), 1, T0) == WG_MAC_VALID_NO_COOKIE);
    CHECK(wg_cookie_create_reply(&checker, reply, init, sizeof(init), src, sizeof(src), T0));
    CHECK_MEM(reply, want, WG_COOKIE_MSG_LEN);
    CHECK(sc.pos == sc.len);

    /* The initiator: its maker last sent this very initiation, so re-adding the macs reproduces
     * mac1, and the reply opens against it. */
    CHECK(wg_cookie_maker_init(&maker, &rpub));
    CHECK(wg_cookie_add_macs(&maker, init, sizeof(init), T0));
    CHECK_MEM(init, want_init, WG_INIT_LEN);
    CHECK(wg_cookie_consume_reply(&maker, reply, T0));
    CHECK_MEM(maker.cookie, cookie, WG_COOKIE_LEN);

    CHECK(wg_cookie_add_macs(&maker, init, sizeof(init), T0));
    CHECK_MEM(init, with_mac2, WG_INIT_LEN);
    CHECK(wg_cookie_validate(&checker, init, sizeof(init), src, sizeof(src), 1, T0) == WG_MAC_VALID_WITH_COOKIE);
}

int main(void)
{
    if (!wg_crypto_init()) {
        fprintf(stderr, "wg_crypto_init failed\n");
        return 2;
    }
    RUN(mac1_round_trip);
    RUN(mac1_is_bound_to_the_receiver);
    RUN(cookie_round_trip_under_load);
    RUN(cookie_reply_refusals);
    RUN(cookie_timing);
    RUN(secret_rotation);
    RUN(cookie_transcript);
    wg_crypto_cleanup();
    return t_summary("test_cookie");
}
