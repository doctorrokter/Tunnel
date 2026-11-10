/*
 * ts_disco: Tailscale's disco messages (docs/TAILSCALE.md, section 11a). The vectors come from
 * Tailscale's own code (vectors/disco, Go): frames sealed as magicsock seals them and each message
 * as disco.Parse reads it. Every frame must open with the shared key either end derives, read as Go
 * reads it, and - for the messages we send ourselves - come out of ts_disco_seal byte for byte under
 * the same nonce. Then fuzzed: frames mutated and cut, random messages sealed and opened back, each
 * frame in a heap buffer of exactly its size, so a read past one is caught.
 *
 * Seeded like the daemon's fuzzer: BT_FUZZ_SEED=<hex> picks another run.
 */

#include "test_util.h"
#include "../src/ts_disco.h"
#include "vectors/disco/kat_disco.h"

#include <sys/socket.h>
#include <arpa/inet.h>

static uint64_t xs = 0x3c6ef372fe94f82bULL;

static uint64_t rnd(void)
{
    xs ^= xs << 13;
    xs ^= xs >> 7;
    xs ^= xs << 17;
    return xs;
}

static void ep_text(char* out, size_t cap, const wg_endpoint* e)
{
    char a[64] = "?";
    inet_ntop(e->family == 6 ? AF_INET6 : AF_INET, e->addr, a, sizeof(a));
    snprintf(out, cap, e->family == 6 ? "[%s]:%u" : "%s:%u", a, (unsigned)e->port);
}

static void hex(char* out, const uint8_t* p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", p[i]);
    out[2 * n] = '\0';
}

/* The message in the generator's words (vectors/disco/main.go, describe). */
static void describe(char* out, size_t cap, const ts_disco_msg* m)
{
    char tx[2 * TS_DISCO_TXID_LEN + 1], key[2 * TS_DISCO_KEY_LEN + 1], ep[80];
    size_t len, i;

    hex(tx, m->txid, TS_DISCO_TXID_LEN);
    switch (m->type) {
    case TS_DISCO_PING:
        if (m->has_node_key) hex(key, m->node_key, TS_DISCO_KEY_LEN);
        else snprintf(key, sizeof(key), "-");
        snprintf(out, cap, "ping tx=%s key=%s pad=%u", tx, key, (unsigned)m->padding);
        break;
    case TS_DISCO_PONG:
        ep_text(ep, sizeof(ep), &m->src);
        snprintf(out, cap, "pong tx=%s src=%s", tx, ep);
        break;
    case TS_DISCO_CALL_ME_MAYBE:
        len = (size_t)snprintf(out, cap, "cmm n=%u", (unsigned)m->n_eps);
        for (i = 0; i < m->n_eps && len < cap; i++) {
            ep_text(ep, sizeof(ep), &m->eps[i]);
            len += (size_t)snprintf(out + len, cap - len, " %s", ep);
        }
        break;
    default:
        snprintf(out, cap, "other");
        break;
    }
}

/* ------------------------------------------------------------------ the vectors */

TEST(keys)
{
    wg_key a_priv, b_priv, a_pub, b_pub;
    uint8_t ab[WG_BOX_KEY_LEN], ba[WG_BOX_KEY_LEN];

    memcpy(a_priv.b, disco_vec_a_priv, 32);
    memcpy(b_priv.b, disco_vec_b_priv, 32);
    REQUIRE(wg_key_public(&a_priv, &a_pub) && wg_key_public(&b_priv, &b_pub));
    CHECK_MEM(a_pub.b, disco_vec_a_pub, 32);
    CHECK_MEM(b_pub.b, disco_vec_b_pub, 32);
    /* the shared key: the sender's view and the receiver's are Go's box.Precompute */
    REQUIRE(ts_disco_shared(ab, disco_vec_b_pub, &a_priv));
    REQUIRE(ts_disco_shared(ba, disco_vec_a_pub, &b_priv));
    CHECK_MEM(ab, disco_vec_shared, WG_BOX_KEY_LEN);
    CHECK_MEM(ba, disco_vec_shared, WG_BOX_KEY_LEN);
    {
        static const uint8_t zero[32];
        CHECK(!ts_disco_shared(ab, zero, &a_priv));     /* a low-order key: refused */
    }
}

TEST(vectors_open)
{
    size_t i;

    for (i = 0; i < sizeof(disco_vecs) / sizeof(disco_vecs[0]); i++) {
        const disco_vec* v = &disco_vecs[i];
        uint8_t* f = (uint8_t*)malloc(v->len);
        ts_disco_msg m;
        char got[1024];
        int ok;

        REQUIRE(f);
        memcpy(f, v->frame, v->len);
        CHECK(ts_disco_is(f, v->len));
        CHECK_MEM(ts_disco_sender(f), disco_vec_a_pub, 32);
        ok = ts_disco_open(f, v->len, disco_vec_shared, &m);
        if (!v->opens) {
            CHECK(!ok);
        } else if (v->parsed[0]) {
            /* Go reads it: so do we, the same */
            CHECK(ok);
            describe(got, sizeof(got), &m);
            if (strcmp(got, v->parsed) != 0) {
                fprintf(stderr, "  %s\n    got  %s\n    want %s\n", v->name, got, v->parsed);
                CHECK(0);
            }
        } else {
            /* Go refuses it: we refuse it too - or, for a type nobody uses yet, call it OTHER */
            CHECK(!ok || (m.type == TS_DISCO_OTHER && v->len > TS_DISCO_HEADER_LEN + WG_BOX_TAG_LEN + 1));
            if (ok && m.type != TS_DISCO_OTHER) fprintf(stderr, "  %s: read, Go refuses it\n", v->name);
        }
        free(f);
    }
}

/* What we send ourselves comes out of ts_disco_seal exactly as Go sealed it. */
TEST(vectors_seal)
{
    static const char* ours[] = { "ping", "ping_padded", "ping_old", "pong_v4", "pong_v6", "cmm", "cmm_empty" };
    size_t i, k;

    for (k = 0; k < sizeof(ours) / sizeof(ours[0]); k++) {
        for (i = 0; i < sizeof(disco_vecs) / sizeof(disco_vecs[0]); i++) {
            const disco_vec* v = &disco_vecs[i];
            ts_disco_msg m;
            uint8_t out[TS_DISCO_FRAME_MAX];
            size_t n;

            if (strcmp(v->name, ours[k]) != 0) continue;
            REQUIRE(ts_disco_open(v->frame, v->len, disco_vec_shared, &m));
            n = ts_disco_seal(out, sizeof(out), &m, disco_vec_a_pub, disco_vec_shared,
                              v->frame + TS_DISCO_MAGIC_LEN + TS_DISCO_KEY_LEN);
            CHECK(n == v->len);
            if (n == v->len) CHECK_MEM(out, v->frame, n);
            /* one byte short of room: refused, not cut */
            CHECK(ts_disco_seal(out, v->len - 1, &m, disco_vec_a_pub, disco_vec_shared,
                                v->frame + TS_DISCO_MAGIC_LEN + TS_DISCO_KEY_LEN) == 0);
        }
    }
}

TEST(refusals)
{
    ts_disco_msg m;
    uint8_t out[TS_DISCO_FRAME_MAX], nonce[WG_BOX_NONCE_LEN] = { 1 };
    size_t i;

    /* what cannot be written */
    memset(&m, 0, sizeof(m));
    m.type = TS_DISCO_OTHER;
    CHECK(ts_disco_seal(out, sizeof(out), &m, disco_vec_a_pub, disco_vec_shared, nonce) == 0);
    m.type = TS_DISCO_PONG;                         /* a source of no family */
    CHECK(ts_disco_seal(out, sizeof(out), &m, disco_vec_a_pub, disco_vec_shared, nonce) == 0);
    m.type = TS_DISCO_CALL_ME_MAYBE;
    m.n_eps = TS_DISCO_EPS_MAX + 1;
    for (i = 0; i < TS_DISCO_EPS_MAX; i++) m.eps[i].family = 4;
    CHECK(ts_disco_seal(out, sizeof(out), &m, disco_vec_a_pub, disco_vec_shared, nonce) == 0);
    m.n_eps = 1;
    m.eps[0].family = 0;
    CHECK(ts_disco_seal(out, sizeof(out), &m, disco_vec_a_pub, disco_vec_shared, nonce) == 0);
    m.type = TS_DISCO_PING;
    m.padding = TS_DISCO_PLAIN_MAX;                 /* more than a box may hold */
    CHECK(ts_disco_seal(out, sizeof(out), &m, disco_vec_a_pub, disco_vec_shared, nonce) == 0);

    /* what is no disco frame */
    CHECK(!ts_disco_is(NULL, 100));
    CHECK(!ts_disco_is(disco_vecs[0].frame, TS_DISCO_HEADER_LEN - 1));
    memcpy(out, disco_vecs[0].frame, disco_vecs[0].len);
    out[0] ^= 1;
    CHECK(!ts_disco_is(out, disco_vecs[0].len));
    CHECK(!ts_disco_open(out, disco_vecs[0].len, disco_vec_shared, &m));
    /* the header and no room for a tag */
    CHECK(!ts_disco_open(disco_vecs[0].frame, TS_DISCO_HEADER_LEN + WG_BOX_TAG_LEN - 1, disco_vec_shared, &m));
    /* another pair's key */
    {
        uint8_t other[WG_BOX_KEY_LEN];
        memcpy(other, disco_vec_shared, sizeof(other));
        other[0] ^= 1;
        CHECK(!ts_disco_open(disco_vecs[0].frame, disco_vecs[0].len, other, &m));
    }
}

/* ------------------------------------------------------------------ fuzz */

static void random_msg(ts_disco_msg* m)
{
    size_t i;

    memset(m, 0, sizeof(*m));
    m->type = (ts_disco_type)(1 + rnd() % 3);
    for (i = 0; i < TS_DISCO_TXID_LEN; i++) m->txid[i] = (uint8_t)rnd();
    switch (m->type) {
    case TS_DISCO_PING:
        m->has_node_key = (int)(rnd() % 2);
        if (m->has_node_key)
            for (i = 0; i < TS_DISCO_KEY_LEN; i++) m->node_key[i] = (uint8_t)rnd();
        m->padding = rnd() % 4 == 0 ? rnd() % 200 : 0;
        break;
    case TS_DISCO_PONG:
        m->src.family = rnd() % 2 ? 4 : 6;
        for (i = 0; i < (m->src.family == 4 ? 4u : 16u); i++) m->src.addr[i] = (uint8_t)rnd();
        if (m->src.family == 6) m->src.addr[0] = 0x20;  /* not v4-mapped: it would come back IPv4 */
        m->src.port = (uint16_t)rnd();
        break;
    default:
        m->n_eps = rnd() % (TS_DISCO_EPS_MAX + 1);
        for (i = 0; i < m->n_eps; i++) {
            size_t k;
            m->eps[i].family = rnd() % 2 ? 4 : 6;
            for (k = 0; k < (m->eps[i].family == 4 ? 4u : 16u); k++) m->eps[i].addr[k] = (uint8_t)rnd();
            if (m->eps[i].family == 6) m->eps[i].addr[0] = 0x20;
            m->eps[i].port = (uint16_t)rnd();
        }
        break;
    }
}

static int same_ep(const wg_endpoint* a, const wg_endpoint* b)
{
    return a->family == b->family && a->port == b->port && memcmp(a->addr, b->addr, a->family == 4 ? 4 : 16) == 0;
}

TEST(fuzz)
{
    unsigned i;
    size_t k;

    for (i = 0; i < 100000; i++) {
        ts_disco_msg m, back;
        uint8_t nonce[WG_BOX_NONCE_LEN], frame[TS_DISCO_FRAME_MAX];
        uint8_t* f;
        size_t n;

        random_msg(&m);
        for (k = 0; k < sizeof(nonce); k++) nonce[k] = (uint8_t)rnd();
        n = ts_disco_seal(frame, sizeof(frame), &m, disco_vec_a_pub, disco_vec_shared, nonce);
        CHECK(n > 0);
        if (!n) continue;
        f = (uint8_t*)malloc(n);
        REQUIRE(f);
        memcpy(f, frame, n);
        /* back as it went */
        CHECK(ts_disco_open(f, n, disco_vec_shared, &back));
        CHECK(back.type == m.type);
        if (m.type == TS_DISCO_PING) {
            /* no key and 32 bytes of padding or more: the zeros read as no key, the padding shorter */
            size_t pad = !m.has_node_key && m.padding >= TS_DISCO_KEY_LEN ? m.padding - TS_DISCO_KEY_LEN : m.padding;
            CHECK(memcmp(back.txid, m.txid, TS_DISCO_TXID_LEN) == 0 && back.padding == pad);
            CHECK(back.has_node_key == m.has_node_key);
            if (m.has_node_key) CHECK(memcmp(back.node_key, m.node_key, TS_DISCO_KEY_LEN) == 0);
        } else if (m.type == TS_DISCO_PONG) {
            CHECK(memcmp(back.txid, m.txid, TS_DISCO_TXID_LEN) == 0 && same_ep(&back.src, &m.src));
        } else {
            CHECK(back.n_eps == m.n_eps);
            for (k = 0; k < m.n_eps && k < back.n_eps; k++) CHECK(same_ep(&back.eps[k], &m.eps[k]));
        }
        /* mutated: any byte, any bit - the box fails, or (a header byte) it is no frame */
        if (n) {
            size_t at = (size_t)(rnd() % n);
            f[at] ^= (uint8_t)(1u << (rnd() % 8));
            if (at >= TS_DISCO_MAGIC_LEN + TS_DISCO_KEY_LEN) CHECK(!ts_disco_open(f, n, disco_vec_shared, &back));
            else ts_disco_open(f, n, disco_vec_shared, &back);
        }
        /* cut anywhere */
        ts_disco_open(f, (size_t)(rnd() % (n + 1)), disco_vec_shared, &back);
        free(f);
    }
    /* random bytes behind a real header: never opens */
    for (i = 0; i < 20000; i++) {
        size_t n = TS_DISCO_HEADER_LEN + (size_t)(rnd() % 400);
        uint8_t* f = (uint8_t*)malloc(n);
        ts_disco_msg m;
        REQUIRE(f);
        memcpy(f, disco_vecs[0].frame, TS_DISCO_HEADER_LEN);
        for (k = TS_DISCO_HEADER_LEN; k < n; k++) f[k] = (uint8_t)rnd();
        CHECK(!ts_disco_open(f, n, disco_vec_shared, &m));
        free(f);
    }
}

int main(void)
{
    const char* seed = getenv("BT_FUZZ_SEED");

    if (seed) xs = strtoull(seed, NULL, 16) | 1;
    if (!wg_crypto_init()) {
        fprintf(stderr, "wg_crypto_init failed\n");
        return 1;
    }
    printf("test_ts_disco (fuzz seed %llx)\n", (unsigned long long)xs);
    RUN(keys);
    RUN(vectors_open);
    RUN(vectors_seal);
    RUN(refusals);
    RUN(fuzz);
    return t_summary("test_ts_disco");
}
