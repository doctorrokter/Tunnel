/*
 * ts_noise: the ts2021 transcript byte for byte against Tailscale's own controlbase (the vectors
 * in vectors/kat_ts_noise.h come from vectors/noise), every refusal of the handshake and of the
 * record stream, the counters at their limit, EarlyNoise, and garbage under ASan/UBSan - seeded
 * like test_fuzz: another run with BT_FUZZ_SEED=<hex>. Fed input sits in heap buffers of exactly
 * its size, so a read past it is caught.
 *
 * With --interop raw|http HOST PORT CONTROL_KEY_HEX it also talks to vectors/noise's server -
 * controlbase itself on loopback TCP - over a blocking socket (here only; the daemon never blocks).
 */

#include "test_util.h"
#include "../src/ts_noise.h"
#include "vectors/kat_ts_noise.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define WIRE_MAX 16384

static uint64_t xs = 0x6a09e667f3bcc908ULL;

static uint64_t rnd(void)
{
    xs ^= xs >> 12;
    xs ^= xs << 25;
    xs ^= xs >> 27;
    return xs * 0x2545f4914f6cdd1dULL;
}

static void key_hex(wg_key* k, const char* hex)
{
    if (t_hex(k->b, WG_KEY_LEN, hex) != WG_KEY_LEN) {
        fprintf(stderr, "bad key vector\n");
        exit(2);
    }
}

static int all_zero(const void* p, size_t len)
{
    const uint8_t* b = (const uint8_t*)p;
    size_t i;
    for (i = 0; i < len; i++)
        if (b[i]) return 0;
    return 1;
}

/* The transcript's blobs: b[i] = i * mul + add. */
static void blob(uint8_t* out, size_t len, unsigned mul, unsigned add)
{
    size_t i;
    for (i = 0; i < len; i++) out[i] = (uint8_t)(i * mul + add);
}

static void store_be32(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* ------------------------------------------------------------------ scripted randomness */

typedef struct {
    uint8_t b[64];
    size_t  len, pos;
} script;

static int script_fn(void* ctx, void* buf, size_t len)
{
    script* s = (script*)ctx;
    /* Asking for more randomness than the reference drew is a bug in itself. */
    if (s->pos + len > s->len) return 0;
    memcpy(buf, s->b + s->pos, len);
    s->pos += len;
    return 1;
}

static wg_rng script_rng(script* s, const char* hex)
{
    wg_rng r;
    s->len = t_hex(s->b, sizeof(s->b), hex);
    s->pos = 0;
    r.fn = script_fn;
    r.ctx = s;
    return r;
}

static int no_random(void* ctx, void* buf, size_t len)
{
    return 0;
}

/* ------------------------------------------------------------------ a server for the tests */

/*
 * The responder's half of the handshake, written out from controlbase's Server so the tests can
 * make any number of handshakes; responder_matches_reference holds it to the reference transcript
 * first. Its records go through ts_noise itself with the keys swapped (srv_view).
 */
typedef struct {
    wg_key   control_private, control_public;
    wg_key   machine_public;                /* learned from the initiation */
    unsigned version;
    uint8_t  c2s[WG_KEY_LEN], s2c[WG_KEY_LEN];
    uint8_t  hash[WG_HASH_LEN];
} srv;

static int s_mix_hash(uint8_t h[WG_HASH_LEN], const void* in, size_t len)
{
    return wg_hash2(h, h, WG_HASH_LEN, in, len);
}

static int s_mix_dh(uint8_t ck[WG_HASH_LEN], uint8_t* k, const wg_key* sk, const wg_key* pk)
{
    uint8_t dh[WG_KEY_LEN];
    int ok = wg_dh(sk, pk, dh) && wg_kdf(ck, k, NULL, ck, dh, sizeof(dh));
    wg_wipe(dh, sizeof(dh));
    return ok;
}

static void srv_init(srv* s, const wg_key* control_private)
{
    memset(s, 0, sizeof(*s));
    if (control_private) {
        s->control_private = *control_private;
        CHECK(wg_key_public(&s->control_private, &s->control_public));
    } else {
        CHECK(wg_key_generate(&s->control_private, &s->control_public));
    }
}

static int srv_respond(srv* s, const uint8_t init[TS_NOISE_INIT_LEN], const wg_rng* rng,
                       uint8_t resp[TS_NOISE_RESP_LEN])
{
    static const uint8_t zero[12];
    uint8_t h[WG_HASH_LEN], ck[WG_HASH_LEN], k[WG_KEY_LEN], dummy[1];
    char pro[64];
    wg_key re, e, e_pub;
    int plen;

    if (init[2] != TS_NOISE_MSG_INITIATION || init[3] != 0 || init[4] != TS_NOISE_INIT_PAYLOAD_LEN) return 0;
    s->version = ((unsigned)init[0] << 8) | init[1];
    plen = snprintf(pro, sizeof(pro), "Tailscale Control Protocol v%u", s->version);
    if (!wg_hash(h, "Noise_IK_25519_ChaChaPoly_BLAKE2s", 33)) return 0;
    memcpy(ck, h, sizeof(ck));
    if (!s_mix_hash(h, pro, (size_t)plen) || !s_mix_hash(h, s->control_public.b, WG_KEY_LEN)) return 0;

    memcpy(re.b, init + TS_NOISE_INIT_OFF_EPHEMERAL, WG_KEY_LEN);
    if (!s_mix_hash(h, re.b, WG_KEY_LEN)) return 0;
    if (!s_mix_dh(ck, k, &s->control_private, &re)) return 0;                          /* es */
    if (!wg_aead_decrypt_n(s->machine_public.b, k, zero, init + TS_NOISE_INIT_OFF_MACHINE,
                           WG_KEY_LEN + WG_TAG_LEN, h, WG_HASH_LEN)) return 0;
    if (!s_mix_hash(h, init + TS_NOISE_INIT_OFF_MACHINE, WG_KEY_LEN + WG_TAG_LEN)) return 0;
    if (!s_mix_dh(ck, k, &s->control_private, &s->machine_public)) return 0;           /* ss */
    if (!wg_aead_decrypt_n(dummy, k, zero, init + TS_NOISE_INIT_OFF_TAG, WG_TAG_LEN, h, WG_HASH_LEN)) return 0;
    if (!s_mix_hash(h, init + TS_NOISE_INIT_OFF_TAG, WG_TAG_LEN)) return 0;

    if (!wg_key_generate_rng(rng, &e, &e_pub)) return 0;
    resp[0] = TS_NOISE_MSG_RESPONSE;
    resp[1] = 0;
    resp[2] = TS_NOISE_RESP_PAYLOAD_LEN;
    memcpy(resp + TS_NOISE_RESP_OFF_EPHEMERAL, e_pub.b, WG_KEY_LEN);
    if (!s_mix_hash(h, e_pub.b, WG_KEY_LEN)) return 0;
    if (!s_mix_dh(ck, NULL, &e, &re)) return 0;                                        /* ee */
    if (!s_mix_dh(ck, k, &e, &s->machine_public)) return 0;                            /* se */
    if (!wg_aead_encrypt_n(resp + TS_NOISE_RESP_OFF_TAG, k, zero, NULL, 0, h, WG_HASH_LEN)) return 0;
    if (!s_mix_hash(h, resp + TS_NOISE_RESP_OFF_TAG, WG_TAG_LEN)) return 0;
    if (!wg_kdf(s->c2s, s->s2c, NULL, ck, NULL, 0)) return 0;
    memcpy(s->hash, h, WG_HASH_LEN);
    return 1;
}

/* The server's end of the record stream: ts_noise itself, OPEN, with the keys swapped. */
static void srv_view(const srv* s, ts_noise* v)
{
    memset(v, 0, sizeof(*v));
    v->state = TS_NOISE_OPEN;
    memcpy(v->tx_key, s->s2c, WG_KEY_LEN);
    memcpy(v->rx_key, s->c2s, WG_KEY_LEN);
}

/* ------------------------------------------------------------------ driving the stream */

/*
 * Feeds `len` bytes in pieces of `step` bytes (0: random pieces of 1-600), each piece in a heap
 * buffer of exactly its size, and collects the plaintext. Returns 0 at the first refusal, with
 * *out_len holding what came before it.
 */
static int feed(ts_noise* n, const uint8_t* in, size_t len, size_t step, uint8_t* out, size_t cap,
                size_t* out_len)
{
    size_t off = 0;

    *out_len = 0;
    while (off < len) {
        size_t piece = step ? step : 1 + (size_t)(rnd() % 600), pos = 0;
        uint8_t* p;

        if (piece > len - off) piece = len - off;
        p = (uint8_t*)malloc(piece);
        memcpy(p, in + off, piece);
        while (pos < piece) {
            const uint8_t* pt;
            size_t pt_len, used;

            if (!ts_noise_receive(n, p + pos, piece - pos, &used, &pt, &pt_len)) {
                free(p);
                return 0;
            }
            if (!used || used > piece - pos || *out_len + pt_len > cap) {
                CHECK(!"feed: no progress, or more than was given");
                free(p);
                return 0;
            }
            pos += used;
            if (pt_len) memcpy(out + *out_len, pt, pt_len);
            *out_len += pt_len;
        }
        free(p);
        off += piece;
    }
    return 1;
}

/* Seals everything, `room` bytes of output per call (so `room` bounds the record size). */
static int seal_all(ts_noise* n, const uint8_t* in, size_t len, size_t room, uint8_t* out, size_t cap,
                    size_t* out_len)
{
    size_t off = 0;

    *out_len = 0;
    while (off < len) {
        size_t used, made, r = room < cap - *out_len ? room : cap - *out_len;
        if (!ts_noise_seal(n, in + off, len - off, &used, out + *out_len, r, &made)) return 0;
        if (!used) return 0;
        off += used;
        *out_len += made;
    }
    return 1;
}

/* The KAT client: initialized and its initiation made, in SENT. */
static int kat_client(ts_noise* n, script* s, const char* eph, unsigned version)
{
    wg_key msk, cpk;
    wg_rng rng = script_rng(s, eph);
    uint8_t init[TS_NOISE_INIT_LEN];

    key_hex(&msk, KAT_TS_MACHINE_PRIVATE);
    key_hex(&cpk, KAT_TS_CONTROL_PUBLIC);
    return ts_noise_init(n, &msk, &cpk, (uint16_t)version, &rng) && ts_noise_initiation(n, init);
}

/* What the server of the main transcript wrote after the handshake, as plaintext. */
static size_t kat_s2c_plain(uint8_t* out)
{
    size_t json = strlen(KAT_TS_MAIN_EARLY_JSON), n = 0;
    static const uint8_t settings[9] = { 0, 0, 0, 4, 0, 0, 0, 0, 0 };

    memcpy(out, "\xff\xff\xff" "TS", 5);
    store_be32(out + 5, (uint32_t)json);
    n = 9;
    memcpy(out + n, KAT_TS_MAIN_EARLY_JSON, json);
    n += json;
    memcpy(out + n, settings, sizeof(settings));
    n += sizeof(settings);
    blob(out + n, KAT_TS_S2C_BLOB_LEN, KAT_TS_S2C_BLOB_MUL, KAT_TS_S2C_BLOB_ADD);
    return n + KAT_TS_S2C_BLOB_LEN;
}

/* ------------------------------------------------------------------ the reference transcripts */

TEST(kat_main_transcript)
{
    static uint8_t wire[WIRE_MAX], plain[WIRE_MAX], want[WIRE_MAX], sealed[WIRE_MAX];
    script s;
    wg_key msk, mpk, cpk;
    wg_rng rng;
    ts_noise n;
    uint8_t init[TS_NOISE_INIT_LEN], k[WG_KEY_LEN];
    size_t wlen, plen, wantlen, slen, used, made, c2s_len;
    uint32_t json;

    key_hex(&msk, KAT_TS_MACHINE_PRIVATE);
    key_hex(&mpk, KAT_TS_MACHINE_PUBLIC);
    key_hex(&cpk, KAT_TS_CONTROL_PUBLIC);
    rng = script_rng(&s, KAT_TS_MAIN_CLIENT_EPH);

    REQUIRE(ts_noise_init(&n, &msk, &cpk, KAT_TS_MAIN_VERSION, &rng));
    CHECK(n.state == TS_NOISE_READY);
    CHECK_MEM(n.machine_public.b, mpk.b, WG_KEY_LEN);

    /* The initiation, byte for byte - and exactly one ephemeral drawn for it. */
    REQUIRE(ts_noise_initiation(&n, init));
    CHECK(n.state == TS_NOISE_SENT);
    CHECK(s.pos == WG_KEY_LEN && s.len == WG_KEY_LEN);
    CHECK(t_hex(want, sizeof(want), KAT_TS_MAIN_INIT) == TS_NOISE_INIT_LEN);
    CHECK_MEM(init, want, TS_NOISE_INIT_LEN);

    /* The server's stream in one piece: the response, then six records (the blob took two). */
    wlen = t_hex(wire, sizeof(wire), KAT_TS_MAIN_S2C_WIRE);
    wantlen = kat_s2c_plain(want);
    CHECK(feed(&n, wire, wlen, wlen, plain, sizeof(plain), &plen));
    REQUIRE(n.state == TS_NOISE_OPEN);
    CHECK(plen == wantlen && memcmp(plain, want, wantlen) == 0);
    CHECK(n.rx_counter == KAT_TS_MAIN_S2C_WRITES + 1);
    CHECK(n.rx_len == 0 && n.rx_need == 0);

    t_hex(k, sizeof(k), KAT_TS_MAIN_HASH);
    CHECK_MEM(n.hash, k, WG_HASH_LEN);
    t_hex(k, sizeof(k), KAT_TS_MAIN_TX_KEY);
    CHECK_MEM(n.tx_key, k, WG_KEY_LEN);
    t_hex(k, sizeof(k), KAT_TS_MAIN_RX_KEY);
    CHECK_MEM(n.rx_key, k, WG_KEY_LEN);

    /* The handshake's secrets are gone once it is done. */
    CHECK(all_zero(&n.machine_private, sizeof(n.machine_private)));
    CHECK(all_zero(&n.ephemeral_private, sizeof(n.ephemeral_private)));
    CHECK(all_zero(n.chaining_key, sizeof(n.chaining_key)));

    /* EarlyNoise at the start of the plaintext, HTTP/2 right after its JSON. */
    CHECK(ts_noise_early(plain, plen, &json) == TS_EARLY_FOUND);
    CHECK(json == strlen(KAT_TS_MAIN_EARLY_JSON));
    CHECK(plen > TS_EARLY_HEADER_LEN + json && memcmp(plain + TS_EARLY_HEADER_LEN, KAT_TS_MAIN_EARLY_JSON, json) == 0);
    CHECK(ts_noise_early(plain + TS_EARLY_HEADER_LEN + json, plen - TS_EARLY_HEADER_LEN - json, &json) == TS_EARLY_NONE);

    /* The client's writes, each sealed as one call: the records controlbase made, byte for byte. */
    c2s_len = t_hex(wire, sizeof(wire), KAT_TS_MAIN_C2S_WIRE);
    slen = 0;
    CHECK(ts_noise_seal(&n, (const uint8_t*)KAT_TS_MAIN_C2S_PREFACE, strlen(KAT_TS_MAIN_C2S_PREFACE), &used,
                        sealed, sizeof(sealed), &made));
    CHECK(used == strlen(KAT_TS_MAIN_C2S_PREFACE) && made == used + TS_NOISE_RECORD_OVERHEAD);
    slen += made;
    blob(plain, KAT_TS_C2S_BLOB_LEN, KAT_TS_C2S_BLOB_MUL, KAT_TS_C2S_BLOB_ADD);
    CHECK(ts_noise_seal(&n, plain, KAT_TS_C2S_BLOB_LEN, &used, sealed + slen, sizeof(sealed) - slen, &made));
    CHECK(used == KAT_TS_C2S_BLOB_LEN && made == ts_noise_sealed_len(KAT_TS_C2S_BLOB_LEN));
    slen += made;
    CHECK(slen == c2s_len);
    CHECK_MEM(sealed, wire, c2s_len);
    CHECK(n.tx_counter == 3);
}

/* The same stream cut everywhere: the header and body of every message, split at every byte. */
TEST(kat_main_any_split)
{
    static uint8_t wire[WIRE_MAX], plain[WIRE_MAX], want[WIRE_MAX];
    static ts_noise sent, n;
    script s;
    size_t wlen, wantlen, split, plen, plen2, bad = 0, steps[] = { 1, 2, 3, 50, 51, 52, 4095, 4096, 4097, 0 };
    unsigned i;

    REQUIRE(kat_client(&sent, &s, KAT_TS_MAIN_CLIENT_EPH, KAT_TS_MAIN_VERSION));
    wlen = t_hex(wire, sizeof(wire), KAT_TS_MAIN_S2C_WIRE);
    wantlen = kat_s2c_plain(want);

    for (split = 0; split <= wlen; split++) {
        n = sent;
        if (!feed(&n, wire, split, split ? split : 1, plain, sizeof(plain), &plen) ||
            !feed(&n, wire + split, wlen - split, wlen - split ? wlen - split : 1, plain + plen,
                  sizeof(plain) - plen, &plen2) ||
            plen + plen2 != wantlen || memcmp(plain, want, wantlen) != 0 || n.state != TS_NOISE_OPEN)
            bad++;
    }
    CHECK(bad == 0);

    /* Fixed and random piece sizes. */
    for (i = 0; i < sizeof(steps) / sizeof(steps[0]); i++) {
        int round;
        for (round = 0; round < (steps[i] ? 1 : 50); round++) {
            n = sent;
            CHECK(feed(&n, wire, wlen, steps[i], plain, sizeof(plain), &plen));
            CHECK(plen == wantlen && memcmp(plain, want, wantlen) == 0);
        }
    }
}

static void check_version(const char* eph, unsigned version, const char* init_hex, const char* resp_hex,
                          const char* hash_hex)
{
    script s;
    ts_noise n;
    uint8_t want[TS_NOISE_INIT_LEN], resp[TS_NOISE_RESP_LEN], hash[WG_HASH_LEN], plain[16];
    size_t plen;
    wg_key msk, cpk;
    wg_rng rng = script_rng(&s, eph);
    uint8_t init[TS_NOISE_INIT_LEN];

    key_hex(&msk, KAT_TS_MACHINE_PRIVATE);
    key_hex(&cpk, KAT_TS_CONTROL_PUBLIC);
    REQUIRE(ts_noise_init(&n, &msk, &cpk, (uint16_t)version, &rng));
    REQUIRE(ts_noise_initiation(&n, init));
    CHECK(t_hex(want, sizeof(want), init_hex) == TS_NOISE_INIT_LEN);
    CHECK_MEM(init, want, TS_NOISE_INIT_LEN);
    CHECK(t_hex(resp, sizeof(resp), resp_hex) == TS_NOISE_RESP_LEN);
    CHECK(feed(&n, resp, sizeof(resp), 7, plain, sizeof(plain), &plen) && plen == 0);
    CHECK(n.state == TS_NOISE_OPEN);
    t_hex(hash, sizeof(hash), hash_hex);
    CHECK_MEM(n.hash, hash, WG_HASH_LEN);
}

/* The prologue spells the version in decimal: 1 digit, 3 (above), 5. */
TEST(kat_versions)
{
    check_version(KAT_TS_V1_CLIENT_EPH, KAT_TS_V1_VERSION, KAT_TS_V1_INIT, KAT_TS_V1_RESP, KAT_TS_V1_HASH);
    check_version(KAT_TS_V65535_CLIENT_EPH, KAT_TS_V65535_VERSION, KAT_TS_V65535_INIT, KAT_TS_V65535_RESP,
                  KAT_TS_V65535_HASH);
}

/* Records at far counters: the nonce's byte order, an empty record, the last counter allowed. */
TEST(kat_far_records)
{
    size_t i;

    for (i = 0; i < sizeof(KAT_TS_RECORDS) / sizeof(KAT_TS_RECORDS[0]); i++) {
        const kat_ts_record* r = &KAT_TS_RECORDS[i];
        ts_noise tx, rx;
        uint8_t k[WG_KEY_LEN], wire[256], out[256], got[256];
        size_t wlen = t_hex(wire, sizeof(wire), r->wire), ptlen = strlen(r->pt), used, made, glen;

        t_hex(k, sizeof(k), r->to_server ? KAT_TS_MAIN_TX_KEY : KAT_TS_MAIN_RX_KEY);
        memset(&tx, 0, sizeof(tx));
        memset(&rx, 0, sizeof(rx));
        tx.state = rx.state = TS_NOISE_OPEN;
        memcpy(tx.tx_key, k, WG_KEY_LEN);
        memcpy(rx.rx_key, k, WG_KEY_LEN);
        tx.tx_counter = rx.rx_counter = r->counter;

        if (ptlen) {
            CHECK(ts_noise_seal(&tx, (const uint8_t*)r->pt, ptlen, &used, out, sizeof(out), &made));
            CHECK(used == ptlen && made == wlen);
            CHECK_MEM(out, wire, wlen);
            CHECK(tx.tx_counter == r->counter + 1);
        }
        CHECK(feed(&rx, wire, wlen, wlen, got, sizeof(got), &glen));
        CHECK(glen == ptlen && memcmp(got, r->pt, ptlen) == 0);
        CHECK(rx.rx_counter == r->counter + 1);

        /* Past the last counter, nothing more either way. */
        if (r->counter == TS_NOISE_COUNTER_LIMIT - 1) {
            CHECK(tx.tx_counter == TS_NOISE_COUNTER_LIMIT || !ptlen);
            if (ptlen) {
                CHECK(!ts_noise_seal(&tx, (const uint8_t*)"x", 1, &used, out, sizeof(out), &made));
                CHECK(tx.err == TS_NOISE_ERR_EXHAUSTED && made == 0);
            }
            CHECK(!feed(&rx, wire, wlen, wlen, got, sizeof(got), &glen));
            CHECK(rx.err == TS_NOISE_ERR_EXHAUSTED && glen == 0);
        }
    }
}

/* The test server reproduces the reference's response: it may stand in for controlbase below. */
TEST(responder_matches_reference)
{
    script cs, ss;
    ts_noise n;
    srv s;
    wg_key csk, mpk;
    wg_rng rng;
    uint8_t init[TS_NOISE_INIT_LEN], resp[TS_NOISE_RESP_LEN], want[TS_NOISE_RESP_LEN], k[WG_KEY_LEN];

    key_hex(&csk, KAT_TS_CONTROL_PRIVATE);
    key_hex(&mpk, KAT_TS_MACHINE_PUBLIC);
    srv_init(&s, &csk);
    REQUIRE(kat_client(&n, &cs, KAT_TS_MAIN_CLIENT_EPH, KAT_TS_MAIN_VERSION));
    t_hex(init, sizeof(init), KAT_TS_MAIN_INIT);
    rng = script_rng(&ss, KAT_TS_MAIN_SERVER_EPH);
    REQUIRE(srv_respond(&s, init, &rng, resp));
    t_hex(want, sizeof(want), KAT_TS_MAIN_RESP);
    CHECK_MEM(resp, want, TS_NOISE_RESP_LEN);
    CHECK_MEM(s.machine_public.b, mpk.b, WG_KEY_LEN);
    CHECK(s.version == KAT_TS_MAIN_VERSION);
    t_hex(k, sizeof(k), KAT_TS_MAIN_TX_KEY);
    CHECK_MEM(s.c2s, k, WG_KEY_LEN);
    t_hex(k, sizeof(k), KAT_TS_MAIN_RX_KEY);
    CHECK_MEM(s.s2c, k, WG_KEY_LEN);
    t_hex(k, sizeof(k), KAT_TS_MAIN_HASH);
    CHECK_MEM(s.hash, k, WG_HASH_LEN);
}

/* ------------------------------------------------------------------ handshakes in memory */

/* A fresh pair: the client OPEN after the test server's response, the server's view of it. */
static int pair(ts_noise* c, ts_noise* sv, srv* s, uint16_t version)
{
    wg_key msk, mpk;
    uint8_t init[TS_NOISE_INIT_LEN], resp[TS_NOISE_RESP_LEN], plain[4];
    size_t plen;

    srv_init(s, NULL);
    if (!wg_key_generate(&msk, &mpk)) return 0;
    if (!ts_noise_init(c, &msk, &s->control_public, version, NULL) || !ts_noise_initiation(c, init)) return 0;
    if (!srv_respond(s, init, NULL, resp)) return 0;
    if (memcmp(s->machine_public.b, mpk.b, WG_KEY_LEN) != 0 || s->version != version) return 0;
    if (!feed(c, resp, sizeof(resp), sizeof(resp), plain, sizeof(plain), &plen) || plen) return 0;
    srv_view(s, sv);
    return c->state == TS_NOISE_OPEN && memcmp(c->hash, s->hash, WG_HASH_LEN) == 0;
}

TEST(handshake_and_big_data)
{
    static uint8_t data[200000], wire[300000], got[200000];
    static ts_noise c, sv;
    srv s;
    size_t i, wlen, glen;
    int round;

    for (i = 0; i < sizeof(data); i++) data[i] = (uint8_t)rnd();
    for (round = 0; round < 4; round++) {
        size_t len = 1 + (size_t)(rnd() % sizeof(data));
        size_t room = round == 0 ? sizeof(wire) : 200 + (size_t)(rnd() % 9000);

        REQUIRE(pair(&c, &sv, &s, (uint16_t)rnd()));
        CHECK(memcmp(c.tx_key, s.c2s, WG_KEY_LEN) == 0 && memcmp(c.rx_key, s.s2c, WG_KEY_LEN) == 0);

        /* client -> server, then back: many records, cut by the room given to each seal */
        CHECK(seal_all(&c, data, len, room, wire, sizeof(wire), &wlen));
        if (round == 0) CHECK(wlen == ts_noise_sealed_len(len));
        CHECK(feed(&sv, wire, wlen, 0, got, sizeof(got), &glen));
        CHECK(glen == len && memcmp(got, data, len) == 0);
        CHECK(c.tx_counter == sv.rx_counter);

        CHECK(seal_all(&sv, data, len, room, wire, sizeof(wire), &wlen));
        CHECK(feed(&c, wire, wlen, 0, got, sizeof(got), &glen));
        CHECK(glen == len && memcmp(got, data, len) == 0);
        CHECK(sv.tx_counter == c.rx_counter);
    }
}

TEST(empty_and_max_records)
{
    static ts_noise c, sv;
    srv s;
    uint8_t rec[TS_NOISE_MAX_RECORD + 64], data[TS_NOISE_MAX_PLAINTEXT + 1], nonce[12] = { 0 }, got[8192];
    size_t used, made, glen;

    REQUIRE(pair(&c, &sv, &s, 130));

    /* An empty record (controlbase allows them, and its Read skips them): 16 bytes of tag. */
    rec[0] = TS_NOISE_MSG_RECORD;
    rec[1] = 0;
    rec[2] = WG_TAG_LEN;
    REQUIRE(wg_aead_encrypt_n(rec + 3, s.s2c, nonce, NULL, 0, NULL, 0));
    CHECK(feed(&c, rec, 3 + WG_TAG_LEN, 3 + WG_TAG_LEN, got, sizeof(got), &glen) && glen == 0);
    CHECK(c.rx_counter == 1 && c.state == TS_NOISE_OPEN);
    sv.tx_counter = 1;

    /* The largest record: 4096 bytes on the wire, 4077 of plaintext. */
    memset(data, 0x5a, sizeof(data));
    CHECK(ts_noise_seal(&sv, data, sizeof(data), &used, rec, TS_NOISE_MAX_RECORD, &made));
    CHECK(used == TS_NOISE_MAX_PLAINTEXT);
    CHECK(made == TS_NOISE_MAX_RECORD && rec[1] == 0x0f && rec[2] == 0xfd);
    CHECK(feed(&c, rec, made, 1000, got, sizeof(got), &glen) && glen == TS_NOISE_MAX_PLAINTEXT);
    CHECK(memcmp(got, data, glen) == 0);
}

TEST(seal_limits)
{
    static ts_noise c, sv;
    srv s;
    static uint8_t data[10000], out[20000];
    size_t used, made;

    REQUIRE(pair(&c, &sv, &s, 130));
    memset(data, 0x42, sizeof(data));

    /* No room for a one-byte record: nothing taken, nothing written, not a failure. */
    memset(out, 0xee, sizeof(out));
    CHECK(ts_noise_seal(&c, data, 5, &used, out, TS_NOISE_RECORD_OVERHEAD, &made));
    CHECK(used == 0 && made == 0 && out[0] == 0xee && c.tx_counter == 0);
    CHECK(ts_noise_seal(&c, data, 0, &used, out, sizeof(out), &made) && used == 0 && made == 0);

    /* Room for exactly one byte. */
    CHECK(ts_noise_seal(&c, data, 5, &used, out, TS_NOISE_RECORD_OVERHEAD + 1, &made));
    CHECK(used == 1 && made == 20 && c.tx_counter == 1);

    /* Plenty of room: records of 4077, 4077, 1846 - controlbase's cut. */
    CHECK(ts_noise_seal(&c, data, sizeof(data), &used, out, sizeof(out), &made));
    CHECK(used == sizeof(data) && made == sizeof(data) + 3 * TS_NOISE_RECORD_OVERHEAD);
    CHECK(out[0] == 4 && out[1] == 0x0f && out[2] == 0xfd);
    CHECK(out[4096] == 4 && out[4097] == 0x0f && out[4098] == 0xfd);
    CHECK(out[8192] == 4 && ((out[8193] << 8) | out[8194]) == 1846 + WG_TAG_LEN);
    CHECK(c.tx_counter == 4);

    /* The room ends mid-way: one full record, then what fits. */
    CHECK(ts_noise_seal(&c, data, sizeof(data), &used, out, 5000, &made));
    CHECK(used == TS_NOISE_MAX_PLAINTEXT + (5000 - TS_NOISE_MAX_RECORD - TS_NOISE_RECORD_OVERHEAD));
    CHECK(made == 5000);
    CHECK(ts_noise_seal(&c, data, sizeof(data), &used, out, TS_NOISE_MAX_RECORD + 10, &made));
    CHECK(used == TS_NOISE_MAX_PLAINTEXT && made == TS_NOISE_MAX_RECORD);

    CHECK(ts_noise_sealed_len(0) == 0);
    CHECK(ts_noise_sealed_len(1) == 20);
    CHECK(ts_noise_sealed_len(TS_NOISE_MAX_PLAINTEXT) == TS_NOISE_MAX_RECORD);
    CHECK(ts_noise_sealed_len(TS_NOISE_MAX_PLAINTEXT + 1) == TS_NOISE_MAX_PLAINTEXT + 1 + 2 * 19);
}

/* ------------------------------------------------------------------ refusals */

/* Every byte of the response is checked: the header exactly, the rest by the tag. */
TEST(response_tampering)
{
    static ts_noise sent, n;
    script s;
    uint8_t resp[TS_NOISE_RESP_LEN], bad[TS_NOISE_RESP_LEN], out[64];
    size_t i, olen;
    int bit, refused = 0, tries = 0, wiped = 0;

    REQUIRE(kat_client(&sent, &s, KAT_TS_MAIN_CLIENT_EPH, KAT_TS_MAIN_VERSION));
    t_hex(resp, sizeof(resp), KAT_TS_MAIN_RESP);

    for (i = 0; i < TS_NOISE_RESP_LEN; i++) {
        for (bit = 0; bit < 8; bit++) {
            memcpy(bad, resp, sizeof(bad));
            bad[i] ^= (uint8_t)(1u << bit);
            n = sent;
            tries++;
            /* (type 2 -> 3 makes it the server's error message, 48 bytes of "text": refused too) */
            if (!feed(&n, bad, sizeof(bad), sizeof(bad), out, sizeof(out), &olen) && olen == 0) refused++;
            if (n.state == TS_NOISE_DEAD && all_zero(n.tx_key, WG_KEY_LEN) && all_zero(n.rx_key, WG_KEY_LEN) &&
                all_zero(&n.machine_private, sizeof(n.machine_private)) &&
                all_zero(&n.ephemeral_private, sizeof(n.ephemeral_private)))
                wiped++;
            if (i == 1 || i == 2) CHECK(n.err == TS_NOISE_ERR_LENGTH);
            if (i >= TS_NOISE_RESP_OFF_TAG) CHECK(n.err == TS_NOISE_ERR_AUTH);
        }
    }
    CHECK(refused == tries);
    CHECK(wiped == tries);

    /* The genuine one still works on a fresh copy. */
    n = sent;
    CHECK(feed(&n, resp, sizeof(resp), 1, out, sizeof(out), &olen) && n.state == TS_NOISE_OPEN);
}

TEST(wrong_keys)
{
    ts_noise c, other;
    srv s, t;
    wg_key msk, mpk;
    uint8_t init[TS_NOISE_INIT_LEN], resp[TS_NOISE_RESP_LEN], out[8];
    size_t olen;

    /* We believe the server's key is t's: s cannot open our machine key. */
    srv_init(&s, NULL);
    srv_init(&t, NULL);
    REQUIRE(wg_key_generate(&msk, &mpk));
    REQUIRE(ts_noise_init(&c, &msk, &t.control_public, 130, NULL) && ts_noise_initiation(&c, init));
    CHECK(!srv_respond(&s, init, NULL, resp));

    /* A response made for another client's initiation. */
    REQUIRE(ts_noise_init(&c, &msk, &s.control_public, 130, NULL) && ts_noise_initiation(&c, init));
    REQUIRE(ts_noise_init(&other, &msk, &s.control_public, 130, NULL) && ts_noise_initiation(&other, init));
    REQUIRE(srv_respond(&s, init, NULL, resp));
    CHECK(!feed(&c, resp, sizeof(resp), sizeof(resp), out, sizeof(out), &olen));
    CHECK(c.err == TS_NOISE_ERR_AUTH && c.state == TS_NOISE_DEAD);
    CHECK(feed(&other, resp, sizeof(resp), sizeof(resp), out, sizeof(out), &olen) && other.state == TS_NOISE_OPEN);

    /* The version in the clear header is bound by the prologue: changed, nothing opens. */
    REQUIRE(ts_noise_init(&c, &msk, &s.control_public, 130, NULL) && ts_noise_initiation(&c, init));
    init[1] ^= 1;
    CHECK(!srv_respond(&s, init, NULL, resp));
}

static void error_case(const uint8_t* msg, size_t len, size_t step, const char* want_text, size_t want_used)
{
    static ts_noise n;
    script s;
    size_t off = 0, used = 0;
    const uint8_t* pt;
    size_t pt_len;
    int ok = 1;

    REQUIRE(kat_client(&n, &s, KAT_TS_MAIN_CLIENT_EPH, KAT_TS_MAIN_VERSION));
    while (ok && off < len) {
        size_t piece = step < len - off ? step : len - off;
        ok = ts_noise_receive(&n, msg + off, piece, &used, &pt, &pt_len);
        off += used;
    }
    CHECK(!ok);
    CHECK(n.state == TS_NOISE_DEAD && n.err == TS_NOISE_ERR_SERVER);
    CHECK(strcmp(n.err_text, want_text) == 0);
    CHECK(off == want_used);
}

TEST(server_error_message)
{
    static const char text[] = "unexpected handshake message type";
    uint8_t msg[512];
    char want[TS_NOISE_ERR_TEXT_MAX + 1];
    size_t i, len = strlen(text);

    /* What controlbase's sendErr writes: type 3, the length, the text. */
    msg[0] = TS_NOISE_MSG_ERROR;
    msg[1] = 0;
    msg[2] = (uint8_t)len;
    memcpy(msg + 3, text, len);
    error_case(msg, 3 + len, 3 + len, text, 3 + len);
    error_case(msg, 3 + len, 1, text, 3 + len);

    /* The text is unauthenticated: made printable for the log. */
    memcpy(msg + 3, "bad\n\x01\x7f\xff" "name", 11);
    msg[2] = 11;
    error_case(msg, 14, 5, "bad????name", 14);

    /* Empty. */
    msg[2] = 0;
    error_case(msg, 3, 1, "", 3);

    /* Long: only what the log keeps is read, the rest is never touched. */
    msg[1] = 0x01;
    msg[2] = 0x2c;                                  /* 300 */
    for (i = 0; i < 300; i++) msg[3 + i] = (uint8_t)('a' + i % 26);
    for (i = 0; i < TS_NOISE_ERR_TEXT_MAX; i++) want[i] = (char)('a' + i % 26);
    want[TS_NOISE_ERR_TEXT_MAX] = '\0';
    error_case(msg, 303, 303, want, 3 + TS_NOISE_ERR_TEXT_MAX);
}

static void header_case(const ts_noise* from, uint8_t type, unsigned length, ts_noise_error want)
{
    static ts_noise n;
    uint8_t hdr[3];
    const uint8_t* pt;
    size_t used, pt_len;

    n = *from;
    hdr[0] = type;
    hdr[1] = (uint8_t)(length >> 8);
    hdr[2] = (uint8_t)length;
    /* Refused on the header alone, before a byte of the body. */
    CHECK(!ts_noise_receive(&n, hdr, 3, &used, &pt, &pt_len));
    CHECK(n.state == TS_NOISE_DEAD && n.err == want && pt_len == 0);
}

TEST(bad_headers)
{
    static ts_noise sent, opened, sv;
    script s;
    srv server;
    uint8_t hdr[2] = { TS_NOISE_MSG_RECORD, 0x10 };
    const uint8_t* pt;
    size_t used, pt_len;

    /* Before the response: only a response (of exactly 48) or an error. */
    REQUIRE(kat_client(&sent, &s, KAT_TS_MAIN_CLIENT_EPH, KAT_TS_MAIN_VERSION));
    header_case(&sent, 0, 48, TS_NOISE_ERR_TYPE);
    header_case(&sent, TS_NOISE_MSG_INITIATION, 48, TS_NOISE_ERR_TYPE);
    header_case(&sent, TS_NOISE_MSG_RECORD, 48, TS_NOISE_ERR_TYPE);
    header_case(&sent, 5, 48, TS_NOISE_ERR_TYPE);
    header_case(&sent, 0xff, 48, TS_NOISE_ERR_TYPE);
    header_case(&sent, TS_NOISE_MSG_RESPONSE, 0, TS_NOISE_ERR_LENGTH);
    header_case(&sent, TS_NOISE_MSG_RESPONSE, 47, TS_NOISE_ERR_LENGTH);
    header_case(&sent, TS_NOISE_MSG_RESPONSE, 49, TS_NOISE_ERR_LENGTH);
    header_case(&sent, TS_NOISE_MSG_RESPONSE, 0xffff, TS_NOISE_ERR_LENGTH);

    /* After it: only records, 16 to 4093 bytes of ciphertext. */
    REQUIRE(pair(&opened, &sv, &server, 130));
    header_case(&opened, TS_NOISE_MSG_RESPONSE, 48, TS_NOISE_ERR_TYPE);
    header_case(&opened, TS_NOISE_MSG_ERROR, 5, TS_NOISE_ERR_TYPE);
    header_case(&opened, TS_NOISE_MSG_INITIATION, 96, TS_NOISE_ERR_TYPE);
    header_case(&opened, 0, 16, TS_NOISE_ERR_TYPE);
    header_case(&opened, TS_NOISE_MSG_RECORD, 0, TS_NOISE_ERR_LENGTH);
    header_case(&opened, TS_NOISE_MSG_RECORD, WG_TAG_LEN - 1, TS_NOISE_ERR_LENGTH);
    header_case(&opened, TS_NOISE_MSG_RECORD, TS_NOISE_MAX_CIPHERTEXT + 1, TS_NOISE_ERR_LENGTH);
    header_case(&opened, TS_NOISE_MSG_RECORD, 0xffff, TS_NOISE_ERR_LENGTH);

    /* Half a header is no verdict yet: it waits. */
    sv = opened;
    CHECK(ts_noise_receive(&sv, hdr, 2, &used, &pt, &pt_len));
    CHECK(used == 2 && pt_len == 0 && sv.rx_len == 2 && sv.state == TS_NOISE_OPEN);
}

TEST(record_tampering)
{
    static ts_noise c, sv, n;
    static uint8_t wire[4 * TS_NOISE_MAX_RECORD], twice[8 * TS_NOISE_MAX_RECORD], got[8 * TS_NOISE_MAX_RECORD];
    srv s;
    uint8_t data[100];
    size_t wlen, glen, i, first;
    int refused = 0, tries = 0;

    REQUIRE(pair(&c, &sv, &s, 130));
    for (i = 0; i < sizeof(data); i++) data[i] = (uint8_t)i;
    /* two records: 60 and 40 bytes */
    REQUIRE(seal_all(&sv, data, sizeof(data), 60 + TS_NOISE_RECORD_OVERHEAD, wire, sizeof(wire), &wlen));
    REQUIRE(wlen == sizeof(data) + 2 * TS_NOISE_RECORD_OVERHEAD);
    first = 60 + TS_NOISE_RECORD_OVERHEAD;

    /* Any bit of either record: the records before it arrive, nothing from it on. A length made
     * longer just waits for bytes that never come - no verdict yet, and no data either. */
    for (i = 0; i < wlen; i++) {
        size_t before = i < first ? 0 : 60;
        int bit;
        for (bit = 0; bit < 8; bit++) {
            n = c;
            wire[i] ^= (uint8_t)(1u << bit);
            tries++;
            if (!feed(&n, wire, wlen, 0, got, sizeof(got), &glen) || n.rx_len != 0) {
                if (glen == before && memcmp(got, data, before) == 0) refused++;
            }
            wire[i] ^= (uint8_t)(1u << bit);
        }
    }
    CHECK(refused == tries);

    /* A record replayed: its counter has moved on. */
    memcpy(twice, wire, first);
    memcpy(twice + first, wire, first);
    n = c;
    CHECK(!feed(&n, twice, 2 * first, 0, got, sizeof(got), &glen));
    CHECK(glen == 60 && n.err == TS_NOISE_ERR_AUTH);

    /* Two records swapped. */
    memcpy(twice, wire + first, wlen - first);
    memcpy(twice + (wlen - first), wire, first);
    n = c;
    CHECK(!feed(&n, twice, wlen, 0, got, sizeof(got), &glen) && glen == 0 && n.err == TS_NOISE_ERR_AUTH);

    /* The untouched stream. */
    n = c;
    CHECK(feed(&n, wire, wlen, 0, got, sizeof(got), &glen) && glen == sizeof(data));
}

TEST(counter_exhaustion)
{
    static ts_noise c, sv;
    static uint8_t out[3 * TS_NOISE_MAX_RECORD], data[5000];
    srv s;
    size_t used, made, glen, i;

    REQUIRE(pair(&c, &sv, &s, 130));
    memset(data, 7, sizeof(data));

    /* Two counters left: two records, then refused - and nothing written by the refused call. */
    c.tx_counter = TS_NOISE_COUNTER_LIMIT - 2;
    CHECK(ts_noise_seal(&c, data, 3, &used, out, 20, &made) && used == 1);
    CHECK(ts_noise_seal(&c, data, 3, &used, out, 20, &made) && used == 1);
    memset(out, 0xee, sizeof(out));
    CHECK(!ts_noise_seal(&c, data, 3, &used, out, 20, &made));
    CHECK(c.err == TS_NOISE_ERR_EXHAUSTED && c.state == TS_NOISE_DEAD && used == 0 && made == 0);
    for (i = 0; i < 20; i++) CHECK(out[i] == 0xee);

    /* One left, a write needing two records: refused whole, not cut. */
    REQUIRE(pair(&c, &sv, &s, 130));
    c.tx_counter = TS_NOISE_COUNTER_LIMIT - 1;
    memset(out, 0xee, sizeof(out));
    CHECK(!ts_noise_seal(&c, data, sizeof(data), &used, out, sizeof(out), &made));
    CHECK(c.err == TS_NOISE_ERR_EXHAUSTED && used == 0 && made == 0 && out[0] == 0xee);

    /* One left, one record: fine. */
    REQUIRE(pair(&c, &sv, &s, 130));
    c.tx_counter = TS_NOISE_COUNTER_LIMIT - 1;
    sv.rx_counter = TS_NOISE_COUNTER_LIMIT - 1;
    CHECK(ts_noise_seal(&c, data, 100, &used, out, sizeof(out), &made) && used == 100);
    CHECK(feed(&sv, out, made, 0, data, sizeof(data), &glen) && glen == 100);
    CHECK(sv.rx_counter == TS_NOISE_COUNTER_LIMIT);

    /* The receiving side at the limit refuses the next record, however genuine. */
    c.tx_counter = TS_NOISE_COUNTER_LIMIT - 2;
    CHECK(ts_noise_seal(&c, data, 10, &used, out, sizeof(out), &made));
    CHECK(!feed(&sv, out, made, 0, data, sizeof(data), &glen) && glen == 0);
    CHECK(sv.err == TS_NOISE_ERR_EXHAUSTED);
}

TEST(failure_is_final)
{
    static ts_noise c, sv;
    srv s;
    uint8_t junk[3] = { 9, 0, 16 }, out[64], init[TS_NOISE_INIT_LEN];
    const uint8_t* pt;
    size_t used, pt_len, made;

    REQUIRE(pair(&c, &sv, &s, 130));
    CHECK(!ts_noise_receive(&c, junk, sizeof(junk), &used, &pt, &pt_len));
    CHECK(c.err == TS_NOISE_ERR_TYPE && c.state == TS_NOISE_DEAD);
    CHECK(all_zero(c.tx_key, WG_KEY_LEN) && all_zero(c.rx_key, WG_KEY_LEN) && all_zero(c.rx, sizeof(c.rx)));

    /* Everything after is refused, and the first reason stays. */
    CHECK(!ts_noise_receive(&c, junk, sizeof(junk), &used, &pt, &pt_len) && used == 0 && pt_len == 0);
    CHECK(!ts_noise_seal(&c, junk, sizeof(junk), &used, out, sizeof(out), &made) && made == 0);
    CHECK(!ts_noise_initiation(&c, init));
    CHECK(c.err == TS_NOISE_ERR_TYPE && c.state == TS_NOISE_DEAD);
    CHECK(strcmp(ts_noise_error_text(c.err), "unexpected message type") == 0);
}

TEST(wrong_state_does_no_harm)
{
    static ts_noise n;
    script s;
    wg_key msk, cpk;
    wg_rng rng;
    uint8_t init[TS_NOISE_INIT_LEN], resp[TS_NOISE_RESP_LEN], in[8] = { 0 }, out[64];
    const uint8_t* pt;
    size_t used, pt_len, made, olen;

    /* zeroed: nothing works */
    memset(&n, 0, sizeof(n));
    t_hex(resp, sizeof(resp), KAT_TS_MAIN_RESP);
    CHECK(!ts_noise_initiation(&n, init) && n.err == TS_NOISE_ERR_STATE);
    CHECK(!ts_noise_receive(&n, resp, 3, &used, &pt, &pt_len) && n.state == TS_NOISE_IDLE);
    CHECK(!ts_noise_seal(&n, in, 1, &used, out, sizeof(out), &made));

    /* READY: no receiving, no sealing - and the initiation still comes out right after. */
    key_hex(&msk, KAT_TS_MACHINE_PRIVATE);
    key_hex(&cpk, KAT_TS_CONTROL_PUBLIC);
    rng = script_rng(&s, KAT_TS_MAIN_CLIENT_EPH);
    REQUIRE(ts_noise_init(&n, &msk, &cpk, KAT_TS_MAIN_VERSION, &rng));
    CHECK(!ts_noise_receive(&n, resp, sizeof(resp), &used, &pt, &pt_len) && used == 0);
    CHECK(!ts_noise_seal(&n, in, 1, &used, out, sizeof(out), &made));
    CHECK(n.state == TS_NOISE_READY && n.err == TS_NOISE_ERR_STATE);
    REQUIRE(ts_noise_initiation(&n, init));

    /* SENT: no second initiation, no sealing - and the response still completes it. */
    CHECK(!ts_noise_initiation(&n, init));
    CHECK(!ts_noise_seal(&n, in, 1, &used, out, sizeof(out), &made));
    CHECK(n.state == TS_NOISE_SENT);
    CHECK(feed(&n, resp, sizeof(resp), 10, out, sizeof(out), &olen) && n.state == TS_NOISE_OPEN);

    /* OPEN: no initiation. */
    CHECK(!ts_noise_initiation(&n, init) && n.state == TS_NOISE_OPEN && n.err == TS_NOISE_ERR_STATE);

    /* Wiped: all zero, IDLE. */
    ts_noise_wipe(&n);
    CHECK(n.state == TS_NOISE_IDLE && all_zero(&n, sizeof(n)));

    /* The error texts exist for every value. */
    CHECK(strcmp(ts_noise_error_text(TS_NOISE_OK), "ok") == 0);
    CHECK(strcmp(ts_noise_error_text(TS_NOISE_ERR_EXHAUSTED), "?") != 0);
    CHECK(strcmp(ts_noise_error_text((ts_noise_error)99), "?") == 0);
}

TEST(low_order_keys_and_no_randomness)
{
    static ts_noise n;
    script s;
    wg_key msk, bad;
    wg_rng none;
    uint8_t init[TS_NOISE_INIT_LEN], resp[TS_NOISE_RESP_LEN], out[8];
    size_t olen;

    key_hex(&msk, KAT_TS_MACHINE_PRIVATE);

    /* The server's key a low-order point (0, then 1): es is all zeroes. */
    memset(&bad, 0, sizeof(bad));
    REQUIRE(ts_noise_init(&n, &msk, &bad, 130, NULL));
    memset(init, 0xaa, sizeof(init));
    CHECK(!ts_noise_initiation(&n, init));
    CHECK(n.err == TS_NOISE_ERR_KEY && n.state == TS_NOISE_DEAD && all_zero(init, sizeof(init)));
    bad.b[0] = 1;
    REQUIRE(ts_noise_init(&n, &msk, &bad, 130, NULL));
    CHECK(!ts_noise_initiation(&n, init) && n.err == TS_NOISE_ERR_KEY);

    /* The server's ephemeral a low-order point: ee is all zeroes. */
    REQUIRE(kat_client(&n, &s, KAT_TS_MAIN_CLIENT_EPH, KAT_TS_MAIN_VERSION));
    t_hex(resp, sizeof(resp), KAT_TS_MAIN_RESP);
    memset(resp + TS_NOISE_RESP_OFF_EPHEMERAL, 0, WG_KEY_LEN);
    CHECK(!feed(&n, resp, sizeof(resp), sizeof(resp), out, sizeof(out), &olen));
    CHECK(n.err == TS_NOISE_ERR_KEY);

    /* No randomness: no ephemeral, no initiation. */
    none.fn = no_random;
    none.ctx = NULL;
    key_hex(&bad, KAT_TS_CONTROL_PUBLIC);
    REQUIRE(ts_noise_init(&n, &msk, &bad, 130, &none));
    CHECK(!ts_noise_initiation(&n, init) && n.err == TS_NOISE_ERR_RNG);
}

/* ------------------------------------------------------------------ EarlyNoise */

TEST(early_noise)
{
    uint8_t p[16];
    uint32_t jl;
    size_t len;

    memcpy(p, "\xff\xff\xff" "TS", 5);
    store_be32(p + 5, 94);
    for (len = 0; len < TS_EARLY_HEADER_LEN; len++) CHECK(ts_noise_early(p, len, &jl) == TS_EARLY_MORE && jl == 0);
    CHECK(ts_noise_early(p, 9, &jl) == TS_EARLY_FOUND && jl == 94);
    CHECK(ts_noise_early(p, 16, &jl) == TS_EARLY_FOUND && jl == 94);

    store_be32(p + 5, 0);
    CHECK(ts_noise_early(p, 9, &jl) == TS_EARLY_FOUND && jl == 0);
    store_be32(p + 5, TS_EARLY_MAX_JSON);
    CHECK(ts_noise_early(p, 9, &jl) == TS_EARLY_FOUND && jl == TS_EARLY_MAX_JSON);
    store_be32(p + 5, TS_EARLY_MAX_JSON + 1);
    CHECK(ts_noise_early(p, 9, &jl) == TS_EARLY_BAD && jl == 0);
    store_be32(p + 5, 0xffffffffu);
    CHECK(ts_noise_early(p, 9, &jl) == TS_EARLY_BAD && jl == 0);

    /* Almost the magic is HTTP/2. */
    store_be32(p + 5, 94);
    p[4] = 's';
    CHECK(ts_noise_early(p, 9, &jl) == TS_EARLY_NONE && jl == 0);
    p[4] = 'S';
    p[2] = 0xfe;
    CHECK(ts_noise_early(p, 9, &jl) == TS_EARLY_NONE);

    /* A server's SETTINGS frame, the usual first bytes without EarlyNoise. */
    memcpy(p, "\x00\x00\x12\x04\x00\x00\x00\x00\x00", 9);
    CHECK(ts_noise_early(p, 9, &jl) == TS_EARLY_NONE);
}

/* ------------------------------------------------------------------ garbage */

static void mutate(uint8_t* buf, size_t* len, size_t cap)
{
    static const uint8_t special[] = { 0, 1, 2, 3, 4, 5, 0x0f, 0x10, 0xfd, 0xfe, 0xff, 0x30 };
    size_t n = *len, i, at;
    int k = (int)(rnd() % 6), times = 1 + (int)(rnd() % 4);

    switch (k) {
    case 0: while (n && times--) buf[rnd() % n] ^= (uint8_t)(1u << (rnd() % 8)); break;
    case 1: while (n && times--) buf[rnd() % n] = (uint8_t)rnd(); break;
    case 2: if (n) *len = (size_t)(rnd() % n); break;
    case 3:
        at = n + 1 + (size_t)(rnd() % 64);
        if (at > cap) at = cap;
        for (i = n; i < at; i++) buf[i] = (uint8_t)rnd();
        *len = at;
        break;
    case 4: while (n && times--) buf[rnd() % n] = special[rnd() % sizeof(special)]; break;
    default:
        if (n > 2) {                                    /* duplicate a slice */
            size_t from = (size_t)(rnd() % n), cnt = 1 + (size_t)(rnd() % (n - from));
            if (n + cnt <= cap) {
                memmove(buf + from + cnt, buf + from, n - from);
                *len = n + cnt;
            }
        }
        break;
    }
}

/* The response, mutated: the handshake completes only if its 51 bytes are the genuine ones. */
TEST(fuzz_response)
{
    static ts_noise sent, n;
    static uint8_t stream[TS_NOISE_RESP_LEN + 256], buf[TS_NOISE_RESP_LEN + 512], out[1024];
    script s;
    size_t slen, olen;
    int iter, wrong_open = 0, opened = 0;

    REQUIRE(kat_client(&sent, &s, KAT_TS_MAIN_CLIENT_EPH, KAT_TS_MAIN_VERSION));
    slen = t_hex(stream, sizeof(stream), KAT_TS_MAIN_RESP);

    for (iter = 0; iter < 4000; iter++) {
        size_t len = slen;
        int k = 1 + (int)(rnd() % 3);

        memcpy(buf, stream, slen);
        while (k--) mutate(buf, &len, sizeof(buf));
        n = sent;
        (void)feed(&n, buf, len, 0, out, sizeof(out), &olen);
        if (n.state == TS_NOISE_OPEN) {
            opened++;
            if (len < TS_NOISE_RESP_LEN || memcmp(buf, stream, TS_NOISE_RESP_LEN) != 0) wrong_open++;
        }
        if (n.state == TS_NOISE_DEAD) CHECK(all_zero(n.rx_key, WG_KEY_LEN) && olen == 0);
    }
    CHECK(wrong_open == 0);
    CHECK(opened > 0);
}

/* Records, mutated: what comes out is always a prefix of what the server sent. */
TEST(fuzz_records)
{
    static ts_noise c, sv, n, sent;
    static uint8_t plain[60000], wire[70000], buf[70000], out[70000];
    srv s;
    script sc;
    size_t plen = 0, wlen = 0, olen;
    int iter, not_prefix = 0, lost = 0, sticky = 0;

    REQUIRE(pair(&c, &sv, &s, 130));
    REQUIRE(kat_client(&sent, &sc, KAT_TS_MAIN_CLIENT_EPH, KAT_TS_MAIN_VERSION));
    /* 40 records of random sizes, among them empty ones and full ones */
    while (sv.tx_counter < 40) {
        size_t len = (size_t)(rnd() % 4);
        size_t used, made, i;

        len = len == 0 ? 0 : len == 1 ? TS_NOISE_MAX_PLAINTEXT : (size_t)(rnd() % 700);
        if (plen + len > sizeof(plain)) break;
        for (i = 0; i < len; i++) plain[plen + i] = (uint8_t)rnd();
        if (len == 0) {
            uint8_t nonce[12] = { 0 };
            size_t j;
            for (j = 0; j < 8; j++) nonce[4 + j] = (uint8_t)(sv.tx_counter >> (56 - 8 * j));
            wire[wlen] = TS_NOISE_MSG_RECORD;
            wire[wlen + 1] = 0;
            wire[wlen + 2] = WG_TAG_LEN;
            REQUIRE(wg_aead_encrypt_n(wire + wlen + 3, sv.tx_key, nonce, NULL, 0, NULL, 0));
            sv.tx_counter++;
            wlen += TS_NOISE_RECORD_OVERHEAD;
            continue;
        }
        REQUIRE(ts_noise_seal(&sv, plain + plen, len, &used, wire + wlen, sizeof(wire) - wlen, &made));
        REQUIRE(used == len);
        plen += len;
        wlen += made;
    }

    n = c;
    CHECK(feed(&n, wire, wlen, 0, out, sizeof(out), &olen) && olen == plen && memcmp(out, plain, plen) == 0);

    for (iter = 0; iter < 3000; iter++) {
        size_t len = wlen;
        int k = 1 + (int)(rnd() % 3), ok;

        memcpy(buf, wire, wlen);
        while (k--) mutate(buf, &len, sizeof(buf));
        n = c;
        ok = feed(&n, buf, len, 0, out, sizeof(out), &olen);
        if (olen > plen || memcmp(out, plain, olen) != 0) not_prefix++;
        if (ok && len == wlen && memcmp(buf, wire, wlen) == 0 && olen != plen) lost++;
        if (!ok) {
            const uint8_t* pt;
            size_t used, pt_len;
            if (ts_noise_receive(&n, wire, wlen, &used, &pt, &pt_len) || pt_len || n.state != TS_NOISE_DEAD) sticky++;
        }
    }
    CHECK(not_prefix == 0);
    CHECK(lost == 0);
    CHECK(sticky == 0);

    /* Pure noise into an open stream, and into one waiting for its response. */
    for (iter = 0; iter < 4000; iter++) {
        size_t len = (size_t)(rnd() % 600), i;
        int waiting = iter % 2;

        for (i = 0; i < len; i++) buf[i] = (uint8_t)rnd();
        if (len > 3 && rnd() % 2) {
            /* a plausible header, then garbage */
            buf[0] = waiting ? TS_NOISE_MSG_RESPONSE : TS_NOISE_MSG_RECORD;
            buf[1] = waiting ? 0 : (uint8_t)(rnd() % 0x10);
            if (waiting) buf[2] = TS_NOISE_RESP_PAYLOAD_LEN;
        }
        n = waiting ? sent : c;
        (void)feed(&n, buf, len, 0, out, sizeof(out), &olen);
        CHECK(olen == 0);
        if (waiting) CHECK(n.state != TS_NOISE_OPEN);
    }
}

TEST(fuzz_early)
{
    uint8_t p[16];
    int iter, bad = 0;

    for (iter = 0; iter < 50000; iter++) {
        size_t len = (size_t)(rnd() % 14), i;
        ts_early_result want, got;
        uint32_t jl, want_len = 0;

        for (i = 0; i < len; i++) {
            static const uint8_t pick[] = { 0xff, 0xff, 0xff, 'T', 'S', 0, 0x00, 0xa0 };
            p[i] = rnd() % 4 ? pick[rnd() % sizeof(pick)] : (uint8_t)rnd();
        }
        if (len >= 5 && rnd() % 3 == 0) memcpy(p, "\xff\xff\xff" "TS", 5);

        if (len < 9) {
            want = TS_EARLY_MORE;
        } else if (memcmp(p, "\xff\xff\xff" "TS", 5) != 0) {
            want = TS_EARLY_NONE;
        } else {
            uint32_t l = ((uint32_t)p[5] << 24) | ((uint32_t)p[6] << 16) | ((uint32_t)p[7] << 8) | p[8];
            want = l > (10u << 20) ? TS_EARLY_BAD : TS_EARLY_FOUND;
            if (want == TS_EARLY_FOUND) want_len = l;
        }
        {
            uint8_t* h = (uint8_t*)malloc(len ? len : 1);
            memcpy(h, p, len);
            got = ts_noise_early(h, len, &jl);
            free(h);
        }
        if (got != want || jl != want_len) bad++;
    }
    CHECK(bad == 0);
}

/* ------------------------------------------------------------------ interop (--interop) */

static const char* io_mode;
static const char* io_host;
static int io_port;
static wg_key io_control;

typedef struct {
    int      fd;
    ts_noise n;
    uint8_t* plain;                 /* decrypted and not yet taken */
    size_t   plain_len, plain_cap;
    int      eof;
    size_t   records_with_response; /* records decrypted in the read that brought the response */
} tcp_link;

static int link_connect(tcp_link* l)
{
    struct sockaddr_in sa;
    struct timeval tv;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)io_port);
    if (inet_pton(AF_INET, io_host, &sa.sin_addr) != 1) return 0;
    l->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (l->fd < 0) return 0;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(l->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return connect(l->fd, (struct sockaddr*)&sa, sizeof(sa)) == 0;
}

static void link_close(tcp_link* l)
{
    if (l->fd >= 0) close(l->fd);
    l->fd = -1;
    free(l->plain);
    l->plain = NULL;
    l->plain_len = l->plain_cap = 0;
    ts_noise_wipe(&l->n);
}

static int send_all(int fd, const uint8_t* p, size_t n)
{
    while (n) {
        ssize_t k = send(fd, p, n, 0);
        if (k <= 0) return 0;
        p += k;
        n -= (size_t)k;
    }
    return 1;
}

/* Bytes from the server through ts_noise; the plaintext piles up in l->plain. 0 on a refusal. */
static int link_feed(tcp_link* l, const uint8_t* in, size_t len)
{
    size_t off = 0;
    int was_sent = l->n.state == TS_NOISE_SENT;

    while (off < len) {
        const uint8_t* pt;
        size_t used, pt_len;

        if (!ts_noise_receive(&l->n, in + off, len - off, &used, &pt, &pt_len)) return 0;
        off += used;
        if (!pt_len) continue;
        if (was_sent) l->records_with_response++;
        if (l->plain_len + pt_len > l->plain_cap) {
            size_t cap = (l->plain_cap ? l->plain_cap * 2 : 65536) + pt_len;
            uint8_t* p = (uint8_t*)realloc(l->plain, cap);
            if (!p) return 0;
            l->plain = p;
            l->plain_cap = cap;
        }
        memcpy(l->plain + l->plain_len, pt, pt_len);
        l->plain_len += pt_len;
    }
    return 1;
}

/* Reads until `want` bytes of plaintext wait, the server hangs up, or ts_noise refuses. */
static int link_pump(tcp_link* l, size_t want)
{
    static uint8_t buf[16384];

    while (l->plain_len < want) {
        ssize_t k = recv(l->fd, buf, sizeof(buf), 0);
        if (k <= 0) {
            l->eof = 1;
            return 0;
        }
        if (!link_feed(l, buf, (size_t)k)) return 0;
    }
    return 1;
}

static void link_take(tcp_link* l, uint8_t* out, size_t k)
{
    if (out) memcpy(out, l->plain, k);
    memmove(l->plain, l->plain + k, l->plain_len - k);
    l->plain_len -= k;
}

/* Seals and sends, `room` bytes of output per seal: `room` sets the record sizes. */
static int link_send(tcp_link* l, const uint8_t* p, size_t len, size_t room)
{
    static uint8_t out[70000];
    size_t off = 0;

    while (off < len) {
        size_t used, made;
        if (!ts_noise_seal(&l->n, p + off, len - off, &used, out, room < sizeof(out) ? room : sizeof(out), &made))
            return 0;
        if (!used || !send_all(l->fd, out, made)) return 0;
        off += used;
    }
    return 1;
}

static void base64(char* out, const uint8_t* in, size_t len)
{
    static const char a[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i, o = 0;

    for (i = 0; i + 2 < len; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[o++] = a[v >> 18];
        out[o++] = a[(v >> 12) & 63];
        out[o++] = a[(v >> 6) & 63];
        out[o++] = a[v & 63];
    }
    if (len - i == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = a[v >> 18];
        out[o++] = a[(v >> 12) & 63];
        out[o++] = '=';
        out[o++] = '=';
    } else if (len - i == 2) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        out[o++] = a[v >> 18];
        out[o++] = a[(v >> 12) & 63];
        out[o++] = a[(v >> 6) & 63];
        out[o++] = '=';
    }
    out[o] = '\0';
}

/* POST /ts2021 as controlhttp's client sends it; the bytes after the 101's headers go to ts_noise. */
static int http_upgrade(tcp_link* l, const uint8_t init[TS_NOISE_INIT_LEN])
{
    char req[512], enc[140];
    uint8_t resp[4096];
    size_t have = 0, i;
    int n;

    base64(enc, init, TS_NOISE_INIT_LEN);
    n = snprintf(req, sizeof(req),
                 "POST /ts2021 HTTP/1.1\r\nHost: %s\r\nUpgrade: tailscale-control-protocol\r\n"
                 "Connection: upgrade\r\nX-Tailscale-Handshake: %s\r\nContent-Length: 0\r\n\r\n",
                 io_host, enc);
    if (n <= 0 || !send_all(l->fd, (const uint8_t*)req, (size_t)n)) return 0;

    for (;;) {
        ssize_t k = recv(l->fd, resp + have, sizeof(resp) - have, 0);
        if (k <= 0) return 0;
        have += (size_t)k;
        for (i = 0; i + 4 <= have; i++) {
            if (memcmp(resp + i, "\r\n\r\n", 4) == 0) {
                if (have < 13 || memcmp(resp, "HTTP/1.1 101 ", 13) != 0) return 0;
                return link_feed(l, resp + i + 4, have - i - 4);
            }
        }
        if (have == sizeof(resp)) return 0;
    }
}

static int link_start(tcp_link* l, const wg_key* control, uint8_t init[TS_NOISE_INIT_LEN], int bad_type)
{
    wg_key msk, mpk;

    memset(l, 0, sizeof(*l));
    l->fd = -1;
    if (!wg_key_generate(&msk, &mpk)) return 0;
    if (!ts_noise_init(&l->n, &msk, control, 130, NULL) || !ts_noise_initiation(&l->n, init)) return 0;
    if (bad_type) init[TS_NOISE_INIT_OFF_TYPE] = 7;
    if (!link_connect(l)) return 0;
    if (strcmp(io_mode, "http") == 0) return http_upgrade(l, init);
    return send_all(l->fd, init, TS_NOISE_INIT_LEN);
}

/* A control key the server does not hold: it cannot open our machine key and hangs up silently. */
TEST(interop_wrong_key)
{
    tcp_link l;
    wg_key sk, pk;
    uint8_t init[TS_NOISE_INIT_LEN];

    REQUIRE(wg_key_generate(&sk, &pk));
    REQUIRE(link_start(&l, &pk, init, 0));
    CHECK(!link_pump(&l, 1) && l.eof);
    CHECK(l.n.state == TS_NOISE_SENT && l.n.rx_len == 0);
    link_close(&l);
}

/* A mangled initiation: the server says why, in an error message. */
TEST(interop_bad_type)
{
    tcp_link l;
    uint8_t init[TS_NOISE_INIT_LEN];

    REQUIRE(link_start(&l, &io_control, init, 1));
    CHECK(!link_pump(&l, 1) && !l.eof);
    CHECK(l.n.state == TS_NOISE_DEAD && l.n.err == TS_NOISE_ERR_SERVER);
    CHECK(strcmp(l.n.err_text, "unexpected handshake message type") == 0);
    link_close(&l);
}

TEST(interop_session)
{
    static uint8_t data[150000], got[150000];
    tcp_link l;
    uint8_t init[TS_NOISE_INIT_LEN], hello[66], len4[4];
    uint32_t jl;
    size_t i, off, rooms[] = { 100, 1000, 5000, 20000 };
    int http = strcmp(io_mode, "http") == 0;

    REQUIRE(link_start(&l, &io_control, init, 0));
    REQUIRE(link_pump(&l, TS_EARLY_HEADER_LEN));
    CHECK(l.n.state == TS_NOISE_OPEN);

    /* The start of the stream: EarlyNoise over HTTP, a bare SETTINGS frame header raw. */
    if (http) {
        CHECK(ts_noise_early(l.plain, l.plain_len, &jl) == TS_EARLY_FOUND);
        link_take(&l, NULL, TS_EARLY_HEADER_LEN);
        REQUIRE(jl > 30 && jl < 1000 && link_pump(&l, jl));
        CHECK(memcmp(l.plain, "{\"nodeKeyChallenge\":\"chalpub:", 29) == 0 && l.plain[jl - 1] == '}');
        link_take(&l, NULL, jl);
    } else {
        CHECK(ts_noise_early(l.plain, l.plain_len, &jl) == TS_EARLY_NONE);
        CHECK(memcmp(l.plain, "\x00\x00\x00\x04\x00\x00\x00\x00\x00", 9) == 0);
        link_take(&l, NULL, 9);
    }
    printf("    %s: %u record(s) came in the read with the response\n", io_mode,
           (unsigned)l.records_with_response);

    /* hello: our machine key as the server saw it, the version, the same handshake hash */
    REQUIRE(link_pump(&l, sizeof(hello)));
    link_take(&l, hello, sizeof(hello));
    CHECK_MEM(hello, l.n.machine_public.b, WG_KEY_LEN);
    CHECK(hello[32] == 0 && hello[33] == 130);
    CHECK_MEM(hello + 34, l.n.hash, WG_HASH_LEN);

    /* 100000 bytes from the server in one write: 25 records, 24 of them full */
    REQUIRE(link_pump(&l, 100000));
    blob(got, 100000, 131, 7);
    CHECK(memcmp(l.plain, got, 100000) == 0);
    link_take(&l, NULL, 100000);

    /* To the server: the length alone, then the data in records of every size - one byte, a
     * hundred, the maximum - and back. */
    blob(data, sizeof(data), 29, 3);
    store_be32(len4, (uint32_t)sizeof(data));
    CHECK(link_send(&l, len4, sizeof(len4), sizeof(len4) + TS_NOISE_RECORD_OVERHEAD));
    CHECK(link_send(&l, data, 16, 1 + TS_NOISE_RECORD_OVERHEAD));
    off = 16;
    for (i = 0; i < sizeof(rooms) / sizeof(rooms[0]); i++) {
        CHECK(link_send(&l, data + off, 10000, rooms[i]));
        off += 10000;
    }
    CHECK(link_send(&l, data + off, sizeof(data) - off, 1 << 20));
    REQUIRE(link_pump(&l, sizeof(data)));
    CHECK(memcmp(l.plain, data, sizeof(data)) == 0);
    link_take(&l, NULL, sizeof(data));

    /* "BYE", then the end of the stream - on a record boundary. */
    REQUIRE(link_pump(&l, 3));
    CHECK(memcmp(l.plain, "BYE", 3) == 0);
    link_take(&l, NULL, 3);
    CHECK(!link_pump(&l, 1) && l.eof && l.plain_len == 0);
    CHECK(l.n.state == TS_NOISE_OPEN && l.n.rx_len == 0);
    printf("    %s: sent %llu records, received %llu\n", io_mode, (unsigned long long)l.n.tx_counter,
           (unsigned long long)l.n.rx_counter);
    link_close(&l);
}

int main(int argc, char** argv)
{
    const char* seed = getenv("BT_FUZZ_SEED");

    if (seed) xs = strtoull(seed, NULL, 16);
    if (!xs) xs = 1;
    printf("test_ts_noise (seed %016llx)\n", (unsigned long long)xs);
    if (!wg_crypto_init()) {
        fprintf(stderr, "wg_crypto_init failed\n");
        return 2;
    }
    RUN(kat_main_transcript);
    RUN(kat_main_any_split);
    RUN(kat_versions);
    RUN(kat_far_records);
    RUN(responder_matches_reference);
    RUN(handshake_and_big_data);
    RUN(empty_and_max_records);
    RUN(seal_limits);
    RUN(response_tampering);
    RUN(wrong_keys);
    RUN(server_error_message);
    RUN(bad_headers);
    RUN(record_tampering);
    RUN(counter_exhaustion);
    RUN(failure_is_final);
    RUN(wrong_state_does_no_harm);
    RUN(low_order_keys_and_no_randomness);
    RUN(early_noise);
    RUN(fuzz_response);
    RUN(fuzz_records);
    RUN(fuzz_early);

    if (argc == 6 && strcmp(argv[1], "--interop") == 0) {
        io_mode = argv[2];
        io_host = argv[3];
        io_port = atoi(argv[4]);
        key_hex(&io_control, argv[5]);
        signal(SIGPIPE, SIG_IGN);
        printf("interop (%s, %s:%d)\n", io_mode, io_host, io_port);
        RUN(interop_wrong_key);
        if (strcmp(io_mode, "raw") == 0) RUN(interop_bad_type);
        RUN(interop_session);
    }
    wg_crypto_cleanup();
    return t_summary("test_ts_noise");
}
