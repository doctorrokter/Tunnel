/*
 * wg_salsa against the classic NaCl example (libsodium's published stages), RFC 8439's Poly1305
 * example, and golang.org/x/crypto/nacl - the very functions Tailscale's DERP seals and opens
 * with (test/vectors/box, kat_box.h). Then what vectors cannot show: tampering, empty messages,
 * buffers in place, low-order keys and random round trips between two key pairs.
 */

#include "test_util.h"
#include "../src/wg_salsa.h"
#include "vectors/kat_box.h"

#define MSG_MAX 1000                            /* the longest Go vector */
#define BUF_MAX (MSG_MAX + WG_BOX_TAG_LEN + 64)
#define SENTINEL 0xa5

/* A vector of exactly n bytes, or the run stops: a shortened vector must not pass as a short one. */
static void load(uint8_t* buf, size_t n, const char* hex)
{
    if (t_hex(buf, n, hex) != n) {
        fprintf(stderr, "vector is not %u bytes: \"%.16s...\"\n", (unsigned)n, hex);
        exit(2);
    }
}

static void load_key(wg_key* k, const char* hex)
{
    load(k->b, sizeof(k->b), hex);
}

static const kat_box_vec* vec_of_len(size_t len)
{
    size_t i;
    for (i = 0; i < sizeof(KAT_BOX_VECS) / sizeof(KAT_BOX_VECS[0]); i++)
        if (KAT_BOX_VECS[i].len == len) return &KAT_BOX_VECS[i];
    fprintf(stderr, "no Go vector of %u bytes\n", (unsigned)len);
    exit(2);
}

static int all_sentinel(const uint8_t* p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (p[i] != SENTINEL) return 0;
    return 1;
}

/* 1 when the box is refused AND the output buffer was not touched - no plaintext, not even a
 * partial one, comes out of a box whose tag does not check. */
static int refused_clean(const uint8_t* box, size_t len, const uint8_t nonce[24], const uint8_t key[32])
{
    uint8_t out[BUF_MAX];

    memset(out, SENTINEL, sizeof(out));
    return !wg_secretbox_open(out, box, len, nonce, key) && all_sentinel(out, sizeof(out));
}

/* ------------------------------------------------------------------ the classic NaCl example */

TEST(hsalsa20_nacl)
{
    uint8_t shared[32], first[32], nonce[24], second[32], zero[16], out[32];

    load(shared, 32, KAT_NACL_SHARED);
    load(first, 32, KAT_NACL_FIRSTKEY);
    load(nonce, 24, KAT_NACL_NONCE);
    load(second, 32, KAT_NACL_SECONDKEY);
    memset(zero, 0, sizeof(zero));

    wg_hsalsa20(out, shared, zero);             /* core1: the box key of the X25519 secret */
    CHECK_MEM(out, first, 32);
    wg_hsalsa20(out, first, nonce);             /* core2: the XSalsa20 subkey, nonce[0..16] */
    CHECK_MEM(out, second, 32);

    /* The output may be the key: the whole state is loaded before a byte is stored. */
    memcpy(out, first, 32);
    wg_hsalsa20(out, out, nonce);
    CHECK_MEM(out, second, 32);
}

TEST(xsalsa20_nacl)
{
    uint8_t first[32], nonce[24], rs[32], zero[32], out[32];

    load(first, 32, KAT_NACL_FIRSTKEY);
    load(nonce, 24, KAT_NACL_NONCE);
    load(rs, 32, KAT_NACL_RS);
    memset(zero, 0, sizeof(zero));

    /* stream3: the first 32 bytes of the stream, which secretbox takes as the Poly1305 key */
    wg_xsalsa20_xor(out, zero, 32, nonce, first);
    CHECK_MEM(out, rs, 32);
}

TEST(poly1305_rfc8439_and_nacl)
{
    uint8_t key[32], msg[64], tag[16], want[16], rs[32], box[147];
    size_t n;

    load(key, 32, KAT_POLY1305_KEY);
    load(want, 16, KAT_POLY1305_TAG);
    n = t_hex(msg, sizeof(msg), KAT_POLY1305_MSG);
    CHECK(wg_poly1305(tag, key, msg, n));
    CHECK_MEM(tag, want, 16);

    /* onetimeauth: the classic box's tag over its ciphertext, under the stream's first 32 bytes */
    load(rs, 32, KAT_NACL_RS);
    load(box, sizeof(box), KAT_NACL_BOX);
    CHECK(wg_poly1305(tag, rs, box + 16, sizeof(box) - 16));
    CHECK_MEM(tag, box, 16);

    /* An empty message: the accumulator stays 0 and the tag is s, the key's second half. */
    CHECK(wg_poly1305(tag, key, NULL, 0));
    CHECK_MEM(tag, key + 16, 16);
}

TEST(box_nacl)
{
    wg_key alice_sk, alice_pk, bob_sk, bob_pk, check;
    uint8_t first[32], nonce[24], k[32], msg[131], box[147], out[147];

    load_key(&alice_sk, KAT_NACL_ALICE_SK);
    load_key(&alice_pk, KAT_NACL_ALICE_PK);
    load_key(&bob_sk, KAT_NACL_BOB_SK);
    load_key(&bob_pk, KAT_NACL_BOB_PK);
    load(first, 32, KAT_NACL_FIRSTKEY);
    load(nonce, 24, KAT_NACL_NONCE);
    load(msg, sizeof(msg), KAT_NACL_MSG);
    load(box, sizeof(box), KAT_NACL_BOX);

    CHECK(wg_key_public(&alice_sk, &check));
    CHECK_MEM(check.b, alice_pk.b, 32);

    /* beforenm is the same key from either end */
    CHECK(wg_box_beforenm(k, &bob_pk, &alice_sk));
    CHECK_MEM(k, first, 32);
    CHECK(wg_box_beforenm(k, &alice_pk, &bob_sk));
    CHECK_MEM(k, first, 32);

    /* box.c: Alice seals; afternm is secretbox under the precomputed key */
    CHECK(wg_box_seal(out, msg, sizeof(msg), nonce, &bob_pk, &alice_sk));
    CHECK_MEM(out, box, sizeof(box));
    memset(out, 0, sizeof(out));
    CHECK(wg_secretbox_seal(out, msg, sizeof(msg), nonce, first));
    CHECK_MEM(out, box, sizeof(box));

    /* box2.c: Bob opens */
    memset(out, 0, sizeof(out));
    CHECK(wg_box_open(out, box, sizeof(box), nonce, &alice_pk, &bob_sk));
    CHECK_MEM(out, msg, sizeof(msg));
}

/* ------------------------------------------------------------------ golang.org/x/crypto */

TEST(xsalsa20_go)
{
    uint8_t key[32], nonce[24], stream[200], zero[200], msg[200], out[201];
    size_t n;
    int bad = 0;

    load(key, 32, KAT_SECRETBOX_KEY);
    load(nonce, 24, KAT_SECRETBOX_NONCE);
    load(stream, sizeof(stream), KAT_XSALSA20_STREAM);
    memset(zero, 0, sizeof(zero));

    /* Every length up to 200 is the same prefix - across the ends of blocks 0, 1 and 2 - and
     * exactly that many bytes are written. */
    for (n = 0; n <= sizeof(stream); n++) {
        memset(out, SENTINEL, sizeof(out));
        wg_xsalsa20_xor(out, zero, n, nonce, key);
        if (memcmp(out, stream, n) != 0 || out[n] != SENTINEL) bad++;
    }
    CHECK(bad == 0);

    /* In place, and a second pass gives the input back. */
    for (n = 0; n < sizeof(msg); n++) msg[n] = (uint8_t)(n * 7 + 1);
    memcpy(out, msg, sizeof(msg));
    wg_xsalsa20_xor(out, out, sizeof(msg), nonce, key);
    for (n = 0, bad = 0; n < sizeof(msg); n++)
        if (out[n] != (uint8_t)(msg[n] ^ stream[n])) bad++;
    CHECK(bad == 0);
    wg_xsalsa20_xor(out, out, sizeof(msg), nonce, key);
    CHECK_MEM(out, msg, sizeof(msg));
}

TEST(beforenm_go)
{
    wg_key csk, cpk, ssk, spk;
    uint8_t want[32], k[32];

    load_key(&csk, KAT_BOX_CLIENT_SK);
    load_key(&cpk, KAT_BOX_CLIENT_PK);
    load_key(&ssk, KAT_BOX_SERVER_SK);
    load_key(&spk, KAT_BOX_SERVER_PK);
    load(want, 32, KAT_BOX_BEFORENM);

    CHECK(wg_box_beforenm(k, &spk, &csk));      /* box.Precompute(server_pk, client_sk) */
    CHECK_MEM(k, want, 32);
    CHECK(wg_box_beforenm(k, &cpk, &ssk));      /* ... and from the server's end */
    CHECK_MEM(k, want, 32);
}

TEST(vectors_go)
{
    wg_key csk, cpk, ssk, spk;
    uint8_t sbkey[32], sbnonce[24], bnonce[24], k[32];
    uint8_t msg[MSG_MAX], want[BUF_MAX], out[BUF_MAX];
    size_t i, n, wlen;

    load_key(&csk, KAT_BOX_CLIENT_SK);
    load_key(&cpk, KAT_BOX_CLIENT_PK);
    load_key(&ssk, KAT_BOX_SERVER_SK);
    load_key(&spk, KAT_BOX_SERVER_PK);
    load(sbkey, 32, KAT_SECRETBOX_KEY);
    load(sbnonce, 24, KAT_SECRETBOX_NONCE);
    load(bnonce, 24, KAT_BOX_NONCE);
    load(k, 32, KAT_BOX_BEFORENM);
    load(msg, sizeof(msg), KAT_BOX_MSG);

    for (i = 0; i < sizeof(KAT_BOX_VECS) / sizeof(KAT_BOX_VECS[0]); i++) {
        n = KAT_BOX_VECS[i].len;

        /* secretbox.Seal / Open; exactly len + 16 bytes written on seal, len on open */
        wlen = t_hex(want, sizeof(want), KAT_BOX_VECS[i].secretbox);
        CHECK(wlen == n + WG_BOX_TAG_LEN);
        memset(out, SENTINEL, sizeof(out));
        CHECK(wg_secretbox_seal(out, msg, n, sbnonce, sbkey));
        CHECK_MEM(out, want, wlen);
        CHECK(out[wlen] == SENTINEL);
        memset(out, SENTINEL, sizeof(out));
        CHECK(wg_secretbox_open(out, want, wlen, sbnonce, sbkey));
        CHECK_MEM(out, msg, n);
        CHECK(out[n] == SENTINEL);

        /* box.Seal: the client seals to the server, as ClientInfo; the server opens, as
         * recvClientKey; and afternm opens it with the precomputed key */
        wlen = t_hex(want, sizeof(want), KAT_BOX_VECS[i].box);
        CHECK(wlen == n + WG_BOX_TAG_LEN);
        CHECK(wg_box_seal(out, msg, n, bnonce, &spk, &csk));
        CHECK_MEM(out, want, wlen);
        memset(out, SENTINEL, sizeof(out));
        CHECK(wg_box_open(out, want, wlen, bnonce, &cpk, &ssk));
        CHECK_MEM(out, msg, n);
        memset(out, SENTINEL, sizeof(out));
        CHECK(wg_secretbox_open(out, want, wlen, bnonce, k));
        CHECK_MEM(out, msg, n);
    }
}

TEST(derp_client_info)
{
    wg_key csk, cpk, ssk, spk;
    const size_t jlen = strlen(KAT_DERP_CLIENT_INFO);
    uint8_t sealed[128], out[128], frame[128];
    size_t slen;

    load_key(&csk, KAT_BOX_CLIENT_SK);
    load_key(&cpk, KAT_BOX_CLIENT_PK);
    load_key(&ssk, KAT_BOX_SERVER_SK);
    load_key(&spk, KAT_BOX_SERVER_PK);
    slen = t_hex(sealed, sizeof(sealed), KAT_DERP_CLIENT_INFO_SEALED);
    REQUIRE(slen == WG_BOX_NONCE_LEN + WG_BOX_TAG_LEN + jlen);

    /* Our side: the JSON under the vector's nonce seals to exactly SealTo's box. */
    CHECK(wg_box_seal(out, KAT_DERP_CLIENT_INFO, jlen, sealed, &spk, &csk));
    CHECK_MEM(out, sealed + WG_BOX_NONCE_LEN, slen - WG_BOX_NONCE_LEN);

    /* The same in SealTo's shape, in place: nonce || room for the tag || JSON in one buffer. */
    memcpy(frame, sealed, WG_BOX_NONCE_LEN);
    memcpy(frame + WG_BOX_NONCE_LEN + WG_BOX_TAG_LEN, KAT_DERP_CLIENT_INFO, jlen);
    CHECK(wg_box_seal(frame + WG_BOX_NONCE_LEN, frame + WG_BOX_NONCE_LEN + WG_BOX_TAG_LEN, jlen,
                      frame, &spk, &csk));
    CHECK_MEM(frame, sealed, slen);

    /* The server's side opens it. */
    CHECK(wg_box_open(out, sealed + WG_BOX_NONCE_LEN, slen - WG_BOX_NONCE_LEN, sealed, &cpk, &ssk));
    CHECK_MEM(out, KAT_DERP_CLIENT_INFO, jlen);
}

TEST(derp_server_info)
{
    wg_key csk, spk;
    const size_t jlen = strlen(KAT_DERP_SERVER_INFO);
    uint8_t sealed[128], out[128], frame[128];
    size_t slen;

    load_key(&csk, KAT_BOX_CLIENT_SK);
    load_key(&spk, KAT_BOX_SERVER_PK);
    slen = t_hex(sealed, sizeof(sealed), KAT_DERP_SERVER_INFO_SEALED);
    REQUIRE(slen == WG_BOX_NONCE_LEN + WG_BOX_TAG_LEN + jlen);

    CHECK(wg_box_open(out, sealed + WG_BOX_NONCE_LEN, slen - WG_BOX_NONCE_LEN, sealed, &spk, &csk));
    CHECK_MEM(out, KAT_DERP_SERVER_INFO, jlen);

    /* OpenFrom's shape, in place: the JSON lands at the start of the frame, over the very nonce
     * it is opened with - the nonce is taken before anything is written. */
    memcpy(frame, sealed, slen);
    CHECK(wg_box_open(frame, frame + WG_BOX_NONCE_LEN, slen - WG_BOX_NONCE_LEN, frame, &spk, &csk));
    CHECK_MEM(frame, KAT_DERP_SERVER_INFO, jlen);
}

/* ------------------------------------------------------------------ what vectors cannot show */

TEST(open_rejects_tampering)
{
    static const size_t lens[] = { 0, 65 };     /* the tag alone; a box across blocks 0, 1 and 2 */
    uint8_t key[32], nonce[24], box[BUF_MAX], bad_box[BUF_MAX], bad_nonce[24], bad_key[32];
    size_t li, i, len;
    int b, accepted;

    load(key, 32, KAT_SECRETBOX_KEY);
    load(nonce, 24, KAT_SECRETBOX_NONCE);

    for (li = 0; li < sizeof(lens) / sizeof(lens[0]); li++) {
        len = t_hex(box, sizeof(box), vec_of_len(lens[li])->secretbox);
        REQUIRE(len == lens[li] + WG_BOX_TAG_LEN);
        REQUIRE(!refused_clean(box, len, nonce, key));      /* the untouched box opens */

        /* every single-bit flip of the box: tag and ciphertext */
        accepted = 0;
        for (i = 0; i < len; i++) {
            for (b = 0; b < 8; b++) {
                memcpy(bad_box, box, len);
                bad_box[i] ^= (uint8_t)(1u << b);
                if (!refused_clean(bad_box, len, nonce, key)) accepted++;
            }
        }
        CHECK(accepted == 0);

        /* every bit of the nonce - 0..15 feed HSalsa20, 16..23 Salsa20 - and of the key */
        accepted = 0;
        for (i = 0; i < 24 * 8; i++) {
            memcpy(bad_nonce, nonce, 24);
            bad_nonce[i / 8] ^= (uint8_t)(1u << (i % 8));
            if (!refused_clean(box, len, bad_nonce, key)) accepted++;
        }
        CHECK(accepted == 0);
        accepted = 0;
        for (i = 0; i < 32 * 8; i++) {
            memcpy(bad_key, key, 32);
            bad_key[i / 8] ^= (uint8_t)(1u << (i % 8));
            if (!refused_clean(box, len, nonce, bad_key)) accepted++;
        }
        CHECK(accepted == 0);

        /* one byte short, one byte extra */
        CHECK(refused_clean(box, len - 1, nonce, key));
        memcpy(bad_box, box, len);
        bad_box[len] = 0;
        CHECK(refused_clean(bad_box, len + 1, nonce, key));
    }

    /* shorter than a tag: nothing to check, nothing to open */
    accepted = 0;
    for (i = 0; i < WG_BOX_TAG_LEN; i++)
        if (!refused_clean(box, i, nonce, key)) accepted++;
    CHECK(accepted == 0);
    CHECK(refused_clean(NULL, 0, nonce, key));
}

TEST(box_rejects_wrong_keys)
{
    wg_key csk, cpk, ssk, spk, xsk, xpk;
    uint8_t bnonce[24], box[BUF_MAX], out[BUF_MAX];
    size_t len;

    load_key(&csk, KAT_BOX_CLIENT_SK);
    load_key(&cpk, KAT_BOX_CLIENT_PK);
    load_key(&ssk, KAT_BOX_SERVER_SK);
    load_key(&spk, KAT_BOX_SERVER_PK);
    load(bnonce, 24, KAT_BOX_NONCE);
    len = t_hex(box, sizeof(box), vec_of_len(33)->box);
    REQUIRE(wg_key_generate(&xsk, &xpk));

    memset(out, SENTINEL, sizeof(out));
    CHECK(!wg_box_open(out, box, len, bnonce, &xpk, &ssk));    /* not from this client */
    CHECK(!wg_box_open(out, box, len, bnonce, &cpk, &xsk));    /* not for this server */
    CHECK(!wg_box_open(out, box, len, bnonce, &spk, &xsk));
    CHECK(all_sentinel(out, sizeof(out)));

    /* The sender opens its own box: beforenm is symmetric (why a nonce may not repeat in either
     * direction). */
    CHECK(wg_box_open(out, box, len, bnonce, &spk, &csk));
}

TEST(low_order_keys)
{
    wg_key sk, pk, zero, small;
    uint8_t k[32], nonce[24], zero32[32], k_any[32], forged[WG_BOX_TAG_LEN + 1], out[64];

    REQUIRE(wg_key_generate(&sk, &pk));
    memset(&zero, 0, sizeof(zero));
    load_key(&small, KAT_NACL_SMALL_ORDER);
    memset(nonce, 0, sizeof(nonce));
    memset(zero32, 0, sizeof(zero32));

    /* The X25519 result is zero: the box key would be one anybody can compute. */
    CHECK(!wg_box_beforenm(k, &zero, &sk));
    CHECK(!wg_box_beforenm(k, &small, &sk));

    /* That key - HSalsa20 of 32 zero bytes, what Go's box.Precompute derives for such a point -
     * seals a box anyone could have made. Go would open it; we do not. */
    wg_hsalsa20(k_any, zero32, zero32);
    REQUIRE(wg_secretbox_seal(forged, "x", 1, nonce, k_any));

    memset(out, SENTINEL, sizeof(out));
    CHECK(!wg_box_open(out, forged, sizeof(forged), nonce, &small, &sk));
    CHECK(!wg_box_open(out, forged, sizeof(forged), nonce, &zero, &sk));
    CHECK(!wg_box_seal(out, "x", 1, nonce, &small, &sk));
    CHECK(!wg_box_seal(out, "x", 1, nonce, &zero, &sk));
    CHECK(all_sentinel(out, sizeof(out)));
}

TEST(empty_message)
{
    wg_key csk, cpk, ssk, spk;
    uint8_t key[32], nonce[24], bnonce[24], want[16], box[16];

    load(key, 32, KAT_SECRETBOX_KEY);
    load(nonce, 24, KAT_SECRETBOX_NONCE);
    load(want, 16, vec_of_len(0)->secretbox);

    /* An empty message seals to the tag alone; NULL is a fine empty message, and a NULL `out`
     * a fine place for one. */
    CHECK(wg_secretbox_seal(box, NULL, 0, nonce, key));
    CHECK_MEM(box, want, 16);
    CHECK(wg_secretbox_open(NULL, box, 16, nonce, key));
    box[15] ^= 0x80;
    CHECK(!wg_secretbox_open(NULL, box, 16, nonce, key));

    load_key(&csk, KAT_BOX_CLIENT_SK);
    load_key(&cpk, KAT_BOX_CLIENT_PK);
    load_key(&ssk, KAT_BOX_SERVER_SK);
    load_key(&spk, KAT_BOX_SERVER_PK);
    load(bnonce, 24, KAT_BOX_NONCE);
    load(want, 16, vec_of_len(0)->box);
    CHECK(wg_box_seal(box, NULL, 0, bnonce, &spk, &csk));
    CHECK_MEM(box, want, 16);
    CHECK(wg_box_open(NULL, box, 16, bnonce, &cpk, &ssk));
}

TEST(in_place)
{
    uint8_t key[32], nonce[24], msg[MSG_MAX], want[BUF_MAX], buf[BUF_MAX];
    size_t i, n, wlen;

    load(key, 32, KAT_SECRETBOX_KEY);
    load(nonce, 24, KAT_SECRETBOX_NONCE);
    load(msg, sizeof(msg), KAT_BOX_MSG);

    for (i = 0; i < sizeof(KAT_BOX_VECS) / sizeof(KAT_BOX_VECS[0]); i++) {
        n = KAT_BOX_VECS[i].len;
        wlen = t_hex(want, sizeof(want), KAT_BOX_VECS[i].secretbox);

        /* seal, msg == out: the message at the start, room for the tag at the end */
        memcpy(buf, msg, n);
        CHECK(wg_secretbox_seal(buf, buf, n, nonce, key));
        CHECK_MEM(buf, want, wlen);
        /* seal, msg == out + 16: room for the tag in front */
        memcpy(buf + WG_BOX_TAG_LEN, msg, n);
        CHECK(wg_secretbox_seal(buf, buf + WG_BOX_TAG_LEN, n, nonce, key));
        CHECK_MEM(buf, want, wlen);
        /* seal, any other overlap */
        memcpy(buf + 5, msg, n);
        CHECK(wg_secretbox_seal(buf, buf + 5, n, nonce, key));
        CHECK_MEM(buf, want, wlen);

        /* open, out == box: the message where the box started */
        memcpy(buf, want, wlen);
        CHECK(wg_secretbox_open(buf, buf, wlen, nonce, key));
        CHECK_MEM(buf, msg, n);
        /* open, out == box + 16: over the ciphertext */
        memcpy(buf, want, wlen);
        CHECK(wg_secretbox_open(buf + WG_BOX_TAG_LEN, buf, wlen, nonce, key));
        CHECK_MEM(buf + WG_BOX_TAG_LEN, msg, n);
        /* open, out past the box start */
        memcpy(buf, want, wlen);
        CHECK(wg_secretbox_open(buf + 9, buf, wlen, nonce, key));
        CHECK_MEM(buf + 9, msg, n);

        /* a forged box opened in place stays exactly as it was */
        memcpy(buf, want, wlen);
        buf[wlen - 1] ^= 0x01;
        CHECK(!wg_secretbox_open(buf, buf, wlen, nonce, key));
        buf[wlen - 1] ^= 0x01;
        CHECK_MEM(buf, want, wlen);
    }
}

TEST(random_roundtrips)
{
    wg_key a_sk, a_pk, b_sk, b_pk, c_sk, c_pk;
    uint8_t msg[1500], box[1500 + WG_BOX_TAG_LEN], out[1500 + WG_BOX_TAG_LEN];
    uint8_t nonce[24], k_ab[32], k_ba[32];
    int round, bad_seal = 0, bad_open = 0, bad_sender = 0, bad_third = 0, bad_afternm = 0;
    size_t len;

    REQUIRE(wg_key_generate(&a_sk, &a_pk));
    REQUIRE(wg_key_generate(&b_sk, &b_pk));
    REQUIRE(wg_key_generate(&c_sk, &c_pk));
    REQUIRE(wg_box_beforenm(k_ab, &b_pk, &a_sk));
    REQUIRE(wg_box_beforenm(k_ba, &a_pk, &b_sk));
    CHECK_MEM(k_ab, k_ba, 32);

    for (round = 0; round < 200; round++) {
        len = wg_rng_below(NULL, sizeof(msg) + 1);
        if (!wg_random(msg, sizeof(msg)) || !wg_random(nonce, sizeof(nonce)) ||
            !wg_box_seal(box, msg, len, nonce, &b_pk, &a_sk)) {
            bad_seal++;
            continue;
        }

        memset(out, 0, sizeof(out));
        if (!wg_box_open(out, box, len + WG_BOX_TAG_LEN, nonce, &a_pk, &b_sk) ||
            memcmp(out, msg, len) != 0)
            bad_open++;
        memset(out, 0, sizeof(out));
        if (!wg_box_open(out, box, len + WG_BOX_TAG_LEN, nonce, &b_pk, &a_sk) ||
            memcmp(out, msg, len) != 0)
            bad_sender++;
        if (wg_box_open(out, box, len + WG_BOX_TAG_LEN, nonce, &a_pk, &c_sk))
            bad_third++;
        if (!wg_secretbox_seal(out, msg, len, nonce, k_ab) || memcmp(out, box, len + WG_BOX_TAG_LEN) != 0)
            bad_afternm++;
    }
    CHECK(bad_seal == 0);
    CHECK(bad_open == 0);       /* b opens what a sealed to it */
    CHECK(bad_sender == 0);     /* so does a: one key for both ends */
    CHECK(bad_third == 0);      /* c does not */
    CHECK(bad_afternm == 0);    /* box == secretbox under beforenm */
}

TEST(seal_rejects_overflow)
{
    uint8_t key[32], nonce[24], out[64];

    memset(key, 0x11, sizeof(key));
    memset(nonce, 0x22, sizeof(nonce));
    memset(out, SENTINEL, sizeof(out));

    /* len + 16 would wrap: refused before a byte is read or written */
    CHECK(!wg_secretbox_seal(out, out, (size_t)-1, nonce, key));
    CHECK(!wg_secretbox_seal(out, out, (size_t)-1 - (WG_BOX_TAG_LEN - 1), nonce, key));
    CHECK(all_sentinel(out, sizeof(out)));
}

int main(void)
{
    uint8_t tag[16], key[32];

    if (!wg_crypto_init()) {
        fprintf(stderr, "wg_crypto_init failed\n");
        return 2;
    }
    memset(key, 0, sizeof(key));
    if (!wg_poly1305(tag, key, NULL, 0)) {
        fprintf(stderr, "OpenSSL has no POLY1305 MAC (EVP_MAC_fetch) - wg_salsa cannot work\n");
        return 2;
    }
    RUN(hsalsa20_nacl);
    RUN(xsalsa20_nacl);
    RUN(poly1305_rfc8439_and_nacl);
    RUN(box_nacl);
    RUN(xsalsa20_go);
    RUN(beforenm_go);
    RUN(vectors_go);
    RUN(derp_client_info);
    RUN(derp_server_info);
    RUN(open_rejects_tampering);
    RUN(box_rejects_wrong_keys);
    RUN(low_order_keys);
    RUN(empty_message);
    RUN(in_place);
    RUN(random_roundtrips);
    RUN(seal_rejects_overflow);
    wg_crypto_cleanup();
    return t_summary("test_salsa");
}
