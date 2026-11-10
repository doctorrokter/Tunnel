/*
 * wg_salsa - see wg_salsa.h.
 *
 * The Salsa20 core follows TweetNaCl (Bernstein, van Gastel, Janssen, Lange, Schwabe, Smetsers;
 * public domain) and the Salsa20 specification, in the shape of wg_crypto's HChaCha20: it is
 * ARX only - no table, no branch on a secret - so it runs in constant time as written.
 *
 * Poly1305 is fetched from OpenSSL per call instead of being kept like wg_crypto's objects: a box
 * is sealed or opened a couple of times per DERP connection, and this file keeps no state. The
 * default provider of our static OpenSSL 3.5.8 carries it (defltprov.o references
 * ossl_poly1305_functions), and Poly1305_Final wipes the MAC state before the context is freed.
 */

#include "wg_salsa.h"

#include <string.h>

#include <openssl/evp.h>

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

static uint32_t load32_le(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store32_le(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

/* ---------------------------------------------------------------------------- Salsa20 core */

/* The Salsa20 quarterround of the specification: add, rotate, xor. */
#define QR(a, b, c, d)                                    \
    do {                                                  \
        b ^= ROTL32(a + d, 7);                            \
        c ^= ROTL32(b + a, 9);                            \
        d ^= ROTL32(c + b, 13);                           \
        a ^= ROTL32(d + c, 18);                           \
    } while (0)

/* Twenty rounds as ten double rounds: a column round, then a row round. */
static void salsa20_rounds(uint32_t x[16])
{
    int i;

    for (i = 0; i < 10; i++) {
        QR(x[0],  x[4],  x[8],  x[12]);
        QR(x[5],  x[9],  x[13], x[1]);
        QR(x[10], x[14], x[2],  x[6]);
        QR(x[15], x[3],  x[7],  x[11]);

        QR(x[0],  x[1],  x[2],  x[3]);
        QR(x[5],  x[6],  x[7],  x[4]);
        QR(x[10], x[11], x[8],  x[9]);
        QR(x[15], x[12], x[13], x[14]);
    }
}

/*
 * The state for a 32-byte key: "expand 32-byte k" on the diagonal, the key in words 1-4 and
 * 11-14, and 16 bytes of input in words 6-9 - the nonce and the block counter for Salsa20, the
 * first 16 nonce bytes for HSalsa20. (ChaCha lays the same pieces out in rows.)
 */
static void salsa20_state(uint32_t s[16], const uint8_t key[WG_BOX_KEY_LEN], const uint8_t in[16])
{
    int i;

    s[0] = 0x61707865; s[5] = 0x3320646e; s[10] = 0x79622d32; s[15] = 0x6b206574;
    for (i = 0; i < 4; i++) {
        s[1 + i]  = load32_le(key + 4 * i);
        s[11 + i] = load32_le(key + 16 + 4 * i);
        s[6 + i]  = load32_le(in + 4 * i);
    }
}

/* One Salsa20 block: the rounds, then the feed-forward addition. The counter is 64-bit
 * little-endian after the 8-byte nonce, so it never wraps for anything we could hold. */
static void salsa20_block(uint8_t out[64], const uint8_t key[WG_BOX_KEY_LEN], const uint8_t nonce[8],
                          uint64_t counter)
{
    uint8_t in[16];
    uint32_t s[16], x[16];
    int i;

    memcpy(in, nonce, 8);
    for (i = 0; i < 8; i++) in[8 + i] = (uint8_t)(counter >> (8 * i));
    salsa20_state(s, key, in);
    memcpy(x, s, sizeof(x));
    salsa20_rounds(x);
    for (i = 0; i < 16; i++) store32_le(out + 4 * i, x[i] + s[i]);

    wg_wipe(s, sizeof(s));
    wg_wipe(x, sizeof(x));
}

/* Salsa20 keystream from block `counter` on, XORed into `in`; `out` may be `in`. */
static void salsa20_xor(uint8_t* out, const uint8_t* in, size_t len, const uint8_t key[WG_BOX_KEY_LEN],
                        const uint8_t nonce[8], uint64_t counter)
{
    uint8_t ks[64];
    size_t i, n;

    while (len) {
        salsa20_block(ks, key, nonce, counter++);
        n = len < 64 ? len : 64;
        for (i = 0; i < n; i++) out[i] = in[i] ^ ks[i];
        out += n;
        in += n;
        len -= n;
    }
    wg_wipe(ks, sizeof(ks));
}

/*
 * HSalsa20: the rounds without the feed-forward, returning the eight words whose starting values
 * are public - the diagonal and the input. TweetNaCl adds the starting state and subtracts those
 * eight back out; the result is the same.
 */
void wg_hsalsa20(uint8_t out[WG_BOX_KEY_LEN], const uint8_t key[WG_BOX_KEY_LEN], const uint8_t in[16])
{
    uint32_t x[16];
    int i;

    salsa20_state(x, key, in);
    salsa20_rounds(x);
    for (i = 0; i < 4; i++) {
        store32_le(out + 4 * i,      x[5 * i]);     /* 0, 5, 10, 15 */
        store32_le(out + 16 + 4 * i, x[6 + i]);     /* 6, 7, 8, 9 */
    }
    wg_wipe(x, sizeof(x));
}

/* XSalsa20 = Salsa20 under HSalsa20(key, nonce[0..16]) with nonce[16..24] as its nonce. */
void wg_xsalsa20_xor(uint8_t* out, const uint8_t* in, size_t len,
                     const uint8_t nonce[WG_BOX_NONCE_LEN], const uint8_t key[WG_BOX_KEY_LEN])
{
    uint8_t subkey[WG_BOX_KEY_LEN], n8[8];

    wg_hsalsa20(subkey, key, nonce);
    memcpy(n8, nonce + 16, sizeof(n8));
    salsa20_xor(out, in, len, subkey, n8, 0);
    wg_wipe(subkey, sizeof(subkey));
}

/* ---------------------------------------------------------------------------- Poly1305 */

int wg_poly1305(uint8_t tag[WG_BOX_TAG_LEN], const uint8_t key[WG_BOX_KEY_LEN],
                const void* msg, size_t len)
{
    EVP_MAC* mac = EVP_MAC_fetch(NULL, "POLY1305", NULL);
    EVP_MAC_CTX* ctx = NULL;
    size_t written = 0;
    int ok = 0;

    if (!mac) return 0;
    ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) goto out;
    if (EVP_MAC_init(ctx, key, WG_BOX_KEY_LEN, NULL) != 1) goto out;
    if (len && EVP_MAC_update(ctx, (const unsigned char*)msg, len) != 1) goto out;
    if (EVP_MAC_final(ctx, tag, &written, WG_BOX_TAG_LEN) != 1 || written != WG_BOX_TAG_LEN) goto out;
    ok = 1;
out:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ok;
}

/* ---------------------------------------------------------------------------- secretbox */

/*
 * What seal and open share: the XSalsa20 subkey, the last 8 nonce bytes and block 0 of the
 * stream - its first 32 bytes are the Poly1305 key, the other 32 encrypt the first 32 message
 * bytes. All of it is taken before `out` is written, which is what lets the nonce and the key
 * live in the caller's buffer next to the box.
 */
typedef struct {
    uint8_t subkey[WG_BOX_KEY_LEN];
    uint8_t n8[8];
    uint8_t block0[64];
} secretbox_keys;

static void secretbox_setup(secretbox_keys* k, const uint8_t nonce[WG_BOX_NONCE_LEN],
                            const uint8_t key[WG_BOX_KEY_LEN])
{
    wg_hsalsa20(k->subkey, key, nonce);
    memcpy(k->n8, nonce + 16, sizeof(k->n8));
    salsa20_block(k->block0, k->subkey, k->n8, 0);
}

/* The stream from byte 32 on, XORed into buf in place: the rest of block 0, then block 1 on. */
static void secretbox_xor(const secretbox_keys* k, uint8_t* buf, size_t len)
{
    size_t head = len < 32 ? len : 32, i;

    if (!len) return;
    for (i = 0; i < head; i++) buf[i] ^= k->block0[32 + i];
    salsa20_xor(buf + head, buf + head, len - head, k->subkey, k->n8, 1);
}

int wg_secretbox_seal(uint8_t* out, const void* msg, size_t len,
                      const uint8_t nonce[WG_BOX_NONCE_LEN], const uint8_t key[WG_BOX_KEY_LEN])
{
    secretbox_keys k;
    uint8_t* ct = out + WG_BOX_TAG_LEN;
    int ok;

    if (len > (size_t)-1 - WG_BOX_TAG_LEN) return 0;
    secretbox_setup(&k, nonce, key);

    /* Move the message where the ciphertext goes, then encrypt it there: memmove is right for
     * every overlap of msg and out, and the XOR in place is then trivially safe. */
    if (len && (const void*)ct != msg) memmove(ct, msg, len);
    secretbox_xor(&k, ct, len);

    ok = wg_poly1305(out, k.block0, ct, len);
    /* With msg == out the first 16 bytes still hold plaintext until the tag lands on them. */
    if (!ok) wg_wipe(out, len + WG_BOX_TAG_LEN);
    wg_wipe(&k, sizeof(k));
    return ok;
}

int wg_secretbox_open(uint8_t* out, const void* box, size_t len,
                      const uint8_t nonce[WG_BOX_NONCE_LEN], const uint8_t key[WG_BOX_KEY_LEN])
{
    const uint8_t* b = (const uint8_t*)box;
    secretbox_keys k;
    uint8_t tag[WG_BOX_TAG_LEN];
    size_t mlen;
    int ok = 0;

    if (len < WG_BOX_TAG_LEN) return 0;
    mlen = len - WG_BOX_TAG_LEN;
    secretbox_setup(&k, nonce, key);

    if (!wg_poly1305(tag, k.block0, b + WG_BOX_TAG_LEN, mlen)) goto out;
    /* Constant time, and before a byte is decrypted: a forged box never yields plaintext. */
    if (!wg_ct_equal(tag, b, WG_BOX_TAG_LEN)) goto out;

    if (mlen) {
        if (out != b + WG_BOX_TAG_LEN) memmove(out, b + WG_BOX_TAG_LEN, mlen);
        secretbox_xor(&k, out, mlen);
    }
    ok = 1;
out:
    wg_wipe(&k, sizeof(k));
    wg_wipe(tag, sizeof(tag));
    return ok;
}

/* ---------------------------------------------------------------------------- box */

int wg_box_beforenm(uint8_t k[WG_BOX_KEY_LEN], const wg_key* their_pk, const wg_key* our_sk)
{
    static const uint8_t zero[16];
    uint8_t shared[WG_KEY_LEN];

    if (!wg_dh(our_sk, their_pk, shared)) {
        wg_wipe(shared, sizeof(shared));
        return 0;
    }
    wg_hsalsa20(k, shared, zero);
    wg_wipe(shared, sizeof(shared));
    return 1;
}

int wg_box_seal(uint8_t* out, const void* msg, size_t len, const uint8_t nonce[WG_BOX_NONCE_LEN],
                const wg_key* their_pk, const wg_key* our_sk)
{
    uint8_t k[WG_BOX_KEY_LEN];
    int ok;

    if (!wg_box_beforenm(k, their_pk, our_sk)) return 0;
    ok = wg_secretbox_seal(out, msg, len, nonce, k);
    wg_wipe(k, sizeof(k));
    return ok;
}

int wg_box_open(uint8_t* out, const void* box, size_t len, const uint8_t nonce[WG_BOX_NONCE_LEN],
                const wg_key* their_pk, const wg_key* our_sk)
{
    uint8_t k[WG_BOX_KEY_LEN];
    int ok;

    if (!wg_box_beforenm(k, their_pk, our_sk)) return 0;
    ok = wg_secretbox_open(out, box, len, nonce, k);
    wg_wipe(k, sizeof(k));
    return ok;
}
