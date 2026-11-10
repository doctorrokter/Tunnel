/*
 * wg_crypto - see wg_crypto.h.
 *
 * Everything routes through the OpenSSL 3.x EVP interfaces, so the same source builds against the
 * workstation's OpenSSL for tests and against our cross-built 3.5.8 for the phone. On BB10 that
 * library has the NEON paths compiled in and the SIGILL CPU probe patched out, so the daemon must
 * NOT set OPENSSL_armcap: a value of 0 in the environment would override the patch and turn NEON
 * off (bb-shared KB 3.8).
 */

#include "wg_crypto.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>

/* Fetched once. NULL until wg_crypto_init() runs. */
static EVP_MD*     g_blake2s;      /* BLAKE2S-256, unkeyed */
static EVP_MAC*    g_mac_blake2s;  /* BLAKE2SMAC, for mac1/mac2 and the cookie key */
static EVP_MAC*    g_mac_hmac;     /* HMAC, instantiated with BLAKE2S-256 */
static EVP_CIPHER* g_chacha20poly1305;
static int         g_ready;

int wg_crypto_init(void)
{
    if (g_ready) return 1;

    g_blake2s           = EVP_MD_fetch(NULL, "BLAKE2S-256", NULL);
    g_mac_blake2s       = EVP_MAC_fetch(NULL, "BLAKE2SMAC", NULL);
    g_mac_hmac          = EVP_MAC_fetch(NULL, "HMAC", NULL);
    g_chacha20poly1305  = EVP_CIPHER_fetch(NULL, "ChaCha20-Poly1305", NULL);

    if (!g_blake2s || !g_mac_blake2s || !g_mac_hmac || !g_chacha20poly1305) {
        wg_crypto_cleanup();
        return 0;
    }
    g_ready = 1;
    return 1;
}

void wg_crypto_cleanup(void)
{
    EVP_MD_free(g_blake2s);                 g_blake2s = NULL;
    EVP_MAC_free(g_mac_blake2s);            g_mac_blake2s = NULL;
    EVP_MAC_free(g_mac_hmac);               g_mac_hmac = NULL;
    EVP_CIPHER_free(g_chacha20poly1305);    g_chacha20poly1305 = NULL;
    g_ready = 0;
}

int wg_random(void* buf, size_t len)
{
    return RAND_bytes((unsigned char*)buf, (int)len) == 1;
}

int wg_rng_bytes(const wg_rng* rng, void* buf, size_t len)
{
    if (rng && rng->fn) return rng->fn(rng->ctx, buf, len);
    return wg_random(buf, len);
}

uint32_t wg_rng_below(const wg_rng* rng, uint32_t n)
{
    uint32_t r = 0;

    if (!n || !wg_rng_bytes(rng, &r, sizeof(r))) return 0;
    return (uint32_t)(((uint64_t)r * n) >> 32);
}

int wg_ct_equal(const void* a, const void* b, size_t len)
{
    return CRYPTO_memcmp(a, b, len) == 0;
}

void wg_wipe(void* p, size_t len)
{
    OPENSSL_cleanse(p, len);
}

/* ---------------------------------------------------------------------------- X25519 */

int wg_key_generate(wg_key* sk, wg_key* pk)
{
    EVP_PKEY* key = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    size_t len;
    int ok = 0;

    if (!key) return 0;

    len = WG_KEY_LEN;
    if (EVP_PKEY_get_raw_private_key(key, sk->b, &len) != 1 || len != WG_KEY_LEN) goto out;
    len = WG_KEY_LEN;
    if (EVP_PKEY_get_raw_public_key(key, pk->b, &len) != 1 || len != WG_KEY_LEN) goto out;
    ok = 1;
out:
    EVP_PKEY_free(key);
    return ok;
}

int wg_key_public(const wg_key* sk, wg_key* pk)
{
    EVP_PKEY* key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk->b, WG_KEY_LEN);
    size_t len = WG_KEY_LEN;
    int ok;

    if (!key) return 0;
    ok = EVP_PKEY_get_raw_public_key(key, pk->b, &len) == 1 && len == WG_KEY_LEN;
    EVP_PKEY_free(key);
    return ok;
}

void wg_key_clamp(wg_key* sk)
{
    sk->b[0] &= 248;
    sk->b[31] &= 127;
    sk->b[31] |= 64;
}

int wg_key_generate_rng(const wg_rng* rng, wg_key* sk, wg_key* pk)
{
    if (!wg_rng_bytes(rng, sk->b, WG_KEY_LEN)) return 0;
    wg_key_clamp(sk);
    if (!wg_key_public(sk, pk)) {
        wg_wipe(sk, sizeof(*sk));
        return 0;
    }
    return 1;
}

int wg_dh(const wg_key* sk, const wg_key* peer_pk, uint8_t out[WG_KEY_LEN])
{
    EVP_PKEY* priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk->b, WG_KEY_LEN);
    EVP_PKEY* pub  = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pk->b, WG_KEY_LEN);
    EVP_PKEY_CTX* ctx = NULL;
    size_t len = WG_KEY_LEN;
    int ok = 0;
    uint8_t zero[WG_KEY_LEN];

    if (!priv || !pub) goto out;
    ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx || EVP_PKEY_derive_init(ctx) != 1) goto out;
    if (EVP_PKEY_derive_set_peer(ctx, pub) != 1) goto out;
    if (EVP_PKEY_derive(ctx, out, &len) != 1 || len != WG_KEY_LEN) goto out;

    /*
     * A low-order public key yields an all-zero shared secret. OpenSSL may or may not reject it
     * depending on version, so check here and make it a failure either way - continuing would
     * hand an attacker a handshake with a predictable key.
     */
    memset(zero, 0, sizeof(zero));
    ok = !wg_ct_equal(out, zero, WG_KEY_LEN);
    if (!ok) wg_wipe(out, WG_KEY_LEN);
out:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pub);
    EVP_PKEY_free(priv);
    return ok;
}

/* ---------------------------------------------------------------------------- BLAKE2s */

int wg_hash2(uint8_t out[WG_HASH_LEN], const void* a, size_t alen, const void* b, size_t blen)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    unsigned int n = 0;
    int ok = 0;

    if (!ctx || !g_ready) goto out;
    if (EVP_DigestInit_ex(ctx, g_blake2s, NULL) != 1) goto out;
    if (alen && EVP_DigestUpdate(ctx, a, alen) != 1) goto out;
    if (blen && EVP_DigestUpdate(ctx, b, blen) != 1) goto out;
    if (EVP_DigestFinal_ex(ctx, out, &n) != 1 || n != WG_HASH_LEN) goto out;
    ok = 1;
out:
    EVP_MD_CTX_free(ctx);
    return ok;
}

int wg_hash(uint8_t out[WG_HASH_LEN], const void* in, size_t len)
{
    return wg_hash2(out, in, len, NULL, 0);
}

/* Keyed BLAKE2s with an explicit output length - BLAKE2SMAC takes both as parameters. */
static int blake2s_keyed(uint8_t* out, size_t outlen,
                         const void* key, size_t keylen, const void* in, size_t len)
{
    EVP_MAC_CTX* ctx = NULL;
    OSSL_PARAM params[3];
    size_t written = 0;
    size_t size = outlen;
    int ok = 0;

    if (!g_ready) return 0;
    ctx = EVP_MAC_CTX_new(g_mac_blake2s);
    if (!ctx) return 0;

    params[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &size);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, (void*)key, keylen);
    params[2] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(ctx, NULL, 0, params) != 1) goto out;
    if (len && EVP_MAC_update(ctx, (const unsigned char*)in, len) != 1) goto out;
    if (EVP_MAC_final(ctx, out, &written, outlen) != 1 || written != outlen) goto out;
    ok = 1;
out:
    EVP_MAC_CTX_free(ctx);
    return ok;
}

int wg_mac16(uint8_t out[WG_MAC_LEN], const void* key, size_t keylen, const void* in, size_t len)
{
    return blake2s_keyed(out, WG_MAC_LEN, key, keylen, in, len);
}

int wg_mac32(uint8_t out[WG_HASH_LEN], const void* key, size_t keylen, const void* in, size_t len)
{
    return blake2s_keyed(out, WG_HASH_LEN, key, keylen, in, len);
}

/* ---------------------------------------------------------------------------- KDF */

int wg_hmac(uint8_t out[WG_HASH_LEN], const uint8_t key[WG_HASH_LEN], const void* in, size_t len)
{
    EVP_MAC_CTX* ctx = NULL;
    OSSL_PARAM params[2];
    size_t written = 0;
    int ok = 0;

    if (!g_ready) return 0;
    ctx = EVP_MAC_CTX_new(g_mac_hmac);
    if (!ctx) return 0;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char*)"BLAKE2S-256", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(ctx, key, WG_HASH_LEN, params) != 1) goto out;
    if (len && EVP_MAC_update(ctx, (const unsigned char*)in, len) != 1) goto out;
    if (EVP_MAC_final(ctx, out, &written, WG_HASH_LEN) != 1 || written != WG_HASH_LEN) goto out;
    ok = 1;
out:
    EVP_MAC_CTX_free(ctx);
    return ok;
}

int wg_kdf(uint8_t* out1, uint8_t* out2, uint8_t* out3,
           const uint8_t key[WG_HASH_LEN], const void* in, size_t len)
{
    uint8_t t0[WG_HASH_LEN], t1[WG_HASH_LEN], t2[WG_HASH_LEN];
    uint8_t buf[WG_HASH_LEN + 1];
    int ok = 0;

    if (!wg_hmac(t0, key, in, len)) goto out;

    buf[0] = 0x1;
    if (!wg_hmac(t1, t0, buf, 1)) goto out;
    if (out1) memcpy(out1, t1, WG_HASH_LEN);
    if (!out2 && !out3) { ok = 1; goto out; }

    memcpy(buf, t1, WG_HASH_LEN);
    buf[WG_HASH_LEN] = 0x2;
    if (!wg_hmac(t2, t0, buf, sizeof(buf))) goto out;
    if (out2) memcpy(out2, t2, WG_HASH_LEN);
    if (!out3) { ok = 1; goto out; }

    memcpy(buf, t2, WG_HASH_LEN);
    buf[WG_HASH_LEN] = 0x3;
    if (!wg_hmac(out3, t0, buf, sizeof(buf))) goto out;
    ok = 1;
out:
    wg_wipe(t0, sizeof(t0));
    wg_wipe(t1, sizeof(t1));
    wg_wipe(t2, sizeof(t2));
    wg_wipe(buf, sizeof(buf));
    return ok;
}

/* ---------------------------------------------------------------------------- AEAD */

/* WireGuard's nonce: four zero bytes, then the counter little-endian. */
static void wg_nonce(uint8_t nonce[12], uint64_t counter)
{
    int i;
    memset(nonce, 0, 4);
    for (i = 0; i < 8; i++) nonce[4 + i] = (uint8_t)(counter >> (8 * i));
}

static int aead_encrypt(uint8_t* out, const EVP_CIPHER* cipher,
                        const uint8_t* key, const uint8_t* nonce, size_t noncelen,
                        const void* pt, size_t ptlen, const void* ad, size_t adlen)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len = 0, ok = 0;

    if (!ctx) return 0;
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)noncelen, NULL) != 1) goto out;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto out;
    if (adlen && EVP_EncryptUpdate(ctx, NULL, &len, (const unsigned char*)ad, (int)adlen) != 1) goto out;
    if (ptlen && EVP_EncryptUpdate(ctx, out, &len, (const unsigned char*)pt, (int)ptlen) != 1) goto out;
    if (EVP_EncryptFinal_ex(ctx, out + ptlen, &len) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, WG_TAG_LEN, out + ptlen) != 1) goto out;
    ok = 1;
out:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int aead_decrypt(uint8_t* out, const EVP_CIPHER* cipher,
                        const uint8_t* key, const uint8_t* nonce, size_t noncelen,
                        const void* ct, size_t ctlen, const void* ad, size_t adlen)
{
    EVP_CIPHER_CTX* ctx;
    const unsigned char* c = (const unsigned char*)ct;
    size_t ptlen;
    int len = 0, ok = 0;

    if (ctlen < WG_TAG_LEN) return 0;
    ptlen = ctlen - WG_TAG_LEN;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)noncelen, NULL) != 1) goto out;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto out;
    if (adlen && EVP_DecryptUpdate(ctx, NULL, &len, (const unsigned char*)ad, (int)adlen) != 1) goto out;
    if (ptlen && EVP_DecryptUpdate(ctx, out, &len, c, (int)ptlen) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, WG_TAG_LEN, (void*)(c + ptlen)) != 1) goto out;
    /* This is the authentication check: a forged or altered packet fails here. */
    if (EVP_DecryptFinal_ex(ctx, out + ptlen, &len) != 1) goto out;
    ok = 1;
out:
    EVP_CIPHER_CTX_free(ctx);
    if (!ok && ptlen) wg_wipe(out, ptlen);
    return ok;
}

int wg_aead_encrypt_n(uint8_t* out, const uint8_t key[WG_KEY_LEN], const uint8_t nonce[12],
                      const void* pt, size_t ptlen, const void* ad, size_t adlen)
{
    if (!g_ready) return 0;
    return aead_encrypt(out, g_chacha20poly1305, key, nonce, 12, pt, ptlen, ad, adlen);
}

int wg_aead_decrypt_n(uint8_t* out, const uint8_t key[WG_KEY_LEN], const uint8_t nonce[12],
                      const void* ct, size_t ctlen, const void* ad, size_t adlen)
{
    if (!g_ready) return 0;
    return aead_decrypt(out, g_chacha20poly1305, key, nonce, 12, ct, ctlen, ad, adlen);
}

int wg_aead_encrypt(uint8_t* out, const uint8_t key[WG_KEY_LEN], uint64_t counter,
                    const void* pt, size_t ptlen, const void* ad, size_t adlen)
{
    uint8_t nonce[12];
    wg_nonce(nonce, counter);
    return wg_aead_encrypt_n(out, key, nonce, pt, ptlen, ad, adlen);
}

int wg_aead_decrypt(uint8_t* out, const uint8_t key[WG_KEY_LEN], uint64_t counter,
                    const void* ct, size_t ctlen, const void* ad, size_t adlen)
{
    uint8_t nonce[12];
    wg_nonce(nonce, counter);
    return wg_aead_decrypt_n(out, key, nonce, ct, ctlen, ad, adlen);
}

/* ---------------------------------------------------------------------------- HChaCha20 */

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

static uint32_t load32_le(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store32_le(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

#define QR(a, b, c, d)                                    \
    do {                                                  \
        a += b; d ^= a; d = ROTL32(d, 16);                \
        c += d; b ^= c; b = ROTL32(b, 12);                \
        a += b; d ^= a; d = ROTL32(d, 8);                 \
        c += d; b ^= c; b = ROTL32(b, 7);                 \
    } while (0)

/*
 * HChaCha20 (RFC 8439 section 2.2 applied as in the XChaCha draft): the ChaCha20 core with no
 * feed-forward addition, returning the first and last rows as a subkey. OpenSSL has no
 * XChaCha20-Poly1305, and WireGuard needs it for cookie replies only.
 */
void wg_hchacha20(uint8_t out[WG_KEY_LEN], const uint8_t key[WG_KEY_LEN], const uint8_t nonce[16])
{
    uint32_t s[16];
    int i;

    s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
    for (i = 0; i < 8; i++)  s[4 + i]  = load32_le(key + 4 * i);
    for (i = 0; i < 4; i++)  s[12 + i] = load32_le(nonce + 4 * i);

    for (i = 0; i < 10; i++) {
        QR(s[0], s[4], s[8],  s[12]);
        QR(s[1], s[5], s[9],  s[13]);
        QR(s[2], s[6], s[10], s[14]);
        QR(s[3], s[7], s[11], s[15]);
        QR(s[0], s[5], s[10], s[15]);
        QR(s[1], s[6], s[11], s[12]);
        QR(s[2], s[7], s[8],  s[13]);
        QR(s[3], s[4], s[9],  s[14]);
    }

    for (i = 0; i < 4; i++) store32_le(out + 4 * i,        s[i]);
    for (i = 0; i < 4; i++) store32_le(out + 16 + 4 * i,   s[12 + i]);

    wg_wipe(s, sizeof(s));
}

/* One ChaCha20 block (RFC 8439 section 2.3): the rounds, then the feed-forward addition. */
static void chacha20_block(uint8_t out[64], const uint8_t key[WG_KEY_LEN], const uint8_t nonce[12],
                           uint32_t counter)
{
    uint32_t s[16], x[16];
    int i;

    s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
    for (i = 0; i < 8; i++) s[4 + i] = load32_le(key + 4 * i);
    s[12] = counter;
    for (i = 0; i < 3; i++) s[13 + i] = load32_le(nonce + 4 * i);
    memcpy(x, s, sizeof(x));

    for (i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8],  x[12]);
        QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]);
        QR(x[3], x[4], x[9],  x[14]);
    }
    for (i = 0; i < 16; i++) store32_le(out + 4 * i, x[i] + s[i]);

    wg_wipe(s, sizeof(s));
    wg_wipe(x, sizeof(x));
}

void wg_chacha20_xor(uint8_t* out, const uint8_t* in, size_t len, const uint8_t key[WG_KEY_LEN],
                     const uint8_t nonce[12], uint32_t counter)
{
    uint8_t ks[64];
    size_t i, n;

    while (len) {
        chacha20_block(ks, key, nonce, counter++);
        n = len < 64 ? len : 64;
        for (i = 0; i < n; i++) out[i] = in[i] ^ ks[i];
        out += n;
        in += n;
        len -= n;
    }
    wg_wipe(ks, sizeof(ks));
}

/*
 * XChaCha20-Poly1305 = HChaCha20(key, nonce[0..16]) as the subkey, then ordinary
 * ChaCha20-Poly1305 with the nonce 0,0,0,0 || nonce[16..24].
 */
static void xchacha_setup(uint8_t subkey[WG_KEY_LEN], uint8_t nonce12[12],
                          const uint8_t key[WG_KEY_LEN], const uint8_t nonce[WG_XNONCE_LEN])
{
    wg_hchacha20(subkey, key, nonce);
    memset(nonce12, 0, 4);
    memcpy(nonce12 + 4, nonce + 16, 8);
}

int wg_xaead_encrypt(uint8_t* out, const uint8_t key[WG_KEY_LEN], const uint8_t nonce[WG_XNONCE_LEN],
                     const void* pt, size_t ptlen, const void* ad, size_t adlen)
{
    uint8_t subkey[WG_KEY_LEN], nonce12[12];
    int ok;

    if (!g_ready) return 0;
    xchacha_setup(subkey, nonce12, key, nonce);
    ok = aead_encrypt(out, g_chacha20poly1305, subkey, nonce12, sizeof(nonce12), pt, ptlen, ad, adlen);
    wg_wipe(subkey, sizeof(subkey));
    return ok;
}

int wg_xaead_decrypt(uint8_t* out, const uint8_t key[WG_KEY_LEN], const uint8_t nonce[WG_XNONCE_LEN],
                     const void* ct, size_t ctlen, const void* ad, size_t adlen)
{
    uint8_t subkey[WG_KEY_LEN], nonce12[12];
    int ok;

    if (!g_ready) return 0;
    xchacha_setup(subkey, nonce12, key, nonce);
    ok = aead_decrypt(out, g_chacha20poly1305, subkey, nonce12, sizeof(nonce12), ct, ctlen, ad, adlen);
    wg_wipe(subkey, sizeof(subkey));
    return ok;
}
