/*
 * wg_crypto - the primitives WireGuard needs, on top of OpenSSL 3.x.
 *
 * Sans-IO: pure functions, no sockets, no allocation of long-lived state, no globals except a
 * one-time fetch of the OpenSSL algorithm objects. That keeps the protocol core testable on the
 * workstation and portable to QNX unchanged (docs/PLAN.md).
 *
 * WireGuard uses Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s:
 *   X25519                    key agreement
 *   ChaCha20-Poly1305 (IETF)  handshake fields and transport data, 12-byte nonce
 *   XChaCha20-Poly1305        cookie replies only, 24-byte nonce
 *   BLAKE2s-256               hashing, and keyed with a 16-byte output for mac1/mac2
 *   HMAC-BLAKE2s              the KDF
 *
 * OpenSSL has all of it except XChaCha20-Poly1305, so HChaCha20 is implemented here (it is a
 * dozen lines of the ChaCha core) and composed with the ordinary AEAD.
 *
 * Every function returns 1 on success and 0 on failure - the OpenSSL convention, so a missed
 * check looks wrong in review rather than reading like a POSIX 0-is-success.
 */

#ifndef WG_CRYPTO_H
#define WG_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define WG_KEY_LEN   32
#define WG_HASH_LEN  32
#define WG_MAC_LEN   16     /* mac1 / mac2: keyed BLAKE2s truncated to 16 bytes */
#define WG_TAG_LEN   16     /* Poly1305 tag */
#define WG_XNONCE_LEN 24

typedef struct { uint8_t b[WG_KEY_LEN]; } wg_key;

/* Fetches the OpenSSL algorithm objects once. Safe to call repeatedly; call before the rest. */
int wg_crypto_init(void);
void wg_crypto_cleanup(void);

/* --- randomness ------------------------------------------------------------------------- */
int wg_random(void* buf, size_t len);

/*
 * A pluggable source of random bytes. The engine leaves it empty and gets wg_random (OpenSSL's
 * CSPRNG); the tests plug in a scripted source, so a whole handshake transcript - ephemeral keys,
 * cookie secret, nonces - is reproducible byte for byte against a reference implementation.
 */
typedef struct {
    int (*fn)(void* ctx, void* buf, size_t len);    /* 1 on success, like the rest of this API */
    void* ctx;
} wg_rng;

/* Bytes from `rng`, or from wg_random when rng is NULL or has no fn. */
int wg_rng_bytes(const wg_rng* rng, void* buf, size_t len);

/* Uniform in [0, n) from 4 bytes of `rng` (multiply-shift, as Go's fastrandn); 0 for n == 0 or
 * when the source fails. */
uint32_t wg_rng_below(const wg_rng* rng, uint32_t n);

/* --- X25519 ---------------------------------------------------------------------------- */
int wg_key_generate(wg_key* sk, wg_key* pk);
int wg_key_public(const wg_key* sk, wg_key* pk);

/*
 * Clamps a private key the way `wg genkey` and the kernel store it. X25519 clamps the scalar
 * internally anyway, so this changes the stored bytes, never a result.
 */
void wg_key_clamp(wg_key* sk);

/* A key pair from 32 bytes of `rng` (see wg_rng), clamped. */
int wg_key_generate_rng(const wg_rng* rng, wg_key* sk, wg_key* pk);

/*
 * Diffie-Hellman. Returns 0 when the shared secret is all zeroes, which is what a peer sending a
 * low-order point produces; WireGuard treats that as a failed handshake rather than a usable key.
 */
int wg_dh(const wg_key* sk, const wg_key* peer_pk, uint8_t out[WG_KEY_LEN]);

/* --- BLAKE2s --------------------------------------------------------------------------- */
int wg_hash(uint8_t out[WG_HASH_LEN], const void* in, size_t len);
/* hash(a || b) - the shape the Noise handshake mixes in, without a scratch buffer at the caller */
int wg_hash2(uint8_t out[WG_HASH_LEN], const void* a, size_t alen, const void* b, size_t blen);
/* keyed BLAKE2s with a 16-byte output: mac1 and mac2 */
int wg_mac16(uint8_t out[WG_MAC_LEN], const void* key, size_t keylen, const void* in, size_t len);
/* keyed BLAKE2s with a 32-byte output: the cookie derivation */
int wg_mac32(uint8_t out[WG_HASH_LEN], const void* key, size_t keylen, const void* in, size_t len);

/* --- KDF ------------------------------------------------------------------------------- */
int wg_hmac(uint8_t out[WG_HASH_LEN], const uint8_t key[WG_HASH_LEN], const void* in, size_t len);

/*
 * The WireGuard KDF, written out as the HMAC chain from the whitepaper rather than through
 * OpenSSL's HKDF: the transport keys derive from an EMPTY input, and a KDF API that rejects a
 * zero-length input would fail exactly there. Pass NULL for the outputs you do not need.
 *
 *   t0 = HMAC(key, input); t1 = HMAC(t0, 0x1); t2 = HMAC(t0, t1 || 0x2); t3 = HMAC(t0, t2 || 0x3)
 */
int wg_kdf(uint8_t* out1, uint8_t* out2, uint8_t* out3,
           const uint8_t key[WG_HASH_LEN], const void* in, size_t len);

/* --- AEAD ------------------------------------------------------------------------------ */
/*
 * ChaCha20-Poly1305 with WireGuard's nonce: 4 zero bytes followed by the 64-bit counter,
 * little-endian. `out` needs ptlen + WG_TAG_LEN bytes on encrypt, ctlen - WG_TAG_LEN on decrypt.
 */
int wg_aead_encrypt(uint8_t* out, const uint8_t key[WG_KEY_LEN], uint64_t counter,
                    const void* pt, size_t ptlen, const void* ad, size_t adlen);
int wg_aead_decrypt(uint8_t* out, const uint8_t key[WG_KEY_LEN], uint64_t counter,
                    const void* ct, size_t ctlen, const void* ad, size_t adlen);

/*
 * The same AEAD with the nonce spelled out. WireGuard itself always uses the counter form above,
 * but an explicit nonce is what the RFC 8439 test vectors are written against, and an obfuscation
 * layer that reshapes the nonce (AmneziaWG) needs it too.
 */
int wg_aead_encrypt_n(uint8_t* out, const uint8_t key[WG_KEY_LEN], const uint8_t nonce[12],
                      const void* pt, size_t ptlen, const void* ad, size_t adlen);
int wg_aead_decrypt_n(uint8_t* out, const uint8_t key[WG_KEY_LEN], const uint8_t nonce[12],
                      const void* ct, size_t ctlen, const void* ad, size_t adlen);

/* XChaCha20-Poly1305, used for cookie replies. */
int wg_xaead_encrypt(uint8_t* out, const uint8_t key[WG_KEY_LEN], const uint8_t nonce[WG_XNONCE_LEN],
                     const void* pt, size_t ptlen, const void* ad, size_t adlen);
int wg_xaead_decrypt(uint8_t* out, const uint8_t key[WG_KEY_LEN], const uint8_t nonce[WG_XNONCE_LEN],
                     const void* ct, size_t ctlen, const void* ad, size_t adlen);

/* HChaCha20, exposed because the XChaCha composition and its test vectors both need it. */
void wg_hchacha20(uint8_t out[WG_KEY_LEN], const uint8_t key[WG_KEY_LEN], const uint8_t nonce[16]);

/*
 * Plain ChaCha20 (RFC 8439: 96-bit nonce, 32-bit block counter), keystream XORed into `in`; `out`
 * may be `in`. Not WireGuard's - AmneziaWG's header protection, which covers at most one message,
 * so a portable block function is all it needs.
 */
void wg_chacha20_xor(uint8_t* out, const uint8_t* in, size_t len, const uint8_t key[WG_KEY_LEN],
                     const uint8_t nonce[12], uint32_t counter);

/* --- misc ------------------------------------------------------------------------------ */
int wg_ct_equal(const void* a, const void* b, size_t len);
void wg_wipe(void* p, size_t len);

#endif /* WG_CRYPTO_H */
