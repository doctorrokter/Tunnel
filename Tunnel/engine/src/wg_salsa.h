/*
 * wg_salsa - NaCl secretbox and box (XSalsa20-Poly1305 over Curve25519), for Tailscale's DERP.
 *
 * A DERP connection starts with one box each way: ClientInfo, sealed with our node key to the
 * server's key, and ServerInfo back. Tailscale seals and opens them with key.NodePrivate.SealTo /
 * OpenFrom (types/key/node.go), which are golang.org/x/crypto/nacl/box Seal / Open behind a random
 * 24-byte nonce: the frame carries nonce || box. The box layout is NaCl's as libsodium's
 * crypto_box_easy writes it - the 16-byte Poly1305 tag, then the ciphertext, no zero padding in
 * front (NaCl's original crypto_box API wants 32 zero bytes in and gives 16 back).
 *
 *   beforenm(pk, sk)  k = HSalsa20(X25519(sk, pk), 16 zero bytes)
 *   secretbox(m, n, k)
 *                     subkey = HSalsa20(k, n[0..16]), stream = Salsa20(subkey, n[16..24]) from
 *                     block 0; its first 32 bytes are the one-time Poly1305 key, the rest encrypts:
 *                     c = m ^ stream[32..], box = Poly1305(c) || c
 *   box(m, n, pk, sk) secretbox(m, n, beforenm(pk, sk))
 *
 * OpenSSL has no Salsa20, so the Salsa20 core, HSalsa20 and the XSalsa20 stream are written out
 * here, after TweetNaCl (public domain). Poly1305 is OpenSSL's (EVP_MAC "POLY1305" - the code that
 * already authenticates every WireGuard packet inside ChaCha20-Poly1305) and X25519 is wg_dh.
 *
 * beforenm is symmetric - both ends get the same k - so a nonce must never repeat in EITHER
 * direction under one key pair. Tailscale draws every nonce at random; so must we (wg_random).
 *
 * Argument order is NaCl's and Go's: message, nonce, key. Every function returns 1 on success and
 * 0 on failure, like wg_crypto.
 */

#ifndef WG_SALSA_H
#define WG_SALSA_H

#include <stddef.h>
#include <stdint.h>

#include "wg_crypto.h"

#define WG_BOX_KEY_LEN   32     /* a secretbox key, and what beforenm derives */
#define WG_BOX_NONCE_LEN 24
#define WG_BOX_TAG_LEN   16     /* Poly1305: a box is this much longer than its message */

/* --- primitives ------------------------------------------------------------------------ */

/* HSalsa20 (Bernstein, "Extending the Salsa20 nonce"): 32 bytes out of a key and 16 bytes of
 * input. The output may be the key. */
void wg_hsalsa20(uint8_t out[WG_BOX_KEY_LEN], const uint8_t key[WG_BOX_KEY_LEN], const uint8_t in[16]);

/*
 * The XSalsa20 stream from its start (block 0), XORed into `in`; `out` may be `in`. Not a cipher
 * on its own - nothing authenticates it; secretbox below is.
 */
void wg_xsalsa20_xor(uint8_t* out, const uint8_t* in, size_t len,
                     const uint8_t nonce[WG_BOX_NONCE_LEN], const uint8_t key[WG_BOX_KEY_LEN]);

/*
 * Poly1305 (RFC 8439 section 2.5) of `msg` under a ONE-TIME 32-byte key (r || s). Exposed because
 * secretbox and its test vectors both need it.
 */
int wg_poly1305(uint8_t tag[WG_BOX_TAG_LEN], const uint8_t key[WG_BOX_KEY_LEN],
                const void* msg, size_t len);

/* --- secretbox: XSalsa20-Poly1305 under a shared key ----------------------------------- */

/*
 * Seals `len` bytes of `msg` into `out`: len + WG_BOX_TAG_LEN bytes, tag first. `msg` may overlap
 * `out` in any way - in place is msg == out (the message at the start of a buffer with room for
 * the tag at its end) or msg == out + WG_BOX_TAG_LEN (room at the start). The nonce and the key
 * are taken before `out` is written, so they may share the buffer too. A length whose box would
 * not fit in a size_t is refused before anything is touched; any later failure wipes `out`.
 */
int wg_secretbox_seal(uint8_t* out, const void* msg, size_t len,
                      const uint8_t nonce[WG_BOX_NONCE_LEN], const uint8_t key[WG_BOX_KEY_LEN]);

/*
 * Opens a box of `len` bytes, tag included, into `out`: len - WG_BOX_TAG_LEN bytes. The tag is
 * checked in constant time BEFORE a byte is decrypted: a forged or damaged box fails and `out` is
 * left as it was. `out` may overlap `box` in any way (out == box puts the message where the box
 * started) and may be NULL for an empty message; the nonce and the key may share the buffer.
 */
int wg_secretbox_open(uint8_t* out, const void* box, size_t len,
                      const uint8_t nonce[WG_BOX_NONCE_LEN], const uint8_t key[WG_BOX_KEY_LEN]);

/* --- box: secretbox under an X25519 agreement ------------------------------------------- */

/*
 * The shared key of the pair (their_pk, our_sk) - both ends derive the same one. Fails on a
 * low-order public key (an all-zero X25519 result, see wg_dh), as libsodium's crypto_box_beforenm
 * does; Go's box.Precompute carries on with a key anyone can compute.
 */
int wg_box_beforenm(uint8_t k[WG_BOX_KEY_LEN], const wg_key* their_pk, const wg_key* our_sk);

/* crypto_box_easy / crypto_box_open_easy: beforenm, then the secretbox above (same buffers and
 * overlap rules). A failed key agreement leaves `out` untouched. */
int wg_box_seal(uint8_t* out, const void* msg, size_t len, const uint8_t nonce[WG_BOX_NONCE_LEN],
                const wg_key* their_pk, const wg_key* our_sk);
int wg_box_open(uint8_t* out, const void* box, size_t len, const uint8_t nonce[WG_BOX_NONCE_LEN],
                const wg_key* their_pk, const wg_key* our_sk);

#endif /* WG_SALSA_H */
