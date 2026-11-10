/*
 * wg_crypto against published vectors (RFC 7693, 7748, 8439, the XChaCha draft) and, where no
 * RFC publishes any, against Python's independent hashlib/hmac (test/vectors/gen_crypto_vectors.py).
 */

#include "test_util.h"
#include "../src/wg_crypto.h"

static const char SUNSCREEN[] =
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
    "sunscreen would be it.";

TEST(blake2s_rfc7693)
{
    uint8_t out[32], want[32];
    t_hex(want, sizeof(want), "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    CHECK(wg_hash(out, "abc", 3));
    CHECK_MEM(out, want, 32);

    /* hash2 must equal hash of the concatenation */
    CHECK(wg_hash2(out, "a", 1, "bc", 2));
    CHECK_MEM(out, want, 32);
}

TEST(x25519_rfc7748)
{
    wg_key a, b, apub, bpub, got;
    uint8_t want[32], s1[32], s2[32];

    t_hex(a.b, 32, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    t_hex(b.b, 32, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    t_hex(apub.b, 32, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    t_hex(bpub.b, 32, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    t_hex(want, 32, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    CHECK(wg_key_public(&a, &got));
    CHECK_MEM(got.b, apub.b, 32);
    CHECK(wg_key_public(&b, &got));
    CHECK_MEM(got.b, bpub.b, 32);

    CHECK(wg_dh(&a, &bpub, s1));
    CHECK(wg_dh(&b, &apub, s2));
    CHECK_MEM(s1, want, 32);
    CHECK_MEM(s2, want, 32);
}

TEST(x25519_rejects_low_order_point)
{
    wg_key sk, pk, zero;
    uint8_t out[32];

    CHECK(wg_key_generate(&sk, &pk));
    memset(&zero, 0, sizeof(zero));
    /* The all-zero point is of low order: the shared secret is zero and must be refused. */
    CHECK(!wg_dh(&sk, &zero, out));
}

TEST(x25519_generate_roundtrip)
{
    wg_key a, apub, b, bpub, check;
    uint8_t s1[32], s2[32];

    CHECK(wg_key_generate(&a, &apub));
    CHECK(wg_key_generate(&b, &bpub));
    CHECK(wg_key_public(&a, &check));
    CHECK_MEM(check.b, apub.b, 32);
    CHECK(wg_dh(&a, &bpub, s1));
    CHECK(wg_dh(&b, &apub, s2));
    CHECK_MEM(s1, s2, 32);
}

TEST(chacha20poly1305_rfc8439)
{
    uint8_t key[32], nonce[12], ad[12], ct[256], pt[256];
    uint8_t want_head[16], want_tag[16];
    size_t len = sizeof(SUNSCREEN) - 1;

    t_hex(key, 32, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    t_hex(nonce, 12, "070000004041424344454647");
    t_hex(ad, 12, "50515253c0c1c2c3c4c5c6c7");
    t_hex(want_head, 16, "d31a8d34648e60db7b86afbc53ef7ec2");
    t_hex(want_tag, 16, "1ae10b594f09e26a7e902ecbd0600691");

    CHECK(wg_aead_encrypt_n(ct, key, nonce, SUNSCREEN, len, ad, sizeof(ad)));
    CHECK_MEM(ct, want_head, 16);
    CHECK_MEM(ct + len, want_tag, 16);

    CHECK(wg_aead_decrypt_n(pt, key, nonce, ct, len + 16, ad, sizeof(ad)));
    CHECK_MEM(pt, SUNSCREEN, len);

    /* One flipped bit anywhere - ciphertext, tag or AD - must fail authentication. */
    ct[5] ^= 0x01;
    CHECK(!wg_aead_decrypt_n(pt, key, nonce, ct, len + 16, ad, sizeof(ad)));
    ct[5] ^= 0x01;
    ct[len + 3] ^= 0x80;
    CHECK(!wg_aead_decrypt_n(pt, key, nonce, ct, len + 16, ad, sizeof(ad)));
    ct[len + 3] ^= 0x80;
    ad[0] ^= 0x01;
    CHECK(!wg_aead_decrypt_n(pt, key, nonce, ct, len + 16, ad, sizeof(ad)));
}

TEST(aead_counter_nonce_layout)
{
    /* WireGuard's nonce is 4 zero bytes then the counter little-endian: counter form and
     * explicit form must produce identical output. */
    uint8_t key[32], nonce[12], a[64], b[64];
    const uint64_t counter = 0x0102030405060708ULL;

    memset(key, 0x42, sizeof(key));
    t_hex(nonce, 12, "000000000807060504030201");

    CHECK(wg_aead_encrypt(a, key, counter, "payload", 7, NULL, 0));
    CHECK(wg_aead_encrypt_n(b, key, nonce, "payload", 7, NULL, 0));
    CHECK_MEM(a, b, 7 + 16);
}

TEST(aead_empty_plaintext)
{
    /* Keepalives are transport messages with an empty payload: just the 16-byte tag. */
    uint8_t key[32], tag[16], out[1];
    memset(key, 0x11, sizeof(key));
    CHECK(wg_aead_encrypt(tag, key, 7, NULL, 0, NULL, 0));
    CHECK(wg_aead_decrypt(out, key, 7, tag, 16, NULL, 0));
    CHECK(!wg_aead_decrypt(out, key, 8, tag, 16, NULL, 0));   /* wrong counter */
}

TEST(hchacha20_xchacha_draft)
{
    uint8_t key[32], nonce[16], out[32], want[32];
    t_hex(key, 32, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    t_hex(nonce, 16, "000000090000004a0000000031415927");
    t_hex(want, 32, "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
    wg_hchacha20(out, key, nonce);
    CHECK_MEM(out, want, 32);
}

TEST(xchacha20poly1305_draft)
{
    uint8_t key[32], nonce[24], ad[12], ct[256], pt[256];
    uint8_t want_head[16], want_tag[16];
    size_t len = sizeof(SUNSCREEN) - 1;

    t_hex(key, 32, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    t_hex(nonce, 24, "404142434445464748494a4b4c4d4e4f5051525354555657");
    t_hex(ad, 12, "50515253c0c1c2c3c4c5c6c7");
    t_hex(want_head, 16, "bd6d179d3e83d43b9576579493c0e939");
    t_hex(want_tag, 16, "c0875924c1c7987947deafd8780acf49");

    CHECK(wg_xaead_encrypt(ct, key, nonce, SUNSCREEN, len, ad, sizeof(ad)));
    CHECK_MEM(ct, want_head, 16);
    CHECK_MEM(ct + len, want_tag, 16);
    CHECK(wg_xaead_decrypt(pt, key, nonce, ct, len + 16, ad, sizeof(ad)));
    CHECK_MEM(pt, SUNSCREEN, len);
    nonce[23] ^= 1;
    CHECK(!wg_xaead_decrypt(pt, key, nonce, ct, len + 16, ad, sizeof(ad)));
}

TEST(chacha20_rfc8439)
{
    uint8_t key[32], nonce[12], zeros[64], block[64], want[128], out[128];
    size_t len = sizeof(SUNSCREEN) - 1;
    int i;

    for (i = 0; i < 32; i++) key[i] = (uint8_t)i;

    /* 2.3.2: one block of keystream */
    t_hex(nonce, 12, "000000090000004a00000000");
    memset(zeros, 0, sizeof(zeros));
    wg_chacha20_xor(block, zeros, 64, key, nonce, 1);
    t_hex(want, 64, "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
                    "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
    CHECK_MEM(block, want, 64);

    /* 2.4.2: across two blocks; applied again in place it gives the plaintext back */
    t_hex(nonce, 12, "000000000000004a00000000");
    t_hex(want, sizeof(want),
          "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
          "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
          "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
          "5af90bbf74a35be6b40b8eedf2785e42874d");
    wg_chacha20_xor(out, (const uint8_t*)SUNSCREEN, len, key, nonce, 1);
    CHECK_MEM(out, want, len);
    wg_chacha20_xor(out, out, len, key, nonce, 1);
    CHECK_MEM(out, SUNSCREEN, len);
}

TEST(keyed_blake2s_python)
{
    uint8_t key[32], out16[16], out32[32], w16[16], w32[32];
    const char* msg = "WireGuard mac1 test";
    int i;
    for (i = 0; i < 32; i++) key[i] = (uint8_t)i;
    t_hex(w16, 16, "ff9b8b06ed3ff3819f790b60ef4f1c1d");
    t_hex(w32, 32, "36075f0bc80dd4fe0dc819b3fa88261cb287c7f9dc6ea0cb47c069fdc62ff3a9");

    CHECK(wg_mac16(out16, key, 32, msg, strlen(msg)));
    CHECK_MEM(out16, w16, 16);
    CHECK(wg_mac32(out32, key, 32, msg, strlen(msg)));
    CHECK_MEM(out32, w32, 32);
}

TEST(hmac_blake2s_python)
{
    uint8_t key[32], out[32], want[32];
    int i;
    for (i = 0; i < 32; i++) key[i] = (uint8_t)i;
    t_hex(want, 32, "36dee8a3b1bd6ef6f4a3212df6b19e8dac65edfd0507dfb3afe6a5346e11970f");
    CHECK(wg_hmac(out, key, "hmac-blake2s", 12));
    CHECK_MEM(out, want, 32);
}

TEST(kdf_python)
{
    uint8_t key[32], t1[32], t2[32], t3[32], w1[32], w2[32], w3[32];
    int i;
    for (i = 0; i < 32; i++) key[i] = (uint8_t)i;

    t_hex(w1, 32, "f0f68421988336e20ce9e9251e4440497d9798985798b8f7fcf2c32ba1752467");
    t_hex(w2, 32, "f9ec09ac5a46c71f76a8b06d37497a03fcde6448a396c864298d4344f902cf1b");
    t_hex(w3, 32, "ea7bfa571e8873ad63e74dd0047867e451c43c0790f055ef36079851788ef4d4");
    CHECK(wg_kdf(t1, t2, t3, key, "kdf input", 9));
    CHECK_MEM(t1, w1, 32);
    CHECK_MEM(t2, w2, 32);
    CHECK_MEM(t3, w3, 32);

    /* The transport keys derive from an EMPTY input - the case a strict HKDF API might refuse. */
    t_hex(w1, 32, "7a38c34bf2b8738d7374ca77c44ecb309a11d2b2528304fa86052c365e722624");
    t_hex(w2, 32, "1a17621f346abdc520746a9fb64d8eb03231d674fc15687537b0780fd9c060fd");
    t_hex(w3, 32, "4eaf02809ac4b930ef63479de62275f1c55656e61f78a3cc653c18a2223d6c5f");
    CHECK(wg_kdf(t1, t2, t3, key, NULL, 0));
    CHECK_MEM(t1, w1, 32);
    CHECK_MEM(t2, w2, 32);
    CHECK_MEM(t3, w3, 32);

    /* Partial outputs */
    memset(t2, 0, 32);
    CHECK(wg_kdf(t1, NULL, NULL, key, NULL, 0));
    CHECK_MEM(t1, w1, 32);
    CHECK(wg_kdf(NULL, t2, NULL, key, NULL, 0));
    CHECK_MEM(t2, w2, 32);
}

TEST(handshake_constants)
{
    static const char construction[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
    static const char identifier[]   = "WireGuard v1 zx2c4 Jason@zx2c4.com";
    uint8_t ck[32], h[32], wck[32], wh[32];

    t_hex(wck, 32, "60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36");
    t_hex(wh, 32, "2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3");
    CHECK(wg_hash(ck, construction, sizeof(construction) - 1));
    CHECK_MEM(ck, wck, 32);
    CHECK(wg_hash2(h, ck, 32, identifier, sizeof(identifier) - 1));
    CHECK_MEM(h, wh, 32);
}

int main(void)
{
    if (!wg_crypto_init()) {
        fprintf(stderr, "wg_crypto_init failed - OpenSSL lacks BLAKE2S-256 / BLAKE2SMAC / HMAC / ChaCha20-Poly1305\n");
        return 2;
    }
    RUN(blake2s_rfc7693);
    RUN(x25519_rfc7748);
    RUN(x25519_rejects_low_order_point);
    RUN(x25519_generate_roundtrip);
    RUN(chacha20poly1305_rfc8439);
    RUN(aead_counter_nonce_layout);
    RUN(aead_empty_plaintext);
    RUN(hchacha20_xchacha_draft);
    RUN(xchacha20poly1305_draft);
    RUN(chacha20_rfc8439);
    RUN(keyed_blake2s_python);
    RUN(hmac_blake2s_python);
    RUN(kdf_python);
    RUN(handshake_constants);
    wg_crypto_cleanup();
    return t_summary("test_crypto");
}
