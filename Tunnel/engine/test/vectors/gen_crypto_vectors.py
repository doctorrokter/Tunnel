#!/usr/bin/env python3
"""
Reference values for the parts of wg_crypto that no RFC publishes vectors for: keyed BLAKE2s at
16 and 32 bytes (mac1/mac2, cookie key), HMAC-BLAKE2s and the WireGuard KDF chain, plus the two
handshake constants every WireGuard implementation precomputes.

Python's hashlib/hmac are an independent implementation from OpenSSL, which is the point: the
C side must agree with a second implementation, not with itself. The output is pasted into
test/test_crypto.c; rerun this only to regenerate those constants.

    python3 engine/test/vectors/gen_crypto_vectors.py
"""

import hashlib
import hmac


def hx(b: bytes) -> str:
    return b.hex()


def b2s(data: bytes, key: bytes = b"", size: int = 32) -> bytes:
    return hashlib.blake2s(data, key=key, digest_size=size).digest()


def hmac_b2s(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.blake2s).digest()


def kdf(key: bytes, data: bytes):
    t0 = hmac_b2s(key, data)
    t1 = hmac_b2s(t0, b"\x01")
    t2 = hmac_b2s(t0, t1 + b"\x02")
    t3 = hmac_b2s(t0, t2 + b"\x03")
    return t1, t2, t3


key = bytes(range(32))

print("mac16  key=00..1f data='WireGuard mac1 test'  ", hx(b2s(b"WireGuard mac1 test", key, 16)))
print("mac32  key=00..1f data='WireGuard mac1 test'  ", hx(b2s(b"WireGuard mac1 test", key, 32)))
print("hmac   key=00..1f data='hmac-blake2s'         ", hx(hmac_b2s(key, b"hmac-blake2s")))

t1, t2, t3 = kdf(key, b"kdf input")
print("kdf    key=00..1f in='kdf input'  t1", hx(t1))
print("                                  t2", hx(t2))
print("                                  t3", hx(t3))

t1, t2, t3 = kdf(key, b"")
print("kdf    key=00..1f in=''           t1", hx(t1))
print("                                  t2", hx(t2))
print("                                  t3", hx(t3))

construction = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
identifier = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
ck = b2s(construction)
h = b2s(ck + identifier)
print("initial chaining key ", hx(ck))
print("initial hash         ", hx(h))
