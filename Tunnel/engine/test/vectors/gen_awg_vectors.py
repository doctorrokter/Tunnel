#!/usr/bin/env python3
"""
AmneziaWG header protection vectors for test_awg.c, computed with pyca/cryptography's ChaCha20 -
an implementation independent of the engine's.

The construction (amneziawg-go device/send.go, receive.go at b5928ef): the datagram is
[S random][message][trailer]; with a header protection key the message - all of it for a handshake
or cookie message, the 16-byte header of a transport message - is XORed with ChaCha20(key,
nonce = the datagram's first 12 bytes, counter 0).

Run: python3 gen_awg_vectors.py   (prints C initialisers)
"""
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

KEY = bytes(range(32))


def keystream(nonce12, n):
    # cryptography takes a 16-byte nonce: the 32-bit counter (LE) first, then the 96-bit nonce
    enc = Cipher(algorithms.ChaCha20(KEY, struct.pack("<I", 0) + nonce12), mode=None).encryptor()
    return enc.update(b"\0" * n)


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def pattern(n, mul, add):
    return bytes((i * mul + add) & 0xFF for i in range(n))


def c_hex(name, data):
    print("/* %s: %d bytes */" % (name, len(data)))
    print('static const char %s[] =' % name)
    h = data.hex()
    for i in range(0, len(h), 64):
        print('    "%s"' % h[i:i + 64])
    print("    ;")


# A: a handshake response behind S2 = 16, the whole message protected.
prefix_a = bytes(range(0xA0, 0xB0))
msg_a = pattern(92, 7, 3)
out_a = prefix_a + xor(msg_a, keystream(prefix_a[:12], len(msg_a)))

# B: a transport message behind S4 = 12, only its 16-byte header protected.
prefix_b = bytes(range(0xB0, 0xBC))
msg_b = pattern(48, 13, 5)
out_b = prefix_b + xor(msg_b[:16], keystream(prefix_b[:12], 16)) + msg_b[16:]

c_hex("HP_RESP_PREFIX", prefix_a)
c_hex("HP_RESP_MSG", msg_a)
c_hex("HP_RESP_WIRE", out_a)
c_hex("HP_DATA_PREFIX", prefix_b)
c_hex("HP_DATA_MSG", msg_b)
c_hex("HP_DATA_WIRE", out_b)
