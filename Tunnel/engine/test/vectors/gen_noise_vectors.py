#!/usr/bin/env python3
"""
A second, independent implementation of the WireGuard handshake (Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s)
and its cookie layer, written from the protocol description (https://www.wireguard.com/protocol/,
whitepaper section 5.4), for test/test_noise.c, test/test_cookie.c and test/test_session.c.

It runs whole exchanges from fixed inputs - static keys, ephemeral seeds, sender indices, the
timestamp, the PSK, the cookie secret and nonce - and prints every wire message and derived key as
C string literals. The C engine, fed the same inputs through a scripted wg_rng, must reproduce the
bytes exactly. The two roles here keep separate state and each computes from its OWN private keys,
so the script also proves to itself that initiator and responder agree.

X25519 and ChaCha20-Poly1305 come from pyca/cryptography (backed by OpenSSL, as is the C side, but
test_crypto.c already pins those primitives to RFC vectors); BLAKE2s and HMAC come from Python's
hashlib/hmac; HChaCha20 is written out below. What this file cross-checks is the composition: the
order of the mixes, which key goes where, the associated data, the offsets, the macs.

The output is the header the C tests include; regenerate it only when the inputs change:

    python3 engine/test/vectors/gen_noise_vectors.py > engine/test/vectors/kat_noise.h
"""

import hashlib
import hmac
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1 = b"mac1----"
LABEL_COOKIE = b"cookie--"

# ------------------------------------------------------------------------------ primitives


def HASH(*parts: bytes) -> bytes:
    h = hashlib.blake2s()
    for p in parts:
        h.update(p)
    return h.digest()


def MAC(key: bytes, data: bytes) -> bytes:
    return hashlib.blake2s(data, key=key, digest_size=16).digest()


def HMAC(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.blake2s).digest()


def KDF(n: int, key: bytes, data: bytes):
    t0 = HMAC(key, data)
    out, prev = [], b""
    for i in range(1, n + 1):
        prev = HMAC(t0, prev + bytes([i]))
        out.append(prev)
    return out


def clamp(b: bytes) -> bytes:
    b = bytearray(b)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return bytes(b)


def pub(sk: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(sk).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def DH(sk: bytes, pk: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(sk).exchange(X25519PublicKey.from_public_bytes(pk))


def nonce12(counter: int) -> bytes:
    return b"\0" * 4 + struct.pack("<Q", counter)


def AEAD(key: bytes, counter: int, pt: bytes, ad: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(nonce12(counter), pt, ad)


def AEAD_open(key: bytes, counter: int, ct: bytes, ad: bytes) -> bytes:
    return ChaCha20Poly1305(key).decrypt(nonce12(counter), ct, ad)


def _rotl(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    s = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    s += list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16))

    def qr(a, b, c, d):
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl(s[d] ^ s[a], 16)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl(s[b] ^ s[c], 12)
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl(s[d] ^ s[a], 8)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl(s[b] ^ s[c], 7)

    for _ in range(10):
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
    return struct.pack("<4I", *s[0:4]) + struct.pack("<4I", *s[12:16])


def XAEAD(key: bytes, nonce24: bytes, pt: bytes, ad: bytes) -> bytes:
    return ChaCha20Poly1305(hchacha20(key, nonce24[:16])).encrypt(b"\0" * 4 + nonce24[16:], pt, ad)


def XAEAD_open(key: bytes, nonce24: bytes, ct: bytes, ad: bytes) -> bytes:
    return ChaCha20Poly1305(hchacha20(key, nonce24[:16])).decrypt(b"\0" * 4 + nonce24[16:], ct, ad)


def tai64n(sec: int, nsec: int) -> bytes:
    # WireGuard rounds the nanoseconds down to 2^24 ns so the timestamp leaks no fine clock.
    return struct.pack(">QI", 0x400000000000000A + sec, nsec & ~0xFFFFFF)


def pad(packet: bytes, mtu: int) -> bytes:
    # Zeroes up to a multiple of 16, never past the MTU (Linux calculate_skb_padding).
    last = len(packet) % mtu if mtu and len(packet) > mtu else len(packet)
    size = (last + 15) & ~15
    if mtu and size > mtu:
        size = mtu
    return packet + b"\0" * (size - last)


def data_message(receiver: int, counter: int, key: bytes, packet: bytes, mtu: int) -> bytes:
    return struct.pack("<IIQ", 4, receiver, counter) + AEAD(key, counter, pad(packet, mtu), b"")


# ------------------------------------------------------------------------------ self-checks

assert hchacha20(bytes(range(32)), bytes.fromhex("000000090000004a0000000031415927")).hex() == \
    "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc", "HChaCha20 draft vector"
assert HASH(CONSTRUCTION).hex() == "60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36"
assert HASH(HASH(CONSTRUCTION), IDENTIFIER).hex() == \
    "2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3"

# ------------------------------------------------------------------------------ the two roles


def add_macs(msg: bytes, receiver_static_pub: bytes, cookie: bytes = None) -> bytes:
    """msg without its 32 mac bytes -> msg || mac1 || mac2 (mac2 zero without a cookie)."""
    mac1 = MAC(HASH(LABEL_MAC1, receiver_static_pub), msg)
    mac2 = MAC(cookie, msg + mac1) if cookie else b"\0" * 16
    return msg + mac1 + mac2


class Initiator:
    def __init__(self, static_sk, peer_pub, psk):
        self.sk, self.pk, self.peer, self.psk = static_sk, pub(static_sk), peer_pub, psk

    def initiation(self, eph_seed, sender, timestamp):
        C = HASH(CONSTRUCTION)
        H = HASH(C, IDENTIFIER)
        H = HASH(H, self.peer)                          # the pre-message: responder's static
        self.e = clamp(eph_seed)
        e_pub = pub(self.e)
        (C,) = KDF(1, C, e_pub)                         # e (psk mode also mixes it into C)
        H = HASH(H, e_pub)
        C, k = KDF(2, C, DH(self.e, self.peer))         # es
        enc_static = AEAD(k, 0, self.pk, H)             # s
        H = HASH(H, enc_static)
        C, k = KDF(2, C, DH(self.sk, self.peer))        # ss
        enc_ts = AEAD(k, 0, timestamp, H)               # payload: TAI64N
        H = HASH(H, enc_ts)
        self.C, self.H, self.sender = C, H, sender
        body = struct.pack("<II", 1, sender) + e_pub + enc_static + enc_ts
        return add_macs(body, self.peer)

    def consume_response(self, msg):
        typ, their, ours = struct.unpack("<III", msg[:12])
        assert typ == 2 and ours == self.sender
        e_r = msg[12:44]
        C, H = self.C, self.H
        (C,) = KDF(1, C, e_r)                           # e
        H = HASH(H, e_r)
        (C,) = KDF(1, C, DH(self.e, e_r))               # ee
        (C,) = KDF(1, C, DH(self.sk, e_r))              # se
        C, tau, k = KDF(3, C, self.psk)                 # psk
        H = HASH(H, tau)
        assert AEAD_open(k, 0, msg[44:60], H) == b""    # payload: empty
        H = HASH(H, msg[44:60])
        send, recv = KDF(2, C, b"")
        return send, recv, their


class Responder:
    def __init__(self, static_sk, peer_pub, psk):
        self.sk, self.pk, self.peer, self.psk = static_sk, pub(static_sk), peer_pub, psk

    def consume_initiation(self, msg):
        typ, sender = struct.unpack("<II", msg[:8])
        assert typ == 1
        assert msg[116:132] == MAC(HASH(LABEL_MAC1, self.pk), msg[:116]), "mac1"
        e_i = msg[8:40]
        C = HASH(CONSTRUCTION)
        H = HASH(C, IDENTIFIER)
        H = HASH(H, self.pk)
        (C,) = KDF(1, C, e_i)
        H = HASH(H, e_i)
        C, k = KDF(2, C, DH(self.sk, e_i))              # es, from the responder's side
        s_i = AEAD_open(k, 0, msg[40:88], H)
        assert s_i == self.peer, "initiator static"
        H = HASH(H, msg[40:88])
        C, k = KDF(2, C, DH(self.sk, s_i))              # ss
        ts = AEAD_open(k, 0, msg[88:116], H)
        H = HASH(H, msg[88:116])
        self.C, self.H, self.e_i, self.their = C, H, e_i, sender
        return ts

    def response(self, eph_seed, sender):
        e = clamp(eph_seed)
        e_pub = pub(e)
        C, H = self.C, self.H
        (C,) = KDF(1, C, e_pub)                         # e
        H = HASH(H, e_pub)
        (C,) = KDF(1, C, DH(e, self.e_i))               # ee
        (C,) = KDF(1, C, DH(e, self.peer))              # se
        C, tau, k = KDF(3, C, self.psk)                 # psk
        H = HASH(H, tau)
        enc_empty = AEAD(k, 0, b"", H)                  # payload: empty
        H = HASH(H, enc_empty)
        recv, send = KDF(2, C, b"")                     # the responder's keys are the other way round
        body = struct.pack("<III", 2, sender, self.their) + e_pub + enc_empty
        return add_macs(body, self.peer), send, recv


# ------------------------------------------------------------------------------ transcripts


def c_hex(name: str, b: bytes) -> str:
    h = b.hex()
    lines = [h[i:i + 64] for i in range(0, len(h), 64)]
    body = "\n".join('    "%s"' % l for l in lines)
    return "static const char %s[] =\n%s;" % (name, body)


I_STATIC = clamp(HASH(b"tunnel test: initiator static"))
R_STATIC = clamp(HASH(b"tunnel test: responder static"))
I_INDEX = 0x11223344
R_INDEX = 0xA1B2C3D4
SEC, NSEC = 1759140000, 987654321      # 2025-09-29 10:00:00 UTC; nsec gets rounded down
MTU = 1420
PACKET_I = bytes(range(37))             # initiator -> responder, padded to 48
PACKET_R = bytes(range(100, 120))       # responder -> initiator, padded to 32


def transcript(tag: str, psk: bytes):
    i_eph = HASH(b"tunnel test: initiator ephemeral " + tag.encode())
    r_eph = HASH(b"tunnel test: responder ephemeral " + tag.encode())
    ts = tai64n(SEC, NSEC)

    ini = Initiator(I_STATIC, pub(R_STATIC), psk)
    rsp = Responder(R_STATIC, pub(I_STATIC), psk)

    init = ini.initiation(i_eph, I_INDEX, ts)
    assert len(init) == 148
    assert rsp.consume_initiation(init) == ts
    resp, r_send, r_recv = rsp.response(r_eph, R_INDEX)
    assert len(resp) == 92
    i_send, i_recv, their = ini.consume_response(resp)
    assert their == R_INDEX
    assert (i_send, i_recv) == (r_recv, r_send), "the two sides disagree on the transport keys"

    # A keepalive from the initiator, the first thing it sends: an empty payload at counter 0.
    keepalive = struct.pack("<IIQ", 4, R_INDEX, 0) + AEAD(i_send, 0, b"", b"")
    assert AEAD_open(r_recv, 0, keepalive[16:], b"") == b""

    # Then a packet each way: the initiator's next counter is 1, the responder starts at 0 (it may
    # send only now, after the keepalive confirmed its keys).
    data_i = data_message(R_INDEX, 1, i_send, PACKET_I, MTU)
    data_r = data_message(I_INDEX, 0, r_send, PACKET_R, MTU)
    assert len(data_i) == 16 + 48 + 16 and len(data_r) == 16 + 32 + 16
    assert AEAD_open(r_recv, 1, data_i[16:], b"") == pad(PACKET_I, MTU)
    assert AEAD_open(i_recv, 0, data_r[16:], b"") == pad(PACKET_R, MTU)

    T = tag.upper()
    print("/* --- transcript %s (psk %s) --- */" % (tag, "set" if any(psk) else "none"))
    print(c_hex("KAT_%s_I_EPH_SEED" % T, i_eph))
    print(c_hex("KAT_%s_R_EPH_SEED" % T, r_eph))
    print(c_hex("KAT_%s_PSK" % T, psk))
    print(c_hex("KAT_%s_INIT" % T, init))
    print(c_hex("KAT_%s_RESP" % T, resp))
    print(c_hex("KAT_%s_I_SEND" % T, i_send))
    print(c_hex("KAT_%s_I_RECV" % T, i_recv))
    print(c_hex("KAT_%s_KEEPALIVE" % T, keepalive))
    print(c_hex("KAT_%s_DATA_I" % T, data_i))
    print(c_hex("KAT_%s_DATA_R" % T, data_r))
    print()
    return init


print("/*")
print(" * Generated by test/vectors/gen_noise_vectors.py - do not edit, rerun it:")
print(" *     python3 engine/test/vectors/gen_noise_vectors.py > engine/test/vectors/kat_noise.h")
print(" *")
print(" * Static keys are stored clamped; the ephemeral seeds are the raw 32 bytes the RNG returns,")
print(" * clamped by the engine. Indices and timestamps as they go on the wire.")
print(" */")
print()
print("#ifndef KAT_NOISE_H")
print("#define KAT_NOISE_H")
print()
print(c_hex("KAT_I_STATIC", I_STATIC))
print(c_hex("KAT_I_STATIC_PUB", pub(I_STATIC)))
print(c_hex("KAT_R_STATIC", R_STATIC))
print(c_hex("KAT_R_STATIC_PUB", pub(R_STATIC)))
print("#define KAT_I_INDEX 0x%08xu" % I_INDEX)
print("#define KAT_R_INDEX 0x%08xu" % R_INDEX)
print("#define KAT_SEC  %dull" % SEC)
print("#define KAT_NSEC %du" % NSEC)
print(c_hex("KAT_TIMESTAMP", tai64n(SEC, NSEC)))
print("#define KAT_MTU %d" % MTU)
print(c_hex("KAT_PACKET_I", PACKET_I))
print(c_hex("KAT_PACKET_R", PACKET_R))
print()

transcript("nopsk", b"\0" * 32)
init = transcript("psk", HASH(b"tunnel test: preshared key"))

# --- the cookie exchange, on the PSK transcript's initiation -------------------------------------
# The responder is under load: the initiation carries no mac2, so it answers with a cookie reply
# bound to the source address. The initiator opens it with its last mac1 as AD and resends the SAME
# bytes with mac2 = MAC(cookie, msg up to mac2).
secret = HASH(b"tunnel test: cookie secret")
src = bytes([192, 0, 2, 1]) + struct.pack(">H", 51820)           # 192.0.2.1:51820, port big-endian
nonce = HASH(b"tunnel test: cookie nonce")[:24]
cookie = MAC(secret, src)
mac1 = init[116:132]
reply = struct.pack("<II", 3, I_INDEX) + nonce + XAEAD(HASH(LABEL_COOKIE, pub(R_STATIC)), nonce, cookie, mac1)
assert len(reply) == 64
opened = XAEAD_open(HASH(LABEL_COOKIE, pub(R_STATIC)), nonce, reply[32:], mac1)
assert opened == cookie
init_mac2 = init[:132] + MAC(opened, init[:132])

print("/* --- cookie reply to KAT_PSK_INIT from 192.0.2.1:51820 --- */")
print(c_hex("KAT_COOKIE_SECRET", secret))
print(c_hex("KAT_COOKIE_SRC", src))
print(c_hex("KAT_COOKIE_NONCE", nonce))
print(c_hex("KAT_COOKIE", cookie))
print(c_hex("KAT_COOKIE_REPLY", reply))
print(c_hex("KAT_INIT_WITH_MAC2", init_mac2))
print()
print("#endif /* KAT_NOISE_H */")
