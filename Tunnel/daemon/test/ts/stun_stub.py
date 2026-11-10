#!/usr/bin/env python3
# A STUN server for the stand (TAILSCALE.md section 11a, stage 2): answers a binding request with
# where it came from (XOR-MAPPED-ADDRESS, as Tailscale's stun.Response builds it), and nothing else.
# The stand's second STUN region beside Headscale's: two servers tell an easy NAT from a hard one.
#
# Each answer comes 50 ms late: the official tailscaled takes the region that answers STUN fastest
# for its home even when the region is STUN only (netcheck's preferred DERP does not ask for a DERP
# node), and then has no relay at all - the real map has no such region. Slower than Headscale's own
# STUN, this one is never anyone's home.
#
#   stun_stub.py ADDR [PORT]        (port 3478 when left out)
import socket
import struct
import sys
import time

COOKIE = b"\x21\x12\xa4\x42"


def answer(req, ip, port):
    if len(req) < 20 or req[0:2] != b"\x00\x01" or req[4:8] != COOKIE:
        return None
    txid = req[8:20]
    if ":" in ip:
        a, fam, key = socket.inet_pton(socket.AF_INET6, ip), b"\x00\x02", COOKIE + txid
    else:
        a, fam, key = socket.inet_aton(ip), b"\x00\x01", COOKIE
    xaddr = bytes(x ^ c for x, c in zip(a, key))
    value = fam + struct.pack("!H", port ^ 0x2112) + xaddr
    attr = struct.pack("!HH", 0x0020, len(value)) + value
    return b"\x01\x01" + struct.pack("!H", len(attr)) + COOKIE + txid + attr


def main():
    addr = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 3478
    s = socket.socket(socket.AF_INET6 if ":" in addr else socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((addr, port))
    while True:
        req, src = s.recvfrom(2048)
        ip, p = src[0], src[1]
        out = answer(req, ip, p)
        if out:
            time.sleep(0.05)
            s.sendto(out, src)


if __name__ == "__main__":
    main()
