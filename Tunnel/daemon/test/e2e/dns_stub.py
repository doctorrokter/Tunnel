#!/usr/bin/env python3
"""A DNS server small enough to trust in a test: A records from a zone file, nothing else.

    dns_stub.py <bind-address> <zone-file>

The zone file is read again for every query (a test changes an answer by rewriting it): lines of
"name address". A known name: its A records for an A query, an empty answer for any other type.
An unknown name: NXDOMAIN. Standard library only.
"""

import socket
import struct
import sys


def read_zone(path):
    zone = {}
    try:
        with open(path) as f:
            for line in f:
                parts = line.split()
                if len(parts) == 2:
                    zone.setdefault(parts[0].lower().rstrip("."), []).append(parts[1])
    except OSError:
        pass
    return zone


def parse_question(msg):
    labels, pos = [], 12
    while True:
        n = msg[pos]
        pos += 1
        if n == 0:
            break
        labels.append(msg[pos:pos + n].decode("ascii", "replace"))
        pos += n
    qtype, qclass = struct.unpack(">HH", msg[pos:pos + 4])
    return ".".join(labels).lower(), qtype, qclass, pos + 4


def answer(msg, zone):
    qid, flags, qd = struct.unpack(">HHH", msg[:6])
    if qd != 1:
        return None
    name, qtype, _, end = parse_question(msg)
    question = msg[12:end]
    rd = flags & 0x0100
    if name not in zone:
        return struct.pack(">HHHHHH", qid, 0x8080 | rd | 3, 1, 0, 0, 0) + question
    records = b""
    count = 0
    if qtype == 1:
        for addr in zone[name]:
            records += struct.pack(">HHHIH", 0xC00C, 1, 1, 30, 4) + socket.inet_aton(addr)
            count += 1
    return struct.pack(">HHHHHH", qid, 0x8080 | rd, 1, count, 0, 0) + question + records


def main():
    bind, zone_path = sys.argv[1], sys.argv[2]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((bind, 53))
    while True:
        msg, peer = s.recvfrom(1500)
        try:
            reply = answer(msg, read_zone(zone_path))
        except (IndexError, struct.error):
            continue
        if reply:
            s.sendto(reply, peer)


if __name__ == "__main__":
    main()
