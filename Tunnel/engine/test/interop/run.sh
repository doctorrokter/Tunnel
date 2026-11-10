#!/usr/bin/env bash
#
# Interop: the engine against the Linux kernel's WireGuard, over loopback, in WSL (as root):
#
#   MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -u root -- bash /mnt/e/dev/momentics-projects/Tunnel/engine/test/interop/run.sh [soak]
#
# Needs the wireguard kernel module and wireguard-tools (wg). A temporary interface, tuntest0, lives
# for the run and is deleted on exit whatever happens; nothing else on the machine is touched.
#
#   1. we initiate:     echoes from us to the kernel's tunnel address, IPv4 and IPv6
#   2. the kernel does: the kernel pings our tunnel address, we only answer
#   3. soak (optional): an echo a second for 140 s - the session is renewed on the way

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE="$HERE/../.."
WORK="$(mktemp -d)"
IF=tuntest0
KPORT=51899         # the kernel's UDP port
OPORT=40099         # ours
FAILED=0

cleanup() {
    ip link del "$IF" 2> /dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

command -v wg > /dev/null || { echo "wg not found: apt install wireguard-tools" >&2; exit 2; }
modprobe wireguard

echo "== build"
gcc -std=gnu99 -O1 -g -Wall -Wextra -Wno-unused-parameter -fsanitize=address,undefined \
    -I"$ENGINE/src" -o "$WORK/wg_interop" "$ENGINE"/src/*.c "$HERE/wg_interop.c" -lcrypto

cd "$WORK"
umask 077
wg genkey > kernel.key
wg pubkey < kernel.key > kernel.pub
wg genkey > ours.key
wg pubkey < ours.key > ours.pub
wg genpsk > psk

V6=1
[ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2> /dev/null || echo 1)" = 0 ] || V6=0

cat > ours.conf << EOF
[Interface]
PrivateKey = $(cat ours.key)
Address = 10.99.0.2/32, fd99::2/128

[Peer]
PublicKey = $(cat kernel.pub)
PresharedKey = $(cat psk)
AllowedIPs = 10.99.0.0/24, fd99::/64
Endpoint = 127.0.0.1:$KPORT
EOF

kernel_up() {
    ip link del "$IF" 2> /dev/null || true
    ip link add "$IF" type wireguard
    wg set "$IF" private-key kernel.key listen-port "$KPORT" \
        peer "$(cat ours.pub)" preshared-key psk allowed-ips 10.99.0.2/32,fd99::2/128 \
        endpoint "127.0.0.1:$OPORT"
    ip addr add 10.99.0.1/24 dev "$IF"
    if [ $V6 = 1 ]; then ip -6 addr add fd99::1/64 dev "$IF" nodad; fi
    ip link set "$IF" up
}

step() {
    local name="$1"
    shift
    if "$@"; then
        echo "   ok    $name"
    else
        echo "   FAIL  $name"
        FAILED=1
    fi
}

echo "== 1. we initiate"
kernel_up
step "IPv4 echo, handshake from us" ./wg_interop ours.conf "$OPORT" ping 10.99.0.1 5
if [ $V6 = 1 ]; then step "IPv6 echo" ./wg_interop ours.conf "$OPORT" ping fd99::1 5; fi
wg show "$IF" latest-handshakes
wg show "$IF" transfer

echo "== 2. the kernel initiates"
kernel_up
./wg_interop ours.conf "$OPORT" answer 10 &
HARNESS=$!
sleep 1
step "the kernel pings us (IPv4)" ping -c 3 -i 0.5 -W 3 10.99.0.2
if [ $V6 = 1 ]; then step "the kernel pings us (IPv6)" ping -6 -c 3 -i 0.5 -W 3 fd99::2; fi
step "we answered" wait "$HARNESS"

if [ "${1:-}" = soak ]; then
    echo "== 3. soak: 140 s, the session renewed on the way"
    kernel_up
    step "140 echoes through a rekey" ./wg_interop ours.conf "$OPORT" soak 10.99.0.1 140
    wg show "$IF" latest-handshakes
fi

if [ $FAILED = 0 ]; then echo "== interop: all passed"; else echo "== interop: FAILED"; fi
exit $FAILED
