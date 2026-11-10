#!/usr/bin/env bash
#
# Interop: the engine against amneziawg-go - the AmneziaWG reference, in userspace - over loopback,
# in WSL (as root):
#
#   MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -u root -- bash /mnt/e/dev/momentics-projects/Tunnel/engine/test/interop/run_awg.sh [awg1|awg2|awg3 ...] [soak]
#
# Builds amneziawg-go (Go >= 1.25, its modules fetched on the first build) and awg (make + gcc) from
# the clones in ../../../../refs into a work directory; nothing is installed. The interface awgtest0
# and amneziawg-go live for the run and are gone on exit, whatever happens.
#
# Profiles - S, H, the header protection key and RandomTrailers must agree on both sides, the rest
# is each side's own:
#
#   awg1   1.x: S1/S2, H1-H4 single values; our junk (Jc/Jmin/Jmax)
#   awg2   2.0: + S3/S4, H1-H4 ranges; our I1, I2, I5 and junk, junk from amneziawg-go too
#   awg3   3.x: + HeaderProtectionKey, RandomTrailers, ContentPaddingAddition, moved timers
#
# For each: 1. we initiate (IPv4 and IPv6 echoes), 2. amneziawg-go initiates, we answer,
# 3. (soak) 100 echoes with our RekeyAfterTime at 30-40 s: several renewals on the way. After awg3 a
# control: with another header protection key on our side there must be no tunnel at all.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE="$HERE/../.."
REFS="$ENGINE/../../refs"
WORK="$(mktemp -d)"
IF=awgtest0
KPORT=51898         # amneziawg-go's UDP port
OPORT=40098         # ours
FAILED=0
GOPID=

PROFILES=()
SOAK=0
for a in "$@"; do
    case "$a" in
        soak) SOAK=1 ;;
        awg1 | awg2 | awg3) PROFILES+=("$a") ;;
        *) echo "unknown argument: $a" >&2; exit 2 ;;
    esac
done
[ ${#PROFILES[@]} -gt 0 ] || PROFILES=(awg1 awg2 awg3)
if [ -x /usr/local/go/bin/go ]; then PATH="/usr/local/go/bin:$PATH"; fi     # a tarball install

reference_down() {
    if [ -n "$GOPID" ]; then kill "$GOPID" 2> /dev/null || true; wait "$GOPID" 2> /dev/null || true; fi
    GOPID=
    ip link del "$IF" 2> /dev/null || true
    rm -f "/var/run/amneziawg/$IF.sock"
}

cleanup() {
    reference_down
    rm -rf "$WORK"
}
trap cleanup EXIT

command -v go > /dev/null || { echo "go not found: Go >= 1.25 builds amneziawg-go" >&2; exit 2; }
[ -d "$REFS/amneziawg-go" ] && [ -d "$REFS/amneziawg-tools" ] || { echo "no clones in $REFS" >&2; exit 2; }
[ -c /dev/net/tun ] || { echo "no /dev/net/tun" >&2; exit 2; }

echo "== build"
# -buildvcs=false: the clone lives on the Windows drive, owned by another user, and git refuses to
# read it as root ("dubious ownership"), which fails the build over a VCS stamp nobody needs.
(cd "$REFS/amneziawg-go" && go build -buildvcs=false -o "$WORK/amneziawg-go" .)
cp -r "$REFS/amneziawg-tools/src" "$WORK/awg-src"
make -s -C "$WORK/awg-src" wg > /dev/null
AWG="$WORK/awg-src/wg"
gcc -std=gnu99 -O1 -g -Wall -Wextra -Wno-unused-parameter -fsanitize=address,undefined \
    -I"$ENGINE/src" -o "$WORK/wg_interop" "$ENGINE"/src/*.c "$HERE/wg_interop.c" -lcrypto

cd "$WORK"
umask 077
"$AWG" genkey > ref.key
"$AWG" pubkey < ref.key > ref.pub
"$AWG" genkey > ours.key
"$AWG" pubkey < ours.key > ours.pub
"$AWG" genpsk > psk
"$AWG" genkey > hp.key          # a header protection key is a key like any other

V6=1
[ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2> /dev/null || echo 1)" = 0 ] || V6=0

# The profiles: shared lines, then each side's own.
shared() {
    case "$1" in
        awg1) printf 'S1 = 52\nS2 = 16\nH1 = 1027243093\nH2 = 1413412324\nH3 = 2069839512\nH4 = 1661493127\n' ;;
        awg2 | awg3)
            printf 'S1 = 24\nS2 = 32\nS3 = 16\nS4 = 20\n'
            printf 'H1 = 100000-100999\nH2 = 200000-200999\nH3 = 300000-300999\nH4 = 400000-499999\n'
            if [ "$1" = awg3 ]; then printf 'HeaderProtectionKey = %s\nRandomTrailers = on\n' "$(cat hp.key)"; fi ;;
    esac
}

ours_only() {
    case "$1" in
        awg1) printf 'Jc = 4\nJmin = 40\nJmax = 70\n' ;;
        awg2 | awg3)
            printf 'Jc = 5\nJmin = 10\nJmax = 50\n'
            printf 'I1 = <b 0xc70000000108ce1bfe8e8c5a0f2a><r 32><t>\nI2 = <b 0xdead><rc 8><rd 4>\nI5 = <dz 16>\n'
            if [ "$1" = awg3 ]; then printf 'ContentPaddingAddition = 8-48\nKeepaliveTimeout = 8-12\n'; fi ;;
    esac
    if [ "${2:-}" = soak ]; then printf 'RekeyAfterTime = 30-40\n'; fi
}

reference_only() {
    case "$1" in
        awg2) printf 'Jc = 3\nJmin = 30\nJmax = 60\n' ;;
        awg3) printf 'Jc = 3\nJmin = 30\nJmax = 60\nContentPaddingAddition = 0-32\n' ;;
    esac
}

write_confs() {
    {
        printf '[Interface]\nPrivateKey = %s\nAddress = 10.98.0.2/32, fd98::2/128\n' "$(cat ours.key)"
        shared "$1"
        ours_only "$1" "${2:-}"
        printf '\n[Peer]\nPublicKey = %s\nPresharedKey = %s\n' "$(cat ref.pub)" "$(cat psk)"
        printf 'AllowedIPs = 10.98.0.0/24, fd98::/64\nEndpoint = 127.0.0.1:%s\n' "$KPORT"
    } > ours.conf
    {
        printf '[Interface]\nPrivateKey = %s\nListenPort = %s\n' "$(cat ref.key)" "$KPORT"
        shared "$1"
        reference_only "$1"
        printf '\n[Peer]\nPublicKey = %s\nPresharedKey = %s\n' "$(cat ours.pub)" "$(cat psk)"
        printf 'AllowedIPs = 10.98.0.2/32, fd98::2/128\nEndpoint = 127.0.0.1:%s\n' "$OPORT"
    } > ref.conf
}

reference_up() {
    local i
    reference_down
    LOG_LEVEL=error "$WORK/amneziawg-go" -f "$IF" > amneziawg-go.log 2>&1 &
    GOPID=$!
    for i in $(seq 1 50); do
        [ -S "/var/run/amneziawg/$IF.sock" ] && break
        sleep 0.1
    done
    "$AWG" setconf "$IF" ref.conf
    ip addr add 10.98.0.1/24 dev "$IF"
    if [ $V6 = 1 ]; then ip -6 addr add fd98::1/64 dev "$IF" nodad; fi
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

fails() {
    ! "$@"
}

for prof in "${PROFILES[@]}"; do
    echo "== $prof: 1. we initiate"
    write_confs "$prof"
    reference_up
    step "$prof IPv4 echo, handshake from us" ./wg_interop ours.conf "$OPORT" ping 10.98.0.1 5
    if [ $V6 = 1 ]; then step "$prof IPv6 echo" ./wg_interop ours.conf "$OPORT" ping fd98::1 5; fi
    "$AWG" show "$IF" latest-handshakes
    "$AWG" show "$IF" transfer

    echo "== $prof: 2. amneziawg-go initiates"
    reference_up
    ./wg_interop ours.conf "$OPORT" answer 10 &
    HARNESS=$!
    sleep 1
    step "$prof: it pings us (IPv4)" ping -c 3 -i 0.5 -W 3 10.98.0.2
    if [ $V6 = 1 ]; then step "$prof: it pings us (IPv6)" ping -6 -c 3 -i 0.5 -W 3 fd98::2; fi
    step "$prof: we answered" wait "$HARNESS"

    if [ $SOAK = 1 ]; then
        echo "== $prof: 3. soak: 100 s, renewed every 30-40 s"
        write_confs "$prof" soak
        reference_up
        step "$prof: 100 echoes through renewals" ./wg_interop ours.conf "$OPORT" soak 10.98.0.1 100
        "$AWG" show "$IF" latest-handshakes
    fi

    if [ "$prof" = awg3 ]; then
        # The control: amneziawg-go keeps the key it was given, ours gets another one. If this
        # passed, the header protection above would have proved nothing.
        echo "== $prof: control - another header protection key gets nowhere"
        write_confs "$prof"
        reference_up
        "$AWG" genkey > hp.key
        write_confs "$prof"
        step "$prof: no tunnel with another key" fails ./wg_interop ours.conf "$OPORT" ping 10.98.0.1 3
        "$AWG" show "$IF" latest-handshakes
    fi
done

if [ $FAILED = 0 ]; then echo "== interop (AmneziaWG): all passed"; else echo "== interop (AmneziaWG): FAILED"; fi
exit $FAILED
