#!/usr/bin/env bash
#
# bt_ts_relay against Tailscale's own DERP servers: two `derper` over plain HTTP (regions 1 and 2,
# ports 3340 and 3341) in a network namespace of their own, and relay_interop.c driving two sets of
# relays through them - bt_tls in its plain mode, ts_http1's upgrade, ts_derp. On SIGUSR1 a helper
# stops derper 1 and starts it again two seconds later: home must follow. Runs in WSL as root,
# after stand_build.sh:
#
#   MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -u root -- bash /mnt/e/dev/momentics-projects/Tunnel/daemon/test/ts/relay_interop.sh

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TUNNEL="$(cd "$HERE/../../.." && pwd)"
BIN="$TUNNEL/daemon/build/stand"
OUT="$TUNNEL/daemon/build/ts-derp"
NS=ts-relay-io
W="$(mktemp -d /tmp/ts_relay.XXXXXX)"
WARN="-std=gnu99 -Wall -Wextra -Wno-unused-parameter -Wno-unused-function -Werror"
SAN="-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=undefined"
S="$TUNNEL/daemon/src"
E="$TUNNEL/engine/src"

[ -x "$BIN/derper" ] || { echo "build first: stand_build.sh" >&2; exit 2; }
mkdir -p "$OUT"
gcc $WARN $SAN -I"$S" -I"$E" -I"$TUNNEL/engine/test" -o "$OUT/relay_interop" "$HERE/relay_interop.c" \
    "$S/bt_ts_relay.c" "$S/bt_tls.c" "$S/ts_http1.c" "$S/ts_derp.c" "$S/bt_log.c" "$S/bt_resolve.c" \
    "$E/wg_salsa.c" "$E/wg_crypto.c" -lssl -lcrypto

HELPER=
D2=
cleanup() {
    [ -n "$HELPER" ] && kill "$HELPER" 2> /dev/null
    [ -n "$D2" ] && kill "$D2" 2> /dev/null
    wait 2> /dev/null
    ip netns del "$NS" 2> /dev/null
    rm -rf "$W"
}
trap cleanup EXIT
ip netns del "$NS" 2> /dev/null || true
ip netns add "$NS"
ip -n "$NS" link set lo up

# derper 1 under a helper that restarts it on SIGUSR1.
helper() {
    local d1=
    start() {
        ip netns exec "$NS" "$BIN/derper" -a 127.0.0.1:3340 -c "$W/d1.json" -stun=false >> "$W/d1.log" 2>&1 &
        d1=$!
    }
    start
    trap 'kill $d1 2> /dev/null; wait $d1 2> /dev/null; sleep 2; start' USR1
    trap 'kill $d1 2> /dev/null; exit 0' TERM
    while :; do sleep 0.2; done
}
helper &
HELPER=$!
echo "$HELPER" > "$W/helper.pid"
ip netns exec "$NS" "$BIN/derper" -a 127.0.0.1:3341 -c "$W/d2.json" -stun=false > "$W/d2.log" 2>&1 &
D2=$!
for port in 3340 3341; do
    for i in $(seq 1 50); do
        ip netns exec "$NS" bash -c "exec 3<>/dev/tcp/127.0.0.1/$port" 2> /dev/null && break
        sleep 0.1
    done
done
ip netns exec "$NS" "$OUT/relay_interop" "$W/helper.pid" 3340 3341 || { tail -5 "$W/d1.log" "$W/d2.log"; exit 1; }
