#!/usr/bin/env bash
#
# ts_derp against Tailscale's own DERP server: `derper -dev` (plain HTTP on :3340) in a network
# namespace of its own, and derp_interop.c talking to it. Runs in WSL as root, after
# stand_build.sh:
#
#   MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -u root -- bash /mnt/e/dev/momentics-projects/Tunnel/daemon/test/ts/derp_interop.sh

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TUNNEL="$(cd "$HERE/../../.." && pwd)"
BIN="$TUNNEL/daemon/build/stand"
OUT="$TUNNEL/daemon/build/ts-derp"
NS=ts-derp-io
W="-std=gnu99 -Wall -Wextra -Wno-unused-parameter -Wno-unused-function -Werror"
SAN="-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=undefined"

[ -x "$BIN/derper" ] || { echo "build first: stand_build.sh" >&2; exit 2; }
mkdir -p "$OUT"
gcc $W $SAN -I"$TUNNEL/daemon/src" -I"$TUNNEL/engine/src" -I"$TUNNEL/engine/test" -o "$OUT/derp_interop" \
    "$HERE/derp_interop.c" "$TUNNEL/daemon/src/ts_derp.c" "$TUNNEL/engine/src/wg_salsa.c" \
    "$TUNNEL/engine/src/wg_crypto.c" -lcrypto

PID=
cleanup() {
    [ -n "$PID" ] && kill "$PID" 2> /dev/null
    wait 2> /dev/null
    ip netns del "$NS" 2> /dev/null
}
trap cleanup EXIT
ip netns del "$NS" 2> /dev/null || true
ip netns add "$NS"
ip -n "$NS" link set lo up
LOG="$(mktemp /tmp/derper.XXXXXX)"
ip netns exec "$NS" "$BIN/derper" -dev -stun=false > "$LOG" 2>&1 &
PID=$!
for i in $(seq 1 50); do
    ip netns exec "$NS" bash -c 'exec 3<>/dev/tcp/127.0.0.1/3340' 2> /dev/null && break
    sleep 0.1
done
ip netns exec "$NS" "$OUT/derp_interop" 127.0.0.1 3340 || { tail -20 "$LOG"; exit 1; }
rm -f "$LOG"
