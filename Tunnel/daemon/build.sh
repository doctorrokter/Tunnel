#!/usr/bin/env bash
#
# Build and run the daemon's tests. Runs inside WSL:
#
#   MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -u root -- bash /mnt/e/dev/momentics-projects/Tunnel/daemon/build.sh [host|cross|all]
#
#   host  (default)  x86_64 with ASan + UBSan against the system OpenSSL 3.x; runs every test/test_*.c
#   cross            the same sources for BB10 (gcc 9.3, our static OpenSSL 3.5.8 from
#                    /root/bbnet-deps/stage, as the engine): proves they compile and link for the
#                    phone; the test binaries land in build/bb10/
#   all              both
#
# The engine is compiled in from ../engine/src; its test harness (test_util.h) is shared.
# Output goes to daemon/build/ (ignored by git).

set -euo pipefail

DAEMON="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE="$(cd "$DAEMON/../engine" && pwd)"
OUT="$DAEMON/build"
MODE="${1:-host}"

# The core the unit tests link - the sans-IO modules and the TLS client (libssl: Tailscale) - then
# the daemon adds the Tailscale side, the tunnels, the control socket, main and a platform backend;
# btctl needs only the protocol.
CORE=(bt_proto bt_store bt_log bt_resolve bt_tls ts_derp ts_profile ts_http1 ts_h2 ts_json ts_netmap ts_noise ts_dns ts_disco ts_path ts_stun)
SRCS=("${CORE[@]/#/$DAEMON/src/}")
SRCS=("${SRCS[@]/%/.c}" "$ENGINE"/src/*.c)
DAEMON_SRCS=("${SRCS[@]}" "$DAEMON/src/bt_ts_relay.c" "$DAEMON/src/bt_ts_control.c" "$DAEMON/src/bt_tailscale.c"
             "$DAEMON/src/bt_tunnel.c" "$DAEMON/src/bt_ctl.c" "$DAEMON/src/main.c")
TESTS=("$DAEMON"/test/test_*.c)
INC=(-I"$DAEMON/src" -I"$ENGINE/src" -I"$ENGINE/test")

WARN="-Wall -Wextra -Wno-unused-parameter -Wno-unused-function"

build_host() {
    local dir="$OUT/host" failed=0 t name
    mkdir -p "$dir"
    echo "== host build (gcc $(gcc -dumpversion), $(openssl version | cut -d' ' -f1-2))"
    for t in "${TESTS[@]}"; do
        name="$(basename "$t" .c)"
        gcc -std=gnu99 -O1 -g $WARN -fno-omit-frame-pointer \
            -fsanitize=address,undefined -fno-sanitize-recover=undefined \
            "${INC[@]}" -o "$dir/$name" "${SRCS[@]}" "$t" -lssl -lcrypto
    done
    echo "== bbtunneld and btctl (Linux backend)"
    gcc -std=gnu99 -O1 -g $WARN -fno-omit-frame-pointer         -fsanitize=address,undefined -fno-sanitize-recover=undefined         "${INC[@]}" -o "$dir/bbtunneld" "${DAEMON_SRCS[@]}" "$DAEMON/src/bt_plat_linux.c" -lssl -lcrypto
    gcc -std=gnu99 -O1 -g $WARN -fsanitize=address,undefined         "${INC[@]}" -o "$dir/btctl" "$DAEMON/src/bt_proto.c" "$DAEMON/src/btctl.c"
    echo "== running"
    for t in "${TESTS[@]}"; do
        name="$(basename "$t" .c)"
        if ! "$dir/$name"; then failed=1; fi
    done
    return $failed
}

build_cross() {
    local toolchain_env="${TOOLCHAIN_ENV:-/root/bbndk/gcc9/bb10-gcc9/env.sh}"
    local ssl="${BB10_OPENSSL:-/root/bbnet-deps/stage}"
    local abi="${QNX_ABI:-arm-blackberry-qnx8eabi}"
    local ndk="${BB10_NDK_TARGET:-$(ls -d /root/bbndk/target_*/qnx6 2>/dev/null | head -1 || true)}"
    local dir="$OUT/bb10" t name

    # shellcheck disable=SC1090
    source "$toolchain_env" > /dev/null 2>&1 || true
    command -v "$abi-gcc" > /dev/null || { echo "$abi-gcc not on PATH" >&2; return 1; }
    [ -f "$ssl/lib/libcrypto.a" ] || { echo "no BB10 libcrypto.a at $ssl/lib" >&2; return 1; }

    mkdir -p "$dir"
    echo "== cross build for BB10 ($abi-gcc $("$abi-gcc" -dumpversion), OpenSSL from $ssl)"
    for t in "${TESTS[@]}"; do
        name="$(basename "$t" .c)"
        # libcrypto STATICALLY: BB10's own OpenSSL is 1.0.1i (see engine/build.sh).
        "$abi-gcc" -std=gnu99 -O2 $WARN "${INC[@]}" -I"$ssl/include" \
            -o "$dir/$name" "${SRCS[@]}" "$t" \
            "$ssl/lib/libssl.a" "$ssl/lib/libcrypto.a" -lsocket -lm -static-libgcc
        "$abi-strip" "$dir/$name"
    done
    # btctl: the daemon's client for SSH on the phone; bbtunneld with the QNX backend. Both ship in
    # the .bar as assets (BBTunnel/bar-descriptor.xml).
    "$abi-gcc" -std=gnu99 -O2 $WARN "${INC[@]}" -o "$dir/btctl" "$DAEMON/src/bt_proto.c" "$DAEMON/src/btctl.c" \
        -lsocket -static-libgcc
    "$abi-strip" "$dir/btctl"
    if [ -f "$DAEMON/src/bt_plat_qnx.c" ]; then
        "$abi-gcc" -std=gnu99 -O2 $WARN "${INC[@]}" -I"$ssl/include" -o "$dir/bbtunneld" \
            "${DAEMON_SRCS[@]}" "$DAEMON/src/bt_plat_qnx.c" "$ssl/lib/libssl.a" "$ssl/lib/libcrypto.a" -lsocket -lm -static-libgcc
        "$abi-strip" "$dir/bbtunneld"
    else
        echo "== bbtunneld: no QNX backend yet (step 3); the shared sources only compiled"
        for f in bt_tunnel bt_ctl main; do
            "$abi-gcc" -std=gnu99 -O2 $WARN "${INC[@]}" -I"$ssl/include" -c -o "$dir/$f.o" "$DAEMON/src/$f.c"
        done
    fi
    ls -l "$dir"
    echo "== NEEDED of one test binary (no libcrypto / libssl may appear here)"
    "$abi-readelf" -d "$dir/$(basename "${TESTS[0]}" .c)" | grep NEEDED || true
}

# bt_lookup against WSL's own resolver over real UDP, checked against getaddrinfo (needs network).
build_live() {
    local dir="$OUT/host" server
    mkdir -p "$dir"
    gcc -std=gnu99 -O1 -g $WARN -fsanitize=address,undefined "${INC[@]}" -o "$dir/dns_live" \
        "$DAEMON/src/bt_resolve.c" "$ENGINE/src/wg_crypto.c" "$DAEMON/test/live/dns_live.c" -lcrypto
    server="$(awk '/^nameserver/ { print $2; exit }' /etc/resolv.conf)"
    echo "== dns_live against $server"
    "$dir/dns_live" "$server" "$@"
}

case "$MODE" in
    host)  build_host ;;
    cross) build_cross ;;
    all)   build_host && build_cross ;;
    live)  shift; build_live "${@:-example.com}" ;;
    *)     echo "usage: $0 [host|cross|all|live [names...]]" >&2; exit 2 ;;
esac
