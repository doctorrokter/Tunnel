#!/usr/bin/env bash
#
# Build and run the engine tests. Runs inside WSL:
#
#   MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -u root -- bash /mnt/e/dev/momentics-projects/Tunnel/engine/build.sh [host|cross|all]
#
#   host  (default)  x86_64 build against the system OpenSSL 3.x with ASan + UBSan, and run every
#                    test/test_*.c. The fast loop - sans-IO code needs no phone.
#   cross            the same sources for BB10 with the gcc 9.3 toolchain against OUR OpenSSL 3.5.8
#                    (the static libcrypto.a that bb-shared/net/deps/build-net.sh leaves in
#                    /root/bbnet-deps/stage - it used to be Syno's /root/syno-deps). Proves the engine
#                    compiles and links for the phone; the test binaries and wg_bench land in
#                    build/bb10/ for a manual run there.
#   all              both.
#   bench [seconds]  test/bench/wg_bench.c on the workstation, optimised, no sanitizers: what a
#                    handshake, sealing, opening and an AllowedIPs lookup cost on one core.
#
# Output goes to engine/build/ (ignored by git).

set -euo pipefail

ENGINE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$ENGINE/build"
MODE="${1:-host}"

SRCS=("$ENGINE"/src/*.c)
TESTS=("$ENGINE"/test/test_*.c)

WARN="-Wall -Wextra -Wno-unused-parameter -Wno-unused-function"

build_host() {
    local dir="$OUT/host" failed=0 t name
    mkdir -p "$dir"
    echo "== host build (gcc $(gcc -dumpversion), $(openssl version | cut -d' ' -f1-2))"
    for t in "${TESTS[@]}"; do
        name="$(basename "$t" .c)"
        gcc -std=gnu99 -O1 -g $WARN -fno-omit-frame-pointer \
            -fsanitize=address,undefined -fno-sanitize-recover=undefined \
            -I"$ENGINE/src" -o "$dir/$name" "${SRCS[@]}" "$t" -lcrypto
    done
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
    local dir="$OUT/bb10" t name

    # shellcheck disable=SC1090
    source "$toolchain_env" > /dev/null 2>&1 || true
    command -v "$abi-gcc" > /dev/null || { echo "$abi-gcc not on PATH" >&2; return 1; }
    [ -f "$ssl/lib/libcrypto.a" ] || { echo "no BB10 libcrypto.a at $ssl/lib" >&2; return 1; }

    mkdir -p "$dir"
    echo "== cross build for BB10 ($abi-gcc $("$abi-gcc" -dumpversion), OpenSSL from $ssl)"
    for t in "${TESTS[@]}"; do
        name="$(basename "$t" .c)"
        # libcrypto is linked STATICALLY: BB10 carries OpenSSL 1.0.1i, which lacks BLAKE2s and
        # the 3.x EVP API, and must never be picked up by accident (memory: headers vs library).
        "$abi-gcc" -std=gnu99 -O2 $WARN \
            -I"$ENGINE/src" -I"$ssl/include" \
            -o "$dir/$name" "${SRCS[@]}" "$t" \
            "$ssl/lib/libcrypto.a" -lsocket -lm \
            -static-libgcc
        "$abi-strip" "$dir/$name"
    done
    "$abi-gcc" -std=gnu99 -O2 $WARN -I"$ENGINE/src" -I"$ssl/include" \
        -o "$dir/wg_bench" "${SRCS[@]}" "$ENGINE/test/bench/wg_bench.c" \
        "$ssl/lib/libcrypto.a" -lsocket -lm -static-libgcc
    "$abi-strip" "$dir/wg_bench"
    ls -l "$dir"
    echo "== NEEDED of one test binary (no libcrypto / libssl may appear here)"
    "$abi-readelf" -d "$dir/$(basename "${TESTS[0]}" .c)" | grep NEEDED || true
}

build_bench() {
    local dir="$OUT/host"
    mkdir -p "$dir"
    echo "== bench (gcc $(gcc -dumpversion) -O2, $(openssl version | cut -d' ' -f1-2))"
    gcc -std=gnu99 -O2 $WARN -I"$ENGINE/src" -o "$dir/wg_bench" "${SRCS[@]}" \
        "$ENGINE/test/bench/wg_bench.c" -lcrypto
    "$dir/wg_bench" "${1:-2}"
}

case "$MODE" in
    host)  build_host ;;
    cross) build_cross ;;
    all)   build_host && build_cross ;;
    bench) build_bench "${2:-2}" ;;
    *)     echo "usage: $0 [host|cross|all|bench [seconds]]" >&2; exit 2 ;;
esac
