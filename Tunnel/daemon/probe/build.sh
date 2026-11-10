#!/usr/bin/env bash
#
# Cross-build tunprobe for BB10 (armv7, QNX) with the gcc 9.3 toolchain, in WSL.
#
#   MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -u root -- bash /mnt/e/dev/momentics-projects/Tunnel/daemon/probe/build.sh
#
# Output: tunprobe next to this script. Plain C, no C++ runtime, so none of the gcc9-vs-4.8
# libstdc++ traps apply; -static-libgcc because BB10 ships no libgcc_s.so.1.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLCHAIN_ENV="${TOOLCHAIN_ENV:-/root/bbndk/gcc9/bb10-gcc9/env.sh}"
NDK="${BB10_NDK_TARGET:-$(ls -d /root/bbndk/target_*/qnx6 2>/dev/null | head -1 || true)}"
ABI="${QNX_ABI:-arm-blackberry-qnx8eabi}"

[ -f "$TOOLCHAIN_ENV" ] || { echo "no toolchain env at $TOOLCHAIN_ENV" >&2; exit 1; }
# shellcheck disable=SC1090
source "$TOOLCHAIN_ENV" > /dev/null 2>&1 || true
command -v "$ABI-gcc" > /dev/null || { echo "$ABI-gcc not on PATH" >&2; exit 1; }
[ -d "$NDK/usr/include" ] || { echo "no BB10 sysroot headers at $NDK" >&2; exit 1; }

# The toolchain's own sysroot is fine for libc, but the networking headers we need
# (net/if_tun.h, sys/sockio.h, netinet6/in6_var.h) live in the NDK target tree.
"$ABI-gcc" -O2 -g -std=gnu99 -Wall -Wextra -Wno-unused-parameter \
    -isystem "$NDK/usr/include" \
    -o "$SCRIPT_DIR/tunprobe" "$SCRIPT_DIR/tunprobe.c" \
    -L"$NDK/armle-v7/lib" -L"$NDK/armle-v7/usr/lib" \
    -lsocket \
    -static-libgcc

"$ABI-strip" "$SCRIPT_DIR/tunprobe"
ls -l "$SCRIPT_DIR/tunprobe"
"$ABI-readelf" -d "$SCRIPT_DIR/tunprobe" | grep NEEDED || true
