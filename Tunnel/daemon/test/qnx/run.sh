#!/usr/bin/env bash
#
# The QNX backend's DNS section on the host: status_public (what BB10's resolver reads) and
# _CS_RESOLVE, as bt_plat_qnx.c has them - extracted from the source as it is (from its "DNS" header
# to pps_close) and built with stubs (dns_probe.c): confstr in memory, status_public a temp file.
# Runs in WSL:
#
#   MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -u root -- bash /mnt/e/dev/momentics-projects/Tunnel/daemon/test/qnx/run.sh
#
# Output: daemon/build/qnx/ (ignored by git).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAEMON="$(cd "$HERE/../.." && pwd)"
OUT="$DAEMON/build/qnx"

mkdir -p "$OUT"
awk '/^\/\* -+ DNS \*\//{on=1} /^static void pps_close/{on=0} on' "$DAEMON/src/bt_plat_qnx.c" > "$OUT/qnx_dns_body.c"
[ -s "$OUT/qnx_dns_body.c" ] || { echo "the DNS section of bt_plat_qnx.c was not found" >&2; exit 1; }
gcc -std=gnu99 -O1 -g -Wall -Wextra -Wno-unused-function -Wno-unused-parameter -fsanitize=address,undefined \
    -I"$OUT" -I"$DAEMON/src" -I"$DAEMON/../engine/src" -o "$OUT/dns_probe" "$HERE/dns_probe.c"
"$OUT/dns_probe"
