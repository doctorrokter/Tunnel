#!/usr/bin/env bash
#
# The Tailscale stand's own binaries, from the read-only reference clones in refs/ (docs/TAILSCALE.md,
# section 13): Headscale (the control server, with its embedded DERP), derper (a DERP server of its
# own, for the TLS stage), and the official tailscaled + tailscale CLI (the "NAS" of the stand).
# Runs inside WSL:
#
#   MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -u root -- bash /mnt/e/dev/momentics-projects/Tunnel/daemon/test/ts/stand_build.sh
#
# Output: daemon/build/stand/ (ignored by git). Go modules are fetched on the first build.
# -buildvcs=false: the clones sit on the Windows disk under another owner, and git as root in WSL
# refuses to read them ("dubious ownership") - the VCS stamp nobody needs would fail the build.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TUNNEL="$(cd "$HERE/../../.." && pwd)"
REFS="$(cd "$TUNNEL/../refs" && pwd)"
OUT="$TUNNEL/daemon/build/stand"

if [ -x /usr/local/go/bin/go ]; then PATH="/usr/local/go/bin:$PATH"; fi
command -v go > /dev/null || { echo "needs Go (engine/README.md: /usr/local/go)" >&2; exit 2; }
[ -d "$REFS/tailscale" ] && [ -d "$REFS/headscale" ] || { echo "needs refs/tailscale and refs/headscale" >&2; exit 2; }

mkdir -p "$OUT"
echo "== $(go version)"
echo "== tailscale $(cd "$REFS/tailscale" && cat VERSION.txt 2>/dev/null || echo '?'): tailscaled, tailscale, derper"
(cd "$REFS/tailscale" && go build -buildvcs=false -o "$OUT/" ./cmd/tailscaled ./cmd/tailscale ./cmd/derper)
echo "== headscale"
(cd "$REFS/headscale" && go build -buildvcs=false -o "$OUT/headscale" ./cmd/headscale)
ls -l "$OUT"
