#!/usr/bin/env bash
#
# Builds client_test (client_test.cpp) against Qt 5 in WSL, with ASan + UBSan, and runs its demo half:
#
#   MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -u root -- bash /mnt/e/dev/momentics-projects/Tunnel/client/test/build.sh
#
# The client code is the phone's (Qt 4.8 there); here it builds against Qt 5 (apt: qtbase5-dev), and
# BB10's platform classes come from stubs/. The half against the real daemon runs inside the daemon's
# e2e world: daemon/test/e2e/run.sh client (build the daemon first: daemon/build.sh host); its
# Tailscale half on the Tailscale stand: daemon/test/ts/e2e.sh [tls] client.
# Output: daemon/build/client/ (ignored by git).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT="$(cd "$HERE/.." && pwd)"
TUNNEL="$(cd "$CLIENT/.." && pwd)"
DAEMON="$TUNNEL/daemon"
SHARED="$(cd "$TUNNEL/../bb-shared" && pwd)"
OUT="$DAEMON/build/client"
MOC=/usr/lib/qt5/bin/moc

command -v pkg-config > /dev/null && [ -x "$MOC" ] || { echo "needs Qt 5: apt-get install qtbase5-dev" >&2; exit 2; }

mkdir -p "$OUT/moc"
QT_CFLAGS="$(pkg-config --cflags Qt5Core Qt5Network)"
QT_LIBS="$(pkg-config --libs Qt5Core Qt5Network)"
# The phone's tree has no TUNNEL_DEMO in a production build; the test wants both halves.
DEFS=(-DTUNNEL_DEMO)
INC=(-I"$HERE/stubs" -I"$CLIENT" -I"$DAEMON/src" -I"$SHARED/l10n")
SAN=(-fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=undefined)
# Qt 5 deprecates some Qt 4 calls the client makes (qStableSort, QSet::toList, toTime_t): not ours to fix.
WARN=(-Wall -Wextra -Wno-deprecated-declarations)

HEADERS=(DaemonClient.hpp Profiles.hpp TunnelSettings.hpp DemoDaemon.hpp service/Notifier.hpp service/RootAutostart.hpp
    gui/Importer.hpp)
SOURCES=(DaemonClient.cpp Profiles.cpp TunnelSettings.cpp DemoDaemon.cpp service/Notifier.cpp service/RootAutostart.cpp
    gui/Importer.cpp gui/AmneziaKey.cpp)

echo "== client_test (Qt $(pkg-config --modversion Qt5Core), g++ $(g++ -dumpversion))"
for h in "${HEADERS[@]}"; do
    "$MOC" "${DEFS[@]}" "${INC[@]}" "$CLIENT/$h" -o "$OUT/moc/moc_$(basename "$h" .hpp).cpp"
done
gcc -std=gnu99 -O1 -g -Wall -Wextra "${SAN[@]}" -I"$DAEMON/src" -c "$DAEMON/src/bt_proto.c" -o "$OUT/bt_proto.o"
g++ -std=c++11 -O1 -g -fPIC "${WARN[@]}" "${SAN[@]}" "${DEFS[@]}" "${INC[@]}" $QT_CFLAGS \
    -o "$OUT/client_test" \
    "$HERE/client_test.cpp" "${SOURCES[@]/#/$CLIENT/}" "$OUT"/moc/*.cpp "$OUT/bt_proto.o" \
    $QT_LIBS -lz

export ASAN_OPTIONS=detect_leaks=0
echo "== AmneziaVPN keys"
rc=0
"$OUT/client_test" --keys || rc=1
echo "== the demo half"
"$OUT/client_test" --demo || rc=1
exit $rc
