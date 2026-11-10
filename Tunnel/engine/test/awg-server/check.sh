#!/usr/bin/env bash
#
# start.sh beside this file as the server runs it - amneziawg-go and awg built from refs/ at the image's versions,
# in a network namespace of its own - and bbtunneld (the host build: daemon/build.sh host) as the phone,
# importing the four configs it makes. In WSL, as root:
#
#   MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -u root -- bash /mnt/e/dev/momentics-projects/Tunnel/engine/test/awg-server/check.sh
#
# Both servers up, the configs' modes, the NAT rules; each config: imported as AmneziaWG, up (a handshake),
# the server's tunnel address pinged, a full one past the NAS too; a clean stop (interfaces and rules
# gone); a second start with the same keys; a NAS whose iptables fails - the servers up without NAT, the
# split configs working. No iptables needed here: a stand-in keeps the rules as lines.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="$(cd "$HERE/../../.." && pwd)"
REFS="$(cd "$T/../refs" && pwd)"
BIN=$T/daemon/build/host
W=/tmp/nasawg
rm -rf "$W"; mkdir -p "$W/bin" "$W/config" "$W/state"
if [ -x /usr/local/go/bin/go ]; then PATH="/usr/local/go/bin:$PATH"; fi
FAILED=0
step() { local n="$1"; shift; if "$@"; then echo "   ok    $n"; else echo "   FAIL  $n"; FAILED=1; fi; }
within() { local s=$1 e; shift; e=$((SECONDS + s)); while :; do "$@" > /dev/null 2>&1 && return 0; [ $SECONDS -ge $e ] && return 1; sleep 0.3; done; }

echo "== build the reference"
(cd "$REFS/amneziawg-go" && go build -buildvcs=false -o "$W/bin/amneziawg-go" .) || exit 2
cp -r "$REFS/amneziawg-tools/src" "$W/awg-src"
make -s -C "$W/awg-src" wg > /dev/null || exit 2
cp "$W/awg-src/wg" "$W/bin/awg"
# the clone sits on the Windows drive with CRLF: "#!/bin/bash\r" would be "not found"
tr -d '\r' < "$W/awg-src/wg-quick/linux.bash" > "$W/bin/awg-quick"
chmod +x "$W/bin/awg-quick"
# No iptables in this WSL: a stand-in that keeps the rules as lines (the NAS image has the real one).
cat > "$W/bin/iptables-legacy" << 'EOF'
#!/bin/sh
# iptables-legacy stand-in: "-t nat -A ..." adds a line, "-t nat -D ..." takes it away
R=/tmp/nasawg/nat.rules
case "$3" in
    -A) echo "$*" >> "$R" ;;
    -D) r="$(echo "$*" | sed 's/ -D / -A /')"; grep -vxF -- "$r" "$R" > "$R.tmp"; mv "$R.tmp" "$R" ;;
esac
EOF
chmod +x "$W/bin/iptables-legacy"; : > "$W/nat.rules"
export PATH="$W/bin:$PATH"

cleanup() {
    [ -n "${DPID:-}" ] && kill "$DPID" 2> /dev/null && wait "$DPID" 2> /dev/null
    if [ -n "${SPID:-}" ]; then
        kill -TERM "$SPID" 2> /dev/null; wait "$SPID" 2> /dev/null
    fi
    ip netns del awgnas 2> /dev/null; ip netns del awgphone 2> /dev/null
    rm -rf /etc/netns/awgphone
}
trap cleanup EXIT

ip netns del awgnas 2> /dev/null; ip netns del awgphone 2> /dev/null
ip netns add awgnas; ip netns add awgphone
ip link add eth0 netns awgnas type veth peer name lan0 netns awgphone
ip -n awgnas addr add 10.55.0.1/24 dev eth0; ip -n awgnas link set eth0 up; ip -n awgnas link set lo up
ip -n awgnas addr add 10.55.9.9/32 dev lo     # "the internet" past the NAS, for the full tunnels
ip -n awgphone addr add 10.55.0.2/24 dev lan0; ip -n awgphone link set lan0 up; ip -n awgphone link set lo up
ip -n awgphone route add default via 10.55.0.1
mkdir -p /etc/netns/awgphone; echo "nameserver 10.55.0.1" > /etc/netns/awgphone/resolv.conf
ip netns exec awgnas sysctl -qw net.ipv4.ip_forward=1

echo "== the NAS: start.sh"
ip netns exec awgnas env SERVER_IP=10.55.0.1 CONFIG_DIR="$W/config" OUT_IF=eth0 PATH="$PATH" \
    sh "$T/engine/test/awg-server/start.sh" > "$W/start.log" 2>&1 &
SPID=$!
step "both servers up" within 20 grep -q "^up: awg0" "$W/start.log"
step "four phone configs, 0644; servers' 0600" bash -c "cd '$W/config' && [ \$(stat -c %a phone-awg2.conf phone-awg2-full.conf phone-awg3.conf phone-awg3-full.conf | sort -u) = 644 ] && [ \$(stat -c %a awg0.conf) = 600 ]"
step "NAT rules in (two MASQUERADE, -o eth0)" bash -c "[ $(grep -c 'MASQUERADE' $W/nat.rules) = 2 ] && grep -q '10.77.0.0/24 -o eth0' $W/nat.rules && grep -q '10.78.0.0/24 -o eth0' $W/nat.rules"
step "the start log shows no private key" bash -c "! grep -qf <(cat '$W'/config/*.key) '$W/start.log'"

echo "== the phone: bbtunneld"
ip netns exec awgphone "$BIN/bbtunneld" --state "$W/state" --socket "$W/d.sock" --log "$W/daemon.txt" \
    --dns-file /etc/resolv.conf --egress bind > "$W/daemon.stderr" 2>&1 &
DPID=$!
within 5 test -S "$W/d.sock"
ctl() { "$BIN/btctl" -s "$W/d.sock" "$@"; }
for p in awg2 awg3; do
    for v in "" "-full"; do
        f="phone-$p$v.conf"
        id="$(ctl -k profile profile.import name="NAS $p$v" conf=@"$W/config/$f" 2> /dev/null)"
        step "$f imported (AmneziaWG)" bash -c "[ -n '$id' ] && '$BIN/btctl' -s '$W/d.sock' profile.list | grep -A3 'profile=$id' | grep -q 'type=amneziawg'"
        [ -n "$id" ] || continue
        ctl tunnel.up profile="$id" > /dev/null
        step "$f: up (a handshake)" ctl -t 15 wait "$id" up
        if [ "$p" = awg2 ]; then srv=10.77.0.1; else srv=10.78.0.1; fi
        step "$f: ping the server's tunnel address" within 10 ip netns exec awgphone ping -c 1 -W 2 "$srv"
        if [ -n "$v" ]; then
            step "$f: past the NAS through the tunnel (10.55.9.9)" within 10 ip netns exec awgphone ping -c 1 -W 2 10.55.9.9
            step "$f: ... and the route to it is the tunnel's" bash -c "ip netns exec awgphone ip route get 10.55.9.9 | grep -qv lan0"
        fi
        ctl tunnel.down profile="$id" > /dev/null
        ctl profile.delete profile="$id" > /dev/null
    done
done
echo "== the NAS's view"
ip netns exec awgnas awg show | grep -E "interface|latest handshake|transfer" | sed 's/^/     /'
step "no ASan / UBSan report from the daemon" bash -c "! grep -q 'ERROR: AddressSanitizer\|runtime error:' '$W/daemon.stderr'"

echo "== the NAS stops (TERM)"
kill -TERM "$SPID"; wait "$SPID" 2> /dev/null; SPID=
step "interfaces gone" bash -c "! ip -n awgnas link show awg0 2>/dev/null && ! ip -n awgnas link show awg1 2>/dev/null"
step "NAT rules gone" bash -c "! grep -q MASQUERADE $W/nat.rules"
echo "== a second start reuses the keys"
before="$(cat "$W/config/srv3.pub")"
ip netns exec awgnas env SERVER_IP=10.55.0.1 CONFIG_DIR="$W/config" OUT_IF=eth0 PATH="$PATH" \
    sh "$T/engine/test/awg-server/start.sh" > "$W/start2.log" 2>&1 &
SPID=$!
step "up again" within 20 grep -q "^up: awg0" "$W/start2.log"
step "same keys, no 'first start'" bash -c "[ \"\$(cat '$W/config/srv3.pub')\" = '$before' ] && ! grep -q 'first start' '$W/start2.log'"
echo "== a NAS whose iptables fails: the servers come up without NAT"
kill -TERM "$SPID"; wait "$SPID" 2> /dev/null; SPID=
printf '#!/bin/sh\nexit 1\n' > "$W/bin/iptables-legacy"
ip netns exec awgnas env SERVER_IP=10.55.0.1 CONFIG_DIR="$W/config" OUT_IF=eth0 PATH="$PATH" \
    sh "$T/engine/test/awg-server/start.sh" > "$W/start3.log" 2>&1 &
SPID=$!
step "up without NAT" within 20 grep -q "^up: awg0" "$W/start3.log"
step "... and the log says so, twice" bash -c "[ \$(grep -c '^no NAT: only' '$W/start3.log') = 2 ]"
id="$(ctl -k profile profile.import name=Split conf=@"$W/config/phone-awg3.conf" 2> /dev/null)"
ctl tunnel.up profile="$id" > /dev/null
step "the split profile works without NAT" ctl -t 15 wait "$id" up
echo; echo "---- start.log"; sed 's/^/     /' "$W/start.log" | head -30
if [ $FAILED = 0 ]; then echo "awg-server check: all passed"; else echo "awg-server check: FAILURES"; tail -20 "$W/daemon.txt"; fi
exit $FAILED
