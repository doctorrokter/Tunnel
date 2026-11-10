#!/usr/bin/env bash
#
# The daemon end to end, in two network namespaces, against the Linux kernel's WireGuard (and with
# `awg`, against amneziawg-go). Runs in WSL as root; build first (build.sh host):
#
#   MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -u root -- bash /mnt/e/dev/momentics-projects/Tunnel/daemon/test/e2e/run.sh [awg] [hostroute] [client]
#
#   bt-phone   the phone: bbtunneld, a real tun device, "Wi-Fi" wifi0 192.168.1.2 and "LTE" lte0
#              10.64.0.2, its resolv.conf (/etc/netns/bt-phone/resolv.conf, which `ip netns exec`
#              mounts over /etc/resolv.conf - the WSL host's own is never touched)
#   bt-inet    the internet: WireGuard servers on 203.0.113.1, .2 and .3 (the same host), the
#              providers' DNS on 192.168.1.1 and 10.64.0.1 (vpn.test) and one past the gateway on
#              198.51.100.53, a DNS inside the tunnel on 10.99.0.1 (inside.test) and a web server on
#              198.18.0.1:8080. nft drops ICMP and port 8080 arriving from the phone's links, so a
#              ping or a fetch that works went THROUGH the tunnel.
#
# Scenarios: import errors with a line number; up; full tunnel (IPv4, IPv6, TCP, DNS inside);
# the "network manager" overwriting our DNS; Wi-Fi -> LTE with our routes wiped; the server's name
# moving to another address; the system's resolver past the gateway; a second, split tunnel beside
# the full one and a second full one refused; down restores the system's DNS; kill -9 and the crash
# journal; always-on; daemon.restart; SIGTERM; the handshake timestamp ceiling across a restart with
# the clock an hour behind (and its control: without the ceiling the server refuses us); log.debug
# (on for a while, off by itself); garbage on the control socket.
#
# `hostroute` runs it all with --egress hostroute: plain sockets kept out of the tunnels by host
# routes to the servers (section 5, the third way) instead of SO_BINDTODEVICE, and checks those
# routes on the way; without it, that there are none.
#
# `client` runs the app's and the service's own C++ against this daemon instead of the scenarios
# above: client/test/client_test (build it first: client/test/build.sh), in the phone's namespace, the
# daemon under a restart loop like the phone's launcher and its socket in an app-like sandbox
# (app/data/daemon.sock).
#
# Everything lives for the run: namespaces, /etc/netns/bt-phone, the work directory. The daemon's
# log is kept in daemon/build/e2e/ for a look afterwards.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAEMON="$(cd "$HERE/../.." && pwd)"
REFS="$DAEMON/../../refs"
BIN="${BT_BIN:-$DAEMON/build/host}"         # the mutation check points it at a broken build
KEEP="$DAEMON/build/e2e"
WORK="$(mktemp -d /tmp/bt_e2e.XXXXXX)"
PH=bt-phone
IN=bt-inet
SOCK="$WORK/d.sock"
STATE="$WORK/state"
RESOLV="/etc/netns/$PH/resolv.conf"
FAILED=0
DPID=
PIDS=()
AWG_RUN=0
HR=0
CLIENT_RUN=0
LOOP=
for a in "$@"; do
    case "$a" in
        awg) AWG_RUN=1 ;;
        hostroute) HR=1 ;;
        client) CLIENT_RUN=1 ;;
        *) echo "unknown argument: $a" >&2; exit 2 ;;
    esac
done
EGRESS=bind
[ $HR = 1 ] && EGRESS=hostroute

export ASAN_OPTIONS=detect_leaks=0

inph() { ip netns exec "$PH" "$@"; }
inin() { ip netns exec "$IN" "$@"; }
ctl() { "$BIN/btctl" -s "$SOCK" "$@"; }

daemon_start() {
    # Not through the inph function: a backgrounded function is a subshell, and $! would be ITS pid
    # - kill would miss the daemon. `ip netns exec` execs in place, so $! is the daemon.
    ip netns exec "$PH" "$BIN/bbtunneld" --state "$STATE" --socket "$SOCK" --log "$WORK/daemon.txt" \
        --dns-file /etc/resolv.conf --egress "$EGRESS" --debug "$@" >> "$WORK/daemon.stderr" 2>&1 &
    DPID=$!
    local i
    for i in $(seq 1 50); do
        [ -S "$SOCK" ] && ctl hello > /dev/null 2>&1 && return 0
        sleep 0.1
    done
    echo "the daemon did not come up" >&2
    return 1
}

daemon_stop() {
    if [ -n "$DPID" ]; then
        kill "$DPID" 2> /dev/null || true
        wait "$DPID" 2> /dev/null || true
    fi
    DPID=
}

cleanup() {
    set +e
    daemon_stop
    if [ -n "$LOOP" ]; then
        # The client run's restart loop: told to stop, then its daemon.
        touch "$WORK/stop"
        kill "$(cat "$WORK/daemon.pid" 2> /dev/null)" 2> /dev/null
        wait "$LOOP" 2> /dev/null
        cp "$WORK"/app/data/logs/daemon*.txt "$WORK/" 2> /dev/null
    fi
    for p in "${PIDS[@]}"; do kill "$p" 2> /dev/null; done
    wait 2> /dev/null
    ip netns del "$PH" 2> /dev/null
    ip netns del "$IN" 2> /dev/null
    rm -rf "/etc/netns/$PH"
    rm -f /var/run/amneziawg/awg-srv.sock
    mkdir -p "$KEEP"
    cp "$WORK"/daemon*.txt "$WORK/daemon.stderr" "$KEEP/" 2> /dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

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

fails() { ! "$@"; }

# Retries a check for up to $1 seconds.
within() {
    local secs="$1" i
    shift
    for i in $(seq 1 $((secs * 5))); do
        if "$@" > /dev/null 2>&1; then return 0; fi
        sleep 0.2
    done
    return 1
}

[ -x "$BIN/bbtunneld" ] && [ -x "$BIN/btctl" ] || { echo "build first: build.sh host" >&2; exit 2; }
command -v wg > /dev/null && command -v nft > /dev/null || { echo "needs wg and nft" >&2; exit 2; }
ip netns del "$PH" 2> /dev/null || true
ip netns del "$IN" 2> /dev/null || true

echo "== setup"
cd "$WORK"
umask 077
ip netns add "$PH"
ip netns add "$IN"
ip -n "$PH" link set lo up
ip -n "$IN" link set lo up
inph sysctl -qw net.ipv6.conf.all.disable_ipv6=0
ip link add wifi0 netns "$PH" type veth peer name wifi0-i netns "$IN"
ip link add lte0 netns "$PH" type veth peer name lte0-i netns "$IN"
ip -n "$PH" addr add 192.168.1.2/24 dev wifi0
ip -n "$PH" addr add 10.64.0.2/24 dev lte0
ip -n "$IN" addr add 192.168.1.1/24 dev wifi0-i
ip -n "$IN" addr add 10.64.0.1/24 dev lte0-i
for l in wifi0 lte0; do ip -n "$PH" link set "$l" up; ip -n "$IN" link set "$l-i" up; done
ip -n "$PH" route add default via 192.168.1.1 dev wifi0
for a in 203.0.113.1 203.0.113.2 203.0.113.3 198.18.0.1 198.51.100.53; do ip -n "$IN" addr add "$a/32" dev lo; done

wg genkey > srv.key; wg pubkey < srv.key > srv.pub
wg genkey > srv2.key; wg pubkey < srv2.key > srv2.pub
wg genkey > phone.key; wg pubkey < phone.key > phone.pub
wg genkey > phone2.key; wg pubkey < phone2.key > phone2.pub
wg genpsk > psk

ip -n "$IN" link add wg-srv type wireguard
inin wg set wg-srv private-key srv.key listen-port 51820 \
    peer "$(cat phone.pub)" preshared-key psk allowed-ips 10.99.0.2/32,fd99::2/128
ip -n "$IN" addr add 10.99.0.1/24 dev wg-srv
ip -n "$IN" -6 addr add fd99::1/64 dev wg-srv nodad
ip -n "$IN" link set wg-srv up
ip -n "$IN" link add wg-srv2 type wireguard
inin wg set wg-srv2 private-key srv2.key listen-port 51821 peer "$(cat phone2.pub)" allowed-ips 10.97.0.2/32
ip -n "$IN" addr add 10.97.0.1/24 dev wg-srv2
ip -n "$IN" link set wg-srv2 up

inin nft -f - << 'EOF'
table inet bt {
    chain input {
        type filter hook input priority 0; policy accept;
        iifname { "wifi0-i", "lte0-i" } meta l4proto { icmp, ipv6-icmp } drop
        iifname { "wifi0-i", "lte0-i" } tcp dport 8080 drop
    }
}
EOF

printf 'vpn.test 203.0.113.1\n' > zone.outer
printf 'inside.test 10.99.0.1\n' > zone.inner
printf 'vpn.test 203.0.113.3\n' > zone.remote
# Helpers in the background: straight through `ip netns exec` (it execs in place, so $! is the
# helper - through the inin function it would be a subshell's, kill would miss, and the helper
# would outlive the run holding its stdout), and with their output away from ours.
bg_inin() { ip netns exec "$IN" "$@" > /dev/null 2>&1 & PIDS+=($!); }
for b in 192.168.1.1 10.64.0.1; do bg_inin python3 "$HERE/dns_stub.py" "$b" zone.outer; done
bg_inin python3 "$HERE/dns_stub.py" 198.51.100.53 zone.remote
bg_inin python3 "$HERE/dns_stub.py" 10.99.0.1 zone.inner
mkdir -p www
echo "through the tunnel" > www/hello.txt
bg_inin python3 -m http.server 8080 --bind 198.18.0.1 --directory www

mkdir -p "/etc/netns/$PH"
printf 'nameserver 192.168.1.1\n' > "$RESOLV"
chmod 644 "$RESOLV"
sleep 0.5

cat > phone.conf << EOF
[Interface]
PrivateKey = $(cat phone.key)
Address = 10.99.0.2/32, fd99::2/128
DNS = 10.99.0.1, test.lan
MTU = 1380

[Peer]
PublicKey = $(cat srv.pub)
PresharedKey = $(cat psk)
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.test:51820
PersistentKeepalive = 25
EOF
cat > split.conf << EOF
[Interface]
PrivateKey = $(cat phone2.key)
Address = 10.97.0.2/32

[Peer]
PublicKey = $(cat srv2.pub)
AllowedIPs = 10.97.0.0/24
Endpoint = 203.0.113.2:51821
EOF
sed -e "s|^PrivateKey = .*|PrivateKey = $(cat phone2.key)|" phone.conf > full2.conf
printf '[Interface]\nPrivateKey = not-a-key\n' > bad.conf

# --- client: the app's own C++ against this daemon ------------------------------------------------
if [ $CLIENT_RUN = 1 ]; then
    CT="$DAEMON/build/client/client_test"
    [ -x "$CT" ] || { echo "build first: client/test/build.sh" >&2; exit 2; }
    # The app's sandbox as on the phone: data/daemon.sock, data/logs, data/Settings - the logs'
    # folder is the daemon's to make, for the app's uid (1000 here; the test itself runs as root).
    APP="$WORK/app"
    mkdir -p "$APP/data"
    sed -e 's/^Endpoint = .*/Endpoint = 203.0.113.1:51899/' -e 's/^AllowedIPs = .*/AllowedIPs = 10.95.0.0\/24/' \
        -e '/^DNS/d' -e "s|^PrivateKey = .*|PrivateKey = $(wg genkey)|" phone.conf > silent.conf
    # The phone's launcher: start it, and again whenever it leaves (daemon.restart, a crash) - unless
    # the test holds it off with the "pause" file.
    (
        while [ ! -e "$WORK/stop" ]; do
            if [ -e "$WORK/pause" ]; then
                sleep 0.2
                continue
            fi
            ip netns exec "$PH" "$BIN/bbtunneld" --state "$STATE" --socket "$APP/data/daemon.sock" \
                --log "$APP/data/logs/daemon.txt" --owner 1000:1000 --dns-file /etc/resolv.conf \
                --egress "$EGRESS" --debug >> "$WORK/daemon.stderr" 2>&1 &
            echo $! > "$WORK/daemon.pid"
            # Quietly: a kill -9 from the test is no news.
            wait $! 2> /dev/null || true
            sleep 1
        done
    ) &
    LOOP=$!
    for i in $(seq 1 50); do [ -S "$APP/data/daemon.sock" ] && break; sleep 0.1; done
    log_dir_ok() { [ -s "$APP/data/logs/daemon.txt" ] && [ "$(stat -c %u:%g "$APP/data/logs")" = 1000:1000 ]; }
    step "the daemon made its log's folder, the app's (--owner)" log_dir_ok
    echo "== the app's client (client/test/client_test) against this daemon"
    ip netns exec "$PH" env ASAN_OPTIONS=detect_leaks=0 "$CT" --app "$APP" --work "$WORK" || FAILED=1
    step "no ASan / UBSan reports from the daemon" bash -c "! grep -q -E 'ERROR: AddressSanitizer|runtime error:' '$WORK/daemon.stderr'"
    echo
    if [ $FAILED = 0 ]; then echo "e2e client: all passed"; else echo "e2e client: FAILURES (log in $KEEP)"; fi
    exit $FAILED
fi

daemon_start

# --- checks ------------------------------------------------------------------------------

resolv_ours() { grep -q '^nameserver 10.99.0.1$' "$RESOLV"; }
resolv_is() { [ "$(cat "$RESOLV")" = "$1" ]; }
# Output taken whole, then searched: `ip` writes route by route, and `| grep -q` quitting at the
# first match leaves its next write a SIGPIPE - a failure under pipefail, whatever the routes.
routes_in() {
    local r
    r="$(inph ip route show)"
    grep -q '^0.0.0.0/1 dev tun' <<< "$r" && grep -q '^128.0.0.0/1 dev tun' <<< "$r"
}
ping4() { inph ping -c 1 -W 2 "$1" > /dev/null 2>&1; }
ping6() { inph ping -6 -c 1 -W 2 "$1" > /dev/null 2>&1; }
fetch() { [ "$(inph curl -s -m 5 http://198.18.0.1:8080/hello.txt)" = "through the tunnel" ]; }
inside_dns() { inph getent hosts inside.test | grep -q '^10.99.0.1 '; }
import_error_line() {
    local out
    out="$(ctl profile.import name=Bad conf=@bad.conf || true)"
    echo "$out" | grep -q '^errno=4$' && echo "$out" | grep -q '^line=2$'
}
server_sees() { inin wg show wg-srv endpoints | grep -q "$1"; }
log_has() { grep -q "$1" "$WORK/daemon.txt"; }
# The status bar's VPN key, by the daemon's log (only the phone has the bar): what it was set to last ...
icon_is() { [ "$(grep 'status bar: VPN icon ' "$WORK/daemon.txt" | tail -1 | awk '{ print $NF }')" = "$1" ]; }
# ... and the first thing the daemon started last did to it.
icon_first_is() {
    [ "$(awk '/bbtunneld .* starting/ { first = "" } /status bar: VPN icon / && first == "" { first = $NF } END { print first }' \
        "$WORK/daemon.txt")" = "$1" ]
}
# Two lines in a row with one value, within one run of the daemon, are a write nobody needed.
icon_written_on_change_only() {
    ! awk '/bbtunneld .* starting/ { last = "" }
           /status bar: VPN icon / { if ($NF == last) found = 1; last = $NF }
           END { exit !found }' "$WORK/daemon.txt"
}
# The daemon's host routes (proto 126), both families.
pins() { inph ip -4 route show proto 126; inph ip -6 route show proto 126; }
pin_via() { local p; p="$(pins)"; grep -Eq "^$1 via $2 dev $3( |\$)" <<< "$p"; }
no_pin() { local p; p="$(pins)"; ! grep -Eq "^$1( |\$)" <<< "$p"; }
no_pins() { [ -z "$(pins)" ]; }
some_pins() { [ -n "$(pins)" ]; }
stats_ok() {
    local s
    s="$(ctl status)"
    echo "$s" | grep -q '^state=up$' && echo "$s" | grep -Eq '^rx_bytes=[1-9]' && echo "$s" | grep -q "^endpoint=$1$"
}
garbage_survived() {
    python3 - "$SOCK" << 'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.sendall(b"cmd=hello\nBAD LINE\n\n")
try: s.recv(100)
except OSError: pass
PY
    ctl hello > /dev/null
}

echo "== 1. profiles"
# Exit status 1 at once; a second daemon that RUNS would otherwise hang the test (timeout: 124).
second_refused() {
    local rc=0
    timeout 5 ip netns exec "$PH" "$BIN/bbtunneld" --state "$STATE" --socket "$WORK/d2.sock" \
        --dns-file /etc/resolv.conf > /dev/null 2>&1 || rc=$?
    [ "$rc" = 1 ]
}
step "a second daemon on the same state is refused" second_refused
step "... and the first still answers" ctl hello
step "the VPN icon: off from the start" icon_first_is off
step "a broken .conf is refused with its line number" import_error_line
P1="$(ctl -k profile profile.import name=Home conf=@phone.conf)"
step "import: profile $P1" test -n "$P1"
step "profile.get shows our public key" bash -c "'$BIN/btctl' -s '$SOCK' profile.get profile=$P1 | grep -q '^public_key=$(cat phone.pub)$'"
step "profile.list lists it" bash -c "'$BIN/btctl' -s '$SOCK' profile.list | grep -q '^name=Home$'"

echo "== 2. up, full tunnel"
ctl tunnel.up profile="$P1" > /dev/null
step "state up" ctl -t 15 wait "$P1" up
step "the VPN icon: connected" icon_is connected
step "... and no \"on\" on the way up: that is for a reconnect" fails log_has "VPN icon on"
step "IPv4 through the tunnel (nft drops it outside)" within 5 ping4 198.18.0.1
step "IPv6 through the tunnel" within 5 ping6 fd99::1
step "TCP through the tunnel" fetch
step "resolv.conf is the tunnel's" resolv_ours
step "DNS inside the tunnel answers" inside_dns
step "the /1 routes are in" routes_in
step "the server sees us from Wi-Fi" server_sees 192.168.1.2
if [ $HR = 1 ]; then
    step "hostroute: the server has a host route via Wi-Fi" pin_via 203.0.113.1 192.168.1.1 wifi0
    step "hostroute: the resolver in the Wi-Fi subnet needed none" fails log_has "host route: 192.168.1.1"
else
    step "bind: no host routes" no_pins
fi

echo "== 3. the network manager rewrites DNS"
printf 'nameserver 192.168.1.1\n# manager\n' > "$RESOLV"
step "ours are back" within 3 resolv_ours
printf 'nameserver 192.168.1.1\n# manager\n' > "$RESOLV"
step "... also when it writes back exactly what it had" within 3 resolv_ours
if [ $HR = 1 ]; then
    # The gateway stays the same: only the look after the change can bring it back.
    inph ip route del 203.0.113.1 proto 126
    step "hostroute: it wipes the host route: back" within 3 pin_via 203.0.113.1 192.168.1.1 wifi0
fi

echo "== 4. Wi-Fi -> LTE, our routes wiped"
ip -n "$PH" route del default
ip -n "$PH" link set wifi0 down
ip -n "$PH" route add default via 10.64.0.1 dev lte0
ip -n "$PH" route del 0.0.0.0/1 2> /dev/null || true
ip -n "$PH" route del 128.0.0.0/1 2> /dev/null || true
printf 'nameserver 10.64.0.1\n' > "$RESOLV"
step "traffic flows again" within 15 ping4 198.18.0.1
step "the routes are back" routes_in
step "the server sees us from LTE" server_sees 10.64.0.2
step "resolv.conf is ours again" resolv_ours
step "the VPN icon stayed through the network change: on" log_has "VPN icon on"
step "... and is connected again" within 5 icon_is connected
[ $HR = 1 ] && step "hostroute: the host route moved to LTE" pin_via 203.0.113.1 10.64.0.1 lte0

echo "== 5. the server's name moves; back to Wi-Fi"
printf 'vpn.test 203.0.113.2\n' > zone.outer
inin nft add rule inet bt input ip daddr 203.0.113.1 udp dport 51820 drop
ip -n "$PH" link set wifi0 up
ip -n "$PH" route del default
ip -n "$PH" route add default via 192.168.1.1 dev wifi0
step "traffic flows again" within 15 ping4 198.18.0.1
step "the daemon looked the name up again" log_has "vpn.test is 203.0.113.2"
step "status: up, bytes in, the new endpoint" stats_ok 203.0.113.2:51820
if [ $HR = 1 ]; then
    step "hostroute: the new address has one via Wi-Fi" within 5 pin_via 203.0.113.2 192.168.1.1 wifi0
    step "hostroute: the old one's is gone" within 5 no_pin 203.0.113.1
fi

echo "== 5b. the system's resolver is past the gateway"
# The full tunnel catches the resolver too: the name can only be looked up if our query to it
# stays outside (SO_BINDTODEVICE, or a host route while the lookup runs).
printf 'nameserver 198.51.100.53\n' > "$RESOLV"
step "ours are back over the new one" within 3 resolv_ours
ctl tunnel.down profile="$P1" > /dev/null
step "down: the system's resolver in resolv.conf" resolv_is "nameserver 198.51.100.53"
step "down: the VPN icon off" icon_is off
ctl tunnel.up profile="$P1" > /dev/null
step "up again" ctl -t 15 wait "$P1" up
step "the name was looked up there, the tunnel up all the while" within 10 log_has "vpn.test is 203.0.113.3"
step "status: the address it gave" within 10 stats_ok 203.0.113.3:51820
step "traffic flows" within 5 ping4 198.18.0.1
if [ $HR = 1 ]; then
    step "hostroute: the resolver had one while it was asked" log_has "host route: 198.51.100.53 via 192.168.1.1 (wifi0)"
    step "hostroute: ... and not after" within 5 no_pin 198.51.100.53
    step "hostroute: the server's new address has one" pin_via 203.0.113.3 192.168.1.1 wifi0
    step "hostroute: the cached one's is gone" within 5 no_pin 203.0.113.2
fi
printf 'nameserver 10.64.0.1\n' > "$RESOLV"
step "the provider's resolver again, ours over it" within 3 resolv_ours

echo "== 6. a split tunnel beside the full one"
P2="$(ctl -k profile profile.import name=Split conf=@split.conf)"
ctl tunnel.up profile="$P2" > /dev/null
step "second tunnel up" ctl -t 15 wait "$P2" up
step "its network through it" within 5 ping4 10.97.0.1
step "the full tunnel still carries the rest" ping4 198.18.0.1
[ $HR = 1 ] && step "hostroute: the split tunnel's server has one too (the full one catches it)" \
    pin_via 203.0.113.2 192.168.1.1 wifi0
P3="$(ctl -k profile profile.import name=Full2 conf=@full2.conf)"
step "a second full tunnel is refused" fails ctl tunnel.up profile="$P3"
step "... with the reason conflict" bash -c "'$BIN/btctl' -s '$SOCK' status | grep -q '^reason=conflict$'"
ctl tunnel.down profile="$P3" > /dev/null

echo "== 7. down"
ctl tunnel.down profile="$P1" > /dev/null
step "resolv.conf is the system's latest" resolv_is "nameserver 10.64.0.1"
step "nothing reaches 198.18.0.1 outside the tunnel" fails ping4 198.18.0.1
step "the split tunnel is still up" ping4 10.97.0.1
step "the VPN icon stays: any tunnel up is enough" icon_is connected
[ $HR = 1 ] && step "hostroute: nothing catches the split tunnel's server now: no host route" \
    within 3 no_pin 203.0.113.2
ctl tunnel.down profile="$P2" > /dev/null
step "the last one down: the VPN icon off" icon_is off
step "no tun devices left" bash -c "! ip netns exec $PH ip link show | grep -q ': tun'"
step "no host routes left" no_pins

echo "== 8. kill -9, the journal, always-on"
ctl settings.set always_on="$P1" > /dev/null
ctl tunnel.up profile="$P1" > /dev/null
ctl -t 15 wait "$P1" up > /dev/null
step "the journal is on disk while up" test -s "$STATE/applied"
kill -9 "$DPID"
wait "$DPID" 2> /dev/null || true
DPID=
step "the dead daemon's DNS is still there" resolv_ours
[ $HR = 1 ] && step "hostroute: ... and its host route" some_pins
daemon_start
step "the journal was replayed" log_has "the system's DNS is back"
[ $HR = 1 ] && step "hostroute: the journal took the host route away" log_has "journal: the host route to 203.0.113"
step "always-on brought the tunnel back" ctl -t 15 wait "$P1" up
step "traffic flows" within 5 ping4 198.18.0.1
step "the new daemon put the dead one's VPN icon out first" icon_first_is off
step "... and lit it for the tunnel it brought back" icon_is connected

echo "== 9. daemon.restart, SIGTERM"
ctl daemon.restart > /dev/null
step "the daemon left on its own" timeout 5 bash -c "while kill -0 $DPID 2> /dev/null; do sleep 0.1; done"
wait "$DPID" 2> /dev/null && RC=0 || RC=$?
step "... with status 0" test "$RC" = 0
DPID=
daemon_start
step "always-on again after the restart" ctl -t 15 wait "$P1" up
daemon_stop
step "SIGTERM: the system's DNS back" resolv_is "nameserver 10.64.0.1"
step "SIGTERM: no journal left" test ! -e "$STATE/applied"
step "SIGTERM: no host routes left" no_pins
step "SIGTERM: the VPN icon off" icon_is off

echo "== 10. the handshake timestamp ceiling"
step "a ceiling is on disk" grep -Eq '^ts_ceiling=[1-9]' "$STATE/$P1.meta"
daemon_start --clock-offset -3600
step "an hour behind, the server still takes us" ctl -t 15 wait "$P1" up
daemon_stop
# The control: without the ceiling, the kernel refuses a timestamp older than the last it saw.
# The control run writes its own (low) ceiling, so the real one is put back afterwards - in real
# life a ceiling only ever rises; only this test zeroes it. The daemon's floor goes the same way,
# or it would stand in for the profile's.
SAVED_CEILING="$(grep '^ts_ceiling=' "$STATE/$P1.meta")"
SAVED_FLOOR="$(grep '^ts_floor=' "$STATE/settings")"
sed -i 's/^ts_ceiling=.*/ts_ceiling=0/' "$STATE/$P1.meta"
sed -i 's/^ts_floor=.*/ts_floor=0/' "$STATE/settings"
daemon_start --clock-offset -7200
step "control: without it, two hours behind, no handshake" fails ctl -t 12 wait "$P1" up
daemon_stop
sed -i "s/^ts_ceiling=.*/$SAVED_CEILING/" "$STATE/$P1.meta"
sed -i "s/^ts_floor=.*/$SAVED_FLOOR/" "$STATE/settings"
daemon_start
step "the ceiling back: up again on the right clock" ctl -t 15 wait "$P1" up

echo "== 11. garbage on the control socket"
step "the daemon drops the client and lives on" garbage_survived

echo "== 12. the rest of the protocol"
stats_events() { [ "$("$BIN/btctl" -s "$SOCK" -t 2.5 watch stats | grep -c '^event=stats$')" -ge 2 ]; }
step "watch stats: a statistics event every second" stats_events
step "log.tail gives the log" bash -c "'$BIN/btctl' -s '$SOCK' -k text log.tail lines=20 | grep -q 'tunnel $P1'"
step "settings.get: always-on is the profile" bash -c "'$BIN/btctl' -s '$SOCK' settings.get | grep -q '^always_on=$P1$'"
always_on_says() { "$BIN/btctl" -s "$SOCK" settings.get | grep -q "^always_on=$1\$"; }
listed_always_on() { "$BIN/btctl" -s "$SOCK" profile.list | grep -A6 "^profile=$1\$" | grep -q "^always_on=$2\$"; }
ctl settings.set always_on="$P2" > /dev/null
step "always-on: another WireGuard profile takes the first one's place" always_on_says "$P2"
step "... the list says so of the new one" listed_always_on "$P2" 1
step "... and of the old one" listed_always_on "$P1" 0
ctl settings.set always_off="$P1" > /dev/null
step "always_off of a profile that is not always on changes nothing" always_on_says "$P2"
ctl settings.set always_off="$P2" > /dev/null
step "always_off: none now" always_on_says ""
ctl settings.set always_on="$P1" > /dev/null
ctl settings.set always_on= > /dev/null
step "always_on= with nothing: none" always_on_says ""
ctl settings.set always_on="$P1" > /dev/null
# log.debug: this daemon runs with --debug - on with no end; off at once; on for 2 s, then off by
# itself; wrong arguments refused; on again (for an hour) for the rest
step "log.debug: on by --debug, no end" [ "$(ctl -k debug log.debug)$(ctl -k left log.debug)" = "10" ]
step "log.debug on=0: off" [ "$(ctl -k debug log.debug on=0)" = 0 ]
mark=$(wc -l < "$WORK/daemon.txt")
ctl status > /dev/null
step "... no debug lines then" bash -c "! tail -n +$((mark + 1)) '$WORK/daemon.txt' | grep -q ' D '"
debug_for_2s() {
    [ "$(ctl -k debug log.debug on=1 seconds=2)" = 1 ] || return 1
    case "$(ctl -k left log.debug)" in 1|2) return 0 ;; *) return 1 ;; esac
}
step "log.debug on=1 seconds=2: on, 1-2 s left" debug_for_2s
ctl status > /dev/null
step "... debug lines again" grep -q ' D ctl: status$' "$WORK/daemon.txt"
step "... off by itself once the time is over" within 5 grep -q ' I debug lines off: their time is over (log.debug)$' "$WORK/daemon.txt"
step "... and says so" [ "$(ctl -k debug log.debug)" = 0 ]
step "log.debug: on=2 refused" bash -c "'$BIN/btctl' -s '$SOCK' log.debug on=2 | grep -q '^errno=1$'"
step "log.debug: seconds=0 refused" bash -c "'$BIN/btctl' -s '$SOCK' log.debug on=1 seconds=0 | grep -q '^errno=1$'"
step "log.debug: seconds=3601 refused" bash -c "'$BIN/btctl' -s '$SOCK' log.debug on=1 seconds=3601 | grep -q '^errno=1$'"
step "log.debug on=1 seconds=3600: on again for the rest" [ "$(ctl -k debug log.debug on=1 seconds=3600)" = 1 ]
step "profile.update: a new name" ctl profile.update profile="$P2" name=Renamed
step "... shows in the list" bash -c "'$BIN/btctl' -s '$SOCK' profile.list | grep -q '^name=Renamed$'"
step "profile.update: a broken .conf is refused" fails ctl profile.update profile="$P2" conf=@bad.conf
step "unknown command" bash -c "'$BIN/btctl' -s '$SOCK' no.such | grep -q '^errno=2$'"
step "unknown profile" bash -c "'$BIN/btctl' -s '$SOCK' tunnel.up profile=00000000 | grep -q '^errno=3$'"
sed -e 's/^Endpoint = .*/Endpoint = nosuch.test:51820/' -e 's/^AllowedIPs = .*/AllowedIPs = 10.95.0.0\/24/' \
    -e '/^DNS/d' -e "s|^PrivateKey = .*|PrivateKey = $(wg genkey)|" phone.conf > noname.conf
PN="$(ctl -k profile profile.import name=NoName conf=@noname.conf)"
ctl tunnel.up profile="$PN" > /dev/null
step "an endpoint name that does not exist: reason resolve" within 10 bash -c \
    "'$BIN/btctl' -s '$SOCK' status | grep -A1 '^profile=$PN$' | grep -q '^state=connecting$' && '$BIN/btctl' -s '$SOCK' status | grep -q '^reason=resolve$'"
ctl tunnel.down profile="$PN" > /dev/null
sed -e 's/^Endpoint = .*/Endpoint = 203.0.113.1:51899/' noname.conf > silent.conf
PS="$(ctl -k profile profile.import name=Silent conf=@silent.conf)"
ctl tunnel.up profile="$PS" > /dev/null
step "a server that never answers: reason handshake (after 15 s)" within 20 bash -c \
    "'$BIN/btctl' -s '$SOCK' status | grep -q '^reason=handshake$'"
ctl tunnel.down profile="$PS" > /dev/null
step "profile.delete of a tunnel that is up takes it down" ctl profile.delete profile="$P1"
step "... and clears always-on" bash -c "'$BIN/btctl' -s '$SOCK' settings.get | grep -q '^always_on=$'"
step "... and gives the system its DNS back" resolv_is "nameserver 10.64.0.1"
# Its key again, in a new profile: after the restarts above its timestamps ran ahead of the clock,
# and the server remembers the newest - the new profile starts above the daemon's floor.
PK="$(ctl -k profile profile.import name=Again conf=@phone.conf)"
ctl tunnel.up profile="$PK" > /dev/null
step "the same key in a new profile: up at once (the daemon's timestamp floor)" ctl -t 15 wait "$PK" up
ctl profile.delete profile="$PK" > /dev/null

if [ $AWG_RUN = 1 ]; then
    echo "== 13. AmneziaWG against amneziawg-go"
    if [ -x /usr/local/go/bin/go ]; then PATH="/usr/local/go/bin:$PATH"; fi
    (cd "$REFS/amneziawg-go" && go build -buildvcs=false -o "$WORK/amneziawg-go" .)
    cp -r "$REFS/amneziawg-tools/src" "$WORK/awg-src"
    make -s -C "$WORK/awg-src" wg > /dev/null
    AWG="$WORK/awg-src/wg"
    "$AWG" genkey > asrv.key; "$AWG" pubkey < asrv.key > asrv.pub
    "$AWG" genkey > aph.key; "$AWG" pubkey < aph.key > aph.pub
    "$AWG" genkey > hp.key
    shared="$(printf 'S1 = 24\nS2 = 32\nS3 = 16\nS4 = 20\nH1 = 100000-100999\nH2 = 200000-200999\nH3 = 300000-300999\nH4 = 400000-499999\nHeaderProtectionKey = %s\nRandomTrailers = on\n' "$(cat hp.key)")"
    printf '[Interface]\nPrivateKey = %s\nListenPort = 51822\n%s\nJc = 3\nJmin = 30\nJmax = 60\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.96.0.2/32\n' \
        "$(cat asrv.key)" "$shared" "$(cat aph.pub)" > asrv.conf
    printf '[Interface]\nPrivateKey = %s\nAddress = 10.96.0.2/32\n%s\nJc = 5\nJmin = 10\nJmax = 50\nI1 = <b 0xc70000000108ce1bfe8e8c5a0f2a><r 32><t>\nContentPaddingAddition = 8-48\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.96.0.0/24\nEndpoint = vpn.test:51822\nPersistentKeepalive = 25\n' \
        "$(cat aph.key)" "$shared" "$(cat asrv.pub)" > aphone.conf
    ip netns exec "$IN" env LOG_LEVEL=error "$WORK/amneziawg-go" -f awg-srv > amneziawg-go.log 2>&1 & PIDS+=($!)
    for i in $(seq 1 50); do [ -S /var/run/amneziawg/awg-srv.sock ] && break; sleep 0.1; done
    inin "$AWG" setconf awg-srv asrv.conf
    ip -n "$IN" addr add 10.96.0.1/24 dev awg-srv
    ip -n "$IN" link set awg-srv up
    PA="$(ctl -k profile profile.import name=Amnezia conf=@aphone.conf)"
    step "imported as amneziawg" bash -c "'$BIN/btctl' -s '$SOCK' profile.get profile=$PA | grep -q '^type=amneziawg$'"
    ctl tunnel.up profile="$PA" > /dev/null
    step "AmneziaWG tunnel up" ctl -t 15 wait "$PA" up
    step "its network through it" within 5 ping4 10.96.0.1
    ctl tunnel.up profile="$P2" > /dev/null
    step "a plain WireGuard tunnel beside it" ctl -t 15 wait "$P2" up
    step "... carries its own network" within 5 ping4 10.97.0.1
    step "... and the AmneziaWG one still carries its" ping4 10.96.0.1
    ctl tunnel.down profile="$P2" > /dev/null
    ctl tunnel.down profile="$PA" > /dev/null
fi

daemon_stop
step "no host routes left at the end" no_pins
step "the VPN icon was written only when it changed" icon_written_on_change_only
step "no ASan / UBSan reports from the daemon" bash -c "! grep -q -E 'ERROR: AddressSanitizer|runtime error:' '$WORK/daemon.stderr'"

echo
if [ $FAILED = 0 ]; then echo "e2e: all passed"; else echo "e2e: FAILURES (log in $KEEP)"; fi
exit $FAILED
