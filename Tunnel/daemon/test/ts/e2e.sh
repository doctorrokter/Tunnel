#!/usr/bin/env bash
#
# bbtunneld's Tailscale side end to end, on the stand of stand.sh: Headscale with its embedded DERP,
# the official tailscaled as the NAS, and our daemon in a phone namespace logging in with an auth key.
# Runs in WSL as root; build first (daemon/build.sh host, then stand_build.sh):
#
#   MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -u root -- bash /mnt/e/dev/momentics-projects/Tunnel/daemon/test/ts/e2e.sh [tls] [client]
#
# Without arguments - stage A, plain HTTP; `tls` - stage B, TLS as on the real network: control over
# https with the stand's test CA (the daemon gets it with --ca-file), the embedded DERP checked against
# that CA, and derper's region checked by the pin of its self-signed certificate. `client`: instead of
# the checks below, the app's and the service's own C++ drive the daemon (client_test --tailscale;
# build it first: client/test/build.sh).
#
#   ts-inet    Headscale on 10.20.0.1 (control and /derp; :8080 on A, :443 on B), derper on
#              10.20.0.2:443 (B); no forwarding between the others
#   ts-nas     tailscaled, DERP-only (TS_DEBUG_ALWAYS_USE_DERP)
#   ts-pc      another tailscaled, joining halfway: a netmap delta
#   ts-phone   bbtunneld with a real tun; reaches ts-inet only
#
# Scenarios: import; up (register, netmap, home relay); the NAS by its 100.x address; TCP both ways;
# what profile.get, status and tailscale.nodes say; (B) the NAS at home in the region that is not
# ours before we speak first, so we log in to both - by the CA and by the pin; a node joining and
# reaching us first (an inbound handshake through our home relay); the phone changing networks;
# (B) a start without the test CA: control refused, no fallback to plain; a restart of the daemon
# (no second registration); the node expired by an admin; a new auth key; the node removed by an
# admin (reason removed) and a new login as a new node, its new address alone on the tun; delete; a login
# by a link (no key: the link in the status, the wait at it held, a new link after a cancel, the same one
# after a reconnect, Headscale's auth register as the login, logging in again by a link). E2E_FAILFAST=1:
# stop at the first failure (the mutation check).
#
# MagicDNS (TAILSCALE.md section 8a): on in the tailnet of stage A, off in that of stage B (E2E_MAGIC=0
# or 1 says otherwise). On: names of the tailnet, short and full, IPv6, our own, an extra record, a
# name in our domain nobody has, a name outside forwarded to the network's resolver (a stub on
# 10.20.0.1), after the network change, inside a full tunnel (the kernel's WireGuard in ts-inet,
# its resolver 10.30.0.53 reachable only through it), with the daemon dead (the fallback after ours
# in resolv.conf), on expiry and on delete. Off: resolv.conf stays the system's.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TUNNEL="$(cd "$HERE/../../.." && pwd)"
BIN="${BT_BIN:-$TUNNEL/daemon/build/host}"
TLS=0
CLIENT=0
for a in "$@"; do
    case "$a" in
        tls) TLS=1 ;;
        client) CLIENT=1 ;;
        *) echo "usage: e2e.sh [tls] [client]" >&2; exit 2 ;;
    esac
done
STAND_TLS=$TLS
if [ $TLS = 1 ]; then MAGIC="${E2E_MAGIC:-0}"; else MAGIC="${E2E_MAGIC:-1}"; fi
STAND_MAGIC=$MAGIC
# Split DNS with MagicDNS: corp.split's names from their own server on 10.20.0.5 (section 2b)
if [ $MAGIC = 1 ]; then STAND_SPLIT="corp.split=10.20.0.5"; fi
KEEP="$TUNNEL/daemon/build/ts-e2e$([ $TLS = 1 ] && echo -tls || true)$([ $CLIENT = 1 ] && echo -client || true)"
STAND_SOURCED=1
# shellcheck source=stand.sh
. "$HERE/stand.sh"
PH=ts-phone
RESOLV="/etc/netns/$PH/resolv.conf"
SOCK="$STAND_WORK/d.sock"
STATE="$STAND_WORK/state"
LOG="$STAND_WORK/daemon.txt"
FAILED=0
DPID=
NO_CA=0
LOG_MARK=0

export ASAN_OPTIONS=detect_leaks=0

ctl() { "$BIN/btctl" -s "$SOCK" "$@"; }
inph() { ip netns exec "$PH" "$@"; }

daemon_start() {
    local ca=()
    if [ $TLS = 1 ] && [ $NO_CA = 0 ]; then ca=(--ca-file "$STAND_CA"); fi
    ip netns exec "$PH" "$BIN/bbtunneld" --state "$STATE" --socket "$SOCK" --log "$LOG" \
        --dns-file /etc/resolv.conf --egress bind --debug "${ca[@]}" >> "$STAND_WORK/daemon.stderr" 2>&1 &
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
    mkdir -p "$KEEP"
    cp "$(dirname "$LOG")"/daemon*.txt "$STAND_WORK/daemon.stderr" "$STAND_WORK/headscale.log" "$KEEP/" 2> /dev/null
    cp "$STAND_WORK/derper/derper.log" "$KEEP/" 2> /dev/null
    for n in nas pc; do cp "$STAND_WORK/$n/tailscaled.log" "$KEEP/$n.tailscaled.log" 2> /dev/null; done
    ip netns del "$PH" 2> /dev/null
    rm -rf "/etc/netns/$PH"
    stand_down
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
        # The mutation check (daemon/build/ts-mut-e2e) wants the first failure only.
        if [ "${E2E_FAILFAST:-0}" = 1 ]; then exit 1; fi
    fi
}

fails() { ! "$@"; }

# By the clock, not by tries: a try may take seconds itself (a ping waits 2 s for its answer), and
# counted tries made "within 20" 220 s on a failure.
within() {
    local secs="$1" end
    shift
    end=$((SECONDS + secs))
    while :; do
        if "$@" > /dev/null 2>&1; then return 0; fi
        [ $SECONDS -ge $end ] && return 1
        sleep 0.2
    done
}

log_has() { grep -q "$1" "$LOG"; }
# What the daemon logged since log_mark (one run of e2e stays far below the 256 KB rotation).
log_mark() { LOG_MARK="$(wc -l < "$LOG")"; }
log_new() { tail -n "+$((LOG_MARK + 1))" "$LOG" | grep -q "$1"; }
ping_from_phone() { inph ping -c 1 -W 2 "$1" > /dev/null 2>&1; }
ping_from() { ip netns exec "ts-$1" ping -c 1 -W 2 "$2" > /dev/null 2>&1; }
ts_ip() { ts "$1" ip -4; }
field() { ctl "$@" | sed -n "s/^$FIELD=//p" | head -1; }
hs_nodes() { hs nodes list -o json; }
hs_has() { hs_nodes | grep -q "\"given_name\": *\"$1\"\|\"name\": *\"$1\""; }
# Until `port` listens in namespace `ns` (3 s at most): a client started after a fixed pause lost
# the race to a listener slow to start once (a loaded WSL), and the connect met a reset.
listening() {
    local ns="$1" port="$2" i out
    for i in $(seq 1 30); do
        out="$(ip netns exec "$ns" ss -ltn 2> /dev/null)" || true
        grep -q ":$port " <<< "$out" && return 0
        sleep 0.1
    done
    return 1
}
# One TCP exchange each way: "ping" one way, "pong" back. Each side stays 3 s after its own end of the
# data (-q 3): with -q 1 the listener had already gone when the other's "ping" came through DERP a
# little late - one failed run in three on stage B, the tunnel fine (2026-10-23). The steps retry
# within a window, as the pings do: a moment while the NAS moves its relay is not a broken tunnel.
tcp_to_nas() {
    local got
    : > "$STAND_WORK/nas.got"
    ip netns exec ts-nas bash -c "echo pong | timeout 8 nc -l -p 7777 -q 3 > '$STAND_WORK/nas.got'" &
    local lp=$!
    listening ts-nas 7777 || true
    got="$(echo ping | timeout 8 ip netns exec "$PH" nc -q 3 "$NAS_IP" 7777)" || true
    wait "$lp" 2> /dev/null || true
    [ "$got" = "pong" ] && [ "$(cat "$STAND_WORK/nas.got")" = "ping" ]
}
tcp_from_nas() {
    local got
    : > "$STAND_WORK/phone.got"
    ip netns exec "$PH" bash -c "echo pong | timeout 8 nc -l -p 7778 -q 3 > '$STAND_WORK/phone.got'" &
    local lp=$!
    listening "$PH" 7778 || true
    got="$(echo ping | timeout 8 ip netns exec ts-nas nc -q 3 "$PHONE_IP" 7778)" || true
    wait "$lp" 2> /dev/null || true
    [ "$got" = "pong" ] && [ "$(cat "$STAND_WORK/phone.got")" = "ping" ]
}
no_asan() { ! grep -q "ERROR: AddressSanitizer\|runtime error:" "$STAND_WORK/daemon.stderr"; }
# Taken whole, then searched (a grep -q quitting early would SIGPIPE btctl under pipefail).
nodes_nas() {
    local out
    out="$(ctl tailscale.nodes profile="$P")"
    grep -q '^name=nas$' <<< "$out" && grep -q '^online=1$' <<< "$out" && grep -q '^active=1$' <<< "$out" &&
        grep -q "^address=$NAS_IP$" <<< "$out"
}
status_reason() { ctl status | sed -n 's/^reason=//p' | head -1; }
# The phone's resolv.conf: its nameservers in order, space-separated; its search line.
resolv_servers_are() { [ "$(awk '$1 == "nameserver" { print $2 }' "$RESOLV" | paste -sd' ')" = "$1" ]; }
resolv_search_is() { [ "$(awk '$1 == "search" { $1 = ""; sub(/^ /, ""); print }' "$RESOLV")" = "$1" ]; }
# A name as the phone's own resolver (glibc, the resolv.conf above) finds it: its first address.
name_v4() { inph timeout 15 getent ahostsv4 "$1" | awk '{ print $1; exit }'; }
name_is() { [ "$(name_v4 "$1")" = "$2" ]; }
name_v6_is() { [ "$(inph timeout 15 getent ahostsv6 "$1" | awk '{ print $1; exit }')" = "$2" ]; }
# Not found (getent's 2) - and at once: an answer, not a timeout.
name_nx_fast() {
    local rc=0
    inph timeout 3 getent ahostsv4 "$1" > /dev/null || rc=$?
    [ $rc = 2 ]
}
relay_is() { [ "$(ts_relay "$1")" = "$2" ]; }
# Where our netmap has the NAS at home (tailscale.nodes relay=).
nas_relay_is() {
    local out
    out="$(ctl tailscale.nodes profile="$P")"
    python3 -c '
import sys
for block in sys.stdin.read().split("\n\n"):
    lines = block.strip().splitlines()
    if "name=nas" in lines and "relay=" + sys.argv[1] in lines:
        sys.exit(0)
sys.exit(1)' "$1" <<< "$out"
}

echo "== the stand (stage $([ $TLS = 1 ] && echo "B: TLS" || echo "A: plain HTTP")) in $STAND_WORK"
stand_up
KEY="$(stand_key)"
stand_node nas 1 "$KEY" > /dev/null
NAS_IP="$(ts_ip nas)"
echo "   NAS: $NAS_IP"

# The phone: its own /24 to the internet namespace, a resolv.conf the Linux backend may own.
ip netns del "$PH" 2> /dev/null || true
ip netns add "$PH"
ip -n "$PH" link set lo up
ip link add phone0 netns "$PH" type veth peer name phone0-i netns "$STAND_INET"
ip -n "$PH" addr add 10.20.9.2/24 dev phone0
ip -n "$STAND_INET" addr add 10.20.9.1/24 dev phone0-i
ip -n "$PH" link set phone0 up
ip -n "$STAND_INET" link set phone0-i up
ip -n "$PH" route add default via 10.20.9.1
mkdir -p "/etc/netns/$PH"
echo "nameserver 10.20.0.1" > "$RESOLV"

# MagicDNS: the network's resolver on 10.20.0.1, and the full tunnel's on 10.30.0.53 (section 4b) -
# the same name, each its own answer, to tell who answered. Straight through `ip netns exec`: $! is
# the stub, and stand_down stops it.
if [ $MAGIC = 1 ]; then
    # the network's resolver knows corp.split's name too, wrongly: only the route's server says .88
    printf 'outside.test 10.20.0.77\nwiki.corp.split 10.20.0.99\n' > "$STAND_WORK/zone.net"
    printf 'outside.test 10.30.0.77\n' > "$STAND_WORK/zone.warp"
    printf 'wiki.corp.split 10.20.0.88\n' > "$STAND_WORK/zone.split"
    ip -n "$STAND_INET" addr add 10.20.0.5/32 dev lo
    ip netns exec "$STAND_INET" python3 "$HERE/../e2e/dns_stub.py" 10.20.0.5 "$STAND_WORK/zone.split" > /dev/null 2>&1 &
    STAND_PIDS+=($!)
    ip -n "$STAND_INET" addr add 10.30.0.53/32 dev lo
    ip netns exec "$STAND_INET" python3 "$HERE/../e2e/dns_stub.py" 10.20.0.1 "$STAND_WORK/zone.net" > /dev/null 2>&1 &
    STAND_PIDS+=($!)
    ip netns exec "$STAND_INET" python3 "$HERE/../e2e/dns_stub.py" 10.30.0.53 "$STAND_WORK/zone.warp" > /dev/null 2>&1 &
    STAND_PIDS+=($!)
fi

# --- client: the app's own C++ against this daemon (client/test/client_test --tailscale) ---------
if [ $CLIENT = 1 ]; then
    CT="$TUNNEL/daemon/build/client/client_test"
    [ -x "$CT" ] || { echo "build first: client/test/build.sh" >&2; exit 2; }
    # The app's sandbox as on the phone: data/daemon.sock, data/logs (the daemon makes it), data/Settings.
    APP="$STAND_WORK/app"
    mkdir -p "$APP/data"
    SOCK="$APP/data/daemon.sock"
    LOG="$APP/data/logs/daemon.txt"
    daemon_start
    # What the test needs from the stand, and what the phone cannot do itself.
    W="$STAND_WORK/client"
    mkdir -p "$W"
    echo "$KEY" > "$W/authkey"
    stand_key > "$W/authkey2"
    echo "$STAND_CONTROL" > "$W/control"
    echo "$NAS_IP" > "$W/nas.ip"
    cat > "$W/expire" << EOF
#!/bin/bash
# An admin expires the phone's node.
HS="ip netns exec $STAND_INET $STAND_BIN/headscale --config $STAND_WORK/headscale.yaml"
id="\$(\$HS nodes list -o json | python3 -c 'import json,sys; print([n["id"] for n in json.load(sys.stdin) if n.get("given_name")=="phone" or n.get("name")=="phone"][0])')"
\$HS nodes expire --identifier "\$id" > /dev/null
EOF
    cat > "$W/nas-refresh" << EOF
#!/bin/bash
# The stand's quirk (section 6 below): the NAS takes a new map after our new login.
TS="ip netns exec ts-nas $STAND_BIN/tailscale --socket=$STAND_WORK/nas/sock"
\$TS down > /dev/null 2>&1
\$TS up --login-server $STAND_CONTROL --hostname nas --accept-dns=false --timeout 30s > /dev/null 2>&1
EOF
    cat > "$W/register" << EOF
#!/bin/bash
# Somebody logs in at the phone's login link (section 11b): Headscale registers its auth id.
ip netns exec $STAND_INET $STAND_BIN/headscale --config $STAND_WORK/headscale.yaml auth register --user stand --auth-id "\$1" > /dev/null
EOF
    chmod +x "$W/expire" "$W/nas-refresh" "$W/register"
    echo "== the app's client (client/test/client_test --tailscale) against this daemon"
    ip netns exec "$PH" env ASAN_OPTIONS=detect_leaks=0 "$CT" --tailscale --app "$APP" --work "$W" || FAILED=1
    step "no ASan / UBSan report from the daemon" no_asan
    echo
    if [ $FAILED = 0 ]; then echo "Tailscale client e2e: all passed"; else echo "Tailscale client e2e: FAILURES (logs in $KEEP)"; fi
    exit $FAILED
fi

daemon_start

echo "== 1. log in"
P="$(ctl -k profile profile.import type=tailscale name=Tailnet authkey="$KEY" control="$STAND_CONTROL" hostname=phone)"
step "import: profile $P" test -n "$P"
step "a bad auth key is refused at import" fails ctl profile.import type=tailscale name=Bad authkey="two words"
step "profile.get: not logged in yet" bash -c "'$BIN/btctl' -s '$SOCK' profile.get profile=$P | grep -q '^login=pending$'"
ctl tunnel.up profile="$P" > /dev/null
step "state up (registered, netmap, home relay)" ctl -t 30 wait "$P" up
step "Headscale has the phone" within 5 hs_has phone
step "the log says registered" log_has "registered"
if [ $TLS = 1 ]; then
    step "control over TLS 1.3 (the certificate checked against the test CA)" log_has "control open (10.20.0.1:443, TLSv1.3)"
    step "the home relay over TLS too" log_has "home relay [0-9]* up (10.20.0.[12]:443)"
fi
FIELD=ts_address
PHONE_IP="$(field status)"
echo "   phone: $PHONE_IP"
step "status: our 100.x address" test -n "$PHONE_IP"
step "profile.get: logged in, the tailnet's addresses cached" bash -c \
    "'$BIN/btctl' -s '$SOCK' profile.get profile=$P | grep -q '^login=ok$' && '$BIN/btctl' -s '$SOCK' profile.get profile=$P | grep -q '^address=$PHONE_IP/32$'"
if [ $MAGIC = 0 ]; then
    step "no MagicDNS in this tailnet: resolv.conf stays the system's" resolv_servers_are "10.20.0.1"
    step "... and the log says nothing of it" fails log_has "MagicDNS on"
fi

if [ $TLS = 1 ]; then
    # The phone answers a node over the region the node's packets came in by (magicsock's reverse
    # route), so it goes to a node's own region only when it speaks first. Here it does, before the
    # NAS has said anything: the NAS moves to the region that is not our home, and the first ping
    # takes the phone there as well - so both checks of a certificate run, the chain to the test CA
    # (999) and the pin (900).
    echo "== 1b. the NAS at home in the other region"
    OUR="$(grep -o 'home relay: [0-9]*' "$LOG" | tail -1 | grep -o '[0-9]*$')"
    OTHER=900
    OTHER_CODE=derper
    if [ "$OUR" = 900 ]; then
        OTHER=999
        OTHER_CODE=stand
    fi
    echo "   our home: $OUR"
    ts_home nas $OTHER
    step "the NAS calls region $OTHER home" within 20 relay_is nas $OTHER_CODE
    step "our netmap has it there (tailscale.nodes relay=$OTHER)" within 20 nas_relay_is $OTHER
fi

echo "== 2. traffic through the relay"
step "the phone pings the NAS" within 15 ping_from_phone "$NAS_IP"
step "the NAS pings the phone" within 15 ping_from nas "$PHONE_IP"
step "TCP phone -> NAS" within 30 tcp_to_nas
step "TCP NAS -> phone" within 30 tcp_from_nas
step "tailscale.nodes: the NAS, online and in use" nodes_nas
if [ $TLS = 1 ]; then
    step "logged in to region 999 by the test CA" log_has "relay 999: logged in"
    step "logged in to region 900 by the pin" log_has "relay 900: logged in"
fi

if [ $MAGIC = 1 ]; then
    echo "== 2b. MagicDNS"
    NAS_IP6="$(ts nas ip -6)"
    step "the log says MagicDNS on, domain $STAND_DOMAIN" within 10 log_has "MagicDNS on, domain $STAND_DOMAIN"
    step "resolv.conf: our resolver first, the network's after it" within 5 resolv_servers_are "100.100.100.100 10.20.0.1"
    step "... and our domains to search" resolv_search_is "$STAND_DOMAIN corp.example"
    step "status: the tunnel holds the DNS" bash -c "'$BIN/btctl' -s '$SOCK' status | grep -q '^dns=1$'"
    step "the NAS by its full name" within 10 name_is "nas.$STAND_DOMAIN" "$NAS_IP"
    step "... by its short name (the search list)" name_is nas "$NAS_IP"
    step "... its IPv6 address ($NAS_IP6)" name_v6_is "nas.$STAND_DOMAIN" "$NAS_IP6"
    step "... in capitals, with the root's dot" name_is "NAS.${STAND_DOMAIN^^}." "$NAS_IP"
    step "our own name" name_is "phone.$STAND_DOMAIN" "$PHONE_IP"
    step "an extra record of the tailnet" name_is "printer.$STAND_DOMAIN" 100.64.0.99
    step "a name in our domain nobody has: not found, at once" name_nx_fast "nobody.$STAND_DOMAIN"
    step "a name outside: forwarded to the network's resolver" name_is outside.test 10.20.0.77
    step "a name nobody has anywhere: not found, at once" name_nx_fast nosuch.test
    step "ping the NAS by name" ping_from_phone nas
    # Split DNS (DNSConfig.Routes): corp.split goes to its own server, not to the network's resolver
    # (which knows the name too, wrongly - .99)
    step "split DNS: a name under the route, from the route's server" name_is wiki.corp.split 10.20.0.88
    step "... in capitals, with the root's dot" name_is WIKI.CORP.SPLIT. 10.20.0.88
    step "... one nobody has there: not found, at once" name_nx_fast nobody.corp.split
    step "... a name beside it, not under it: the network's resolver" name_nx_fast xcorp.split
fi

echo "== 3. a node joins, and speaks first"
stand_node pc 3 "$KEY" > /dev/null
PC_IP="$(ts_ip pc)"
# A node we have never talked to: its handshake comes in through our home relay from a key that is
# no peer of ours yet - the netmap makes it one (and the node found our home in its netmap: control
# had it from our short map).
step "the new node $PC_IP reaches us first (an inbound handshake)" within 20 ping_from pc "$PHONE_IP"
step "the phone pings it back" within 20 ping_from_phone "$PC_IP"
if [ $MAGIC = 1 ]; then
    step "MagicDNS: the new node by name (the netmap's delta)" within 10 name_is "pc.$STAND_DOMAIN" "$PC_IP"
fi

echo "== 4. the phone changes networks"
# A second way out (as Wi-Fi -> LTE): the default route moves to it and the first one goes down. The
# daemon sees the egress interface change, drops control and the relays, and comes back on the new one.
ip link add phone1 netns "$PH" type veth peer name phone1-i netns "$STAND_INET"
ip -n "$PH" addr add 10.20.10.2/24 dev phone1
ip -n "$STAND_INET" addr add 10.20.10.1/24 dev phone1-i
ip -n "$PH" link set phone1 up
ip -n "$STAND_INET" link set phone1-i up
log_mark
ip -n "$PH" route replace default via 10.20.10.1 dev phone1
ip -n "$PH" link set phone0 down
step "control dropped for the new network" within 10 log_new "control lost: the network changed"
step "control open again" within 30 log_new "control open"
step "the phone pings the NAS from the new network" within 30 ping_from_phone "$NAS_IP"
step "the NAS pings the phone" within 20 ping_from nas "$PHONE_IP"
step "state up" ctl -t 30 wait "$P" up
if [ $MAGIC = 1 ]; then
    step "MagicDNS on the new network: the NAS by name" within 10 name_is nas "$NAS_IP"
    step "... a name outside" name_is outside.test 10.20.0.77
fi

if [ $MAGIC = 1 ]; then
    echo "== 4b. MagicDNS inside a full tunnel (as WARP)"
    # A WireGuard server in the internet namespace - the kernel's - and its resolver 10.30.0.53,
    # which nft keeps from the phone's own links: what it answers came through the tunnel. Tailscale's
    # transport moves inside the full tunnel; MagicDNS stays first, the full tunnel's resolver after it.
    wg genkey > "$STAND_WORK/warp-srv.key"
    wg pubkey < "$STAND_WORK/warp-srv.key" > "$STAND_WORK/warp-srv.pub"
    wg genkey > "$STAND_WORK/warp-phone.key"
    wg pubkey < "$STAND_WORK/warp-phone.key" > "$STAND_WORK/warp-phone.pub"
    ip -n "$STAND_INET" link add wg-warp type wireguard
    ip netns exec "$STAND_INET" wg set wg-warp private-key "$STAND_WORK/warp-srv.key" listen-port 51820 \
        peer "$(cat "$STAND_WORK/warp-phone.pub")" allowed-ips 10.30.0.2/32
    ip -n "$STAND_INET" addr add 10.30.0.1/24 dev wg-warp
    ip -n "$STAND_INET" link set wg-warp up
    ip netns exec "$STAND_INET" nft -f - << 'EOF'
table inet bt_warp {
    chain input {
        type filter hook input priority 0; policy accept;
        iifname { "phone0-i", "phone1-i" } ip daddr 10.30.0.53 drop
    }
}
EOF
    cat > "$STAND_WORK/warp.conf" << EOF
[Interface]
PrivateKey = $(cat "$STAND_WORK/warp-phone.key")
Address = 10.30.0.2/32
DNS = 10.30.0.53, warp.lan
MTU = 1380

[Peer]
PublicKey = $(cat "$STAND_WORK/warp-srv.pub")
AllowedIPs = 0.0.0.0/0
Endpoint = 10.20.0.1:51820
EOF
    WP="$(ctl -k profile profile.import name=WARP conf=@"$STAND_WORK/warp.conf")"
    ctl tunnel.up profile="$WP" > /dev/null
    step "the full tunnel up" ctl -t 30 wait "$WP" up
    step "resolv.conf: our resolver first, the full tunnel's after it" within 5 resolv_servers_are "100.100.100.100 10.30.0.53"
    step "... our domains, then its" resolv_search_is "$STAND_DOMAIN corp.example warp.lan"
    step "the NAS by name" within 10 name_is nas "$NAS_IP"
    step "a name outside: the full tunnel's resolver answers (through it)" within 10 name_is outside.test 10.30.0.77
    step "the NAS through Tailscale inside the full tunnel" within 30 ping_from_phone "$NAS_IP"
    ctl tunnel.down profile="$WP" > /dev/null
    step "the full tunnel down: the network's resolver after ours again" within 5 resolv_servers_are "100.100.100.100 10.20.0.1"
    step "... our domains only" resolv_search_is "$STAND_DOMAIN corp.example"
    step "a name outside: the network's resolver again" within 10 name_is outside.test 10.20.0.77
    step "the NAS with the transport outside again" within 30 ping_from_phone "$NAS_IP"
fi

echo "== 5. a crash: always-on brings it back, no second registration"
settings_say() { "$BIN/btctl" -s "$SOCK" settings.get | grep -q "^$1=$2\$"; }
if [ $TLS = 1 ]; then
    # Without the CA the stand's certificate is a stranger's: control must stay shut - no plain
    # fallback, no registration.
    daemon_stop
    NO_CA=1
    log_mark
    daemon_start
    ctl tunnel.up profile="$P" > /dev/null
    step "without the test CA: the certificate refused" within 20 log_new "certificate of 10.20.0.1"
    step "... the tunnel waits for control" within 10 bash -c "test \"\$('$BIN/btctl' -s '$SOCK' status | sed -n 's/^reason=//p' | head -1)\" = control"
    step "... and control never opened" fails log_new "control open"
    NO_CA=0
    daemon_stop
    daemon_start
    ctl tunnel.up profile="$P" > /dev/null
    ctl -t 30 wait "$P" up > /dev/null || true
fi
# As the phone's launcher sees it: the daemon dies while the tunnel is up, and comes back on its own.
ctl settings.set always_on="$P" > /dev/null
step "always-on: a Tailscale profile has its own place" settings_say always_on_tailscale "$P"
step "... the place of the others stays empty" settings_say always_on ""
step "... and the list says it is always on" bash -c \
    "'$BIN/btctl' -s '$SOCK' profile.list | grep -A6 '^profile=$P\$' | grep -q '^always_on=1\$'"
regs_before="$(grep -c "registering the node" "$LOG" || true)"
kill -9 "$DPID"
wait "$DPID" 2> /dev/null || true
DPID=
# As a version before 1.1.0 left it: the one always-on profile, of any kind, in always_on.
sed -i -e "s/^always_on=.*/always_on=$P/" -e "s/^always_on_tailscale=.*/always_on_tailscale=/" "$STATE/settings"
if [ $MAGIC = 1 ]; then
    # Its tun and routes are gone with it; resolv.conf is as it left it.
    step "the daemon dead: its resolver still first in resolv.conf" resolv_servers_are "100.100.100.100 10.20.0.1"
    step "... names still resolve, by the network's resolver after it" name_is outside.test 10.20.0.77
fi
log_mark
daemon_start
step "always-on: up again by itself (no tunnel.up)" ctl -t 30 wait "$P" up
step "the old setting moved to Tailscale's place" settings_say always_on_tailscale "$P"
step "... and left the other place empty" settings_say always_on ""
regs_after="$(grep -c "registering the node" "$LOG" || true)"
step "no second registration" test "$regs_before" = "$regs_after"
step "the NAS again" within 15 ping_from_phone "$NAS_IP"
if [ $MAGIC = 1 ]; then
    step "the journal gave the system its DNS back at the start" log_new "journal: the system's DNS is back"
    step "MagicDNS again after the restart" within 20 name_is nas "$NAS_IP"
    step "... first in resolv.conf again" resolv_servers_are "100.100.100.100 10.20.0.1"
fi

echo "== 6. the login expires; a new auth key"
NODE_ID="$(hs_nodes | python3 -c 'import json,sys; print([n["id"] for n in json.load(sys.stdin) if n.get("given_name")=="phone" or n.get("name")=="phone"][0])')"
hs nodes expire --identifier "$NODE_ID" > /dev/null
step "state error (expired)" ctl -t 30 wait "$P" error
if [ $MAGIC = 1 ]; then
    step "MagicDNS off with it: the system's DNS back" within 5 resolv_servers_are "10.20.0.1"
fi
step "tailscale.nodes while it is in error: refused (no netmap)" fails ctl tailscale.nodes profile="$P"
step "reason: expired" test "$(status_reason)" = expired
KEY2="$(stand_key)"
step "profile.update authkey= (a new node key)" ctl profile.update profile="$P" authkey="$KEY2"
ctl tunnel.down profile="$P" > /dev/null
ctl tunnel.up profile="$P" > /dev/null
step "state up with the new key" ctl -t 30 wait "$P" up
if [ $MAGIC = 1 ]; then
    step "MagicDNS again with the new key" within 20 resolv_servers_are "100.100.100.100 10.20.0.1"
fi
# Headscale 0.29.4 tells the peers our new key but not that the node is no longer expired: the NAS
# keeps the KeyExpiry `nodes expire` gave it and drops us. A new map session gives it the truth
# (the official server sends the change; this is the stand's quirk, not the phone's).
ts nas down > /dev/null 2>&1
ts nas up --login-server "$STAND_CONTROL" --hostname nas --accept-dns=false --timeout 30s > /dev/null 2>&1
if ! within 15 ping_from_phone "$NAS_IP"; then
    echo "   FAIL  the NAS once more"
    FAILED=1
    if [ "${E2E_FAILFAST:-0}" = 1 ]; then exit 1; fi
    echo "---- status"; ctl status | sed 's/^/     /'
    echo "---- the NAS sees"; ts nas status | sed 's/^/     /'
    echo "---- our node key: $(ctl profile.get profile="$P" | sed -n 's/^node_key=//p')"
    echo "---- the NAS's keys for its peers:"
    ts nas status --json | python3 -c 'import json,sys; d=json.load(sys.stdin); [print("     ", p.get("HostName"), p.get("PublicKey"), "expired" if p.get("Expired") else "", p.get("KeyExpiry", "")) for p in d.get("Peer",{}).values()]'
    echo "---- Headscale's:"
    hs nodes list -o json | python3 -c 'import json,sys; [print("     ", n.get("given_name"), n.get("node_key")) for n in json.load(sys.stdin)]'
else
    echo "   ok    the NAS once more"
fi

# The node gone from the tailnet: an admin deletes it (or an ephemeral one falls quiet). The official
# server then refuses the map - "404 node not found" (the phone, 2026-10-22) - and the daemon asks it
# why (check_login): reason removed; that is saas.sh SAAS_REMOVE's, against the real server. Headscale
# 0.29.4 refuses nothing: it ends the stream and answers the next map with our own node expired - so
# here it reads as expired, and the check is never asked for. What the stand does check: the error
# instead of a reconnect loop, and the new login as a new node with a new address (sequential
# allocation) - only that one on the tun, the routes from it.
echo "== 6b. an admin removes the node; a new auth key"
OLD_IP="$(field status)"
NODE_ID="$(hs_nodes | python3 -c 'import json,sys; print([n["id"] for n in json.load(sys.stdin) if n.get("given_name")=="phone" or n.get("name")=="phone"][0])')"
log_mark
hs nodes delete --identifier "$NODE_ID" --force > /dev/null
step "state error (Headscale: expired)" ctl -t 60 wait "$P" error
step "reason: expired (the official server's 404: removed, saas.sh)" test "$(status_reason)" = expired
if [ $MAGIC = 1 ]; then
    step "MagicDNS off with it: the system's DNS back" within 5 resolv_servers_are "10.20.0.1"
fi
KEY3="$(stand_key)"
step "profile.update authkey= (a new node)" ctl profile.update profile="$P" authkey="$KEY3"
step "profile.get: the old node's addresses are not cached" bash -c \
    "! '$BIN/btctl' -s '$SOCK' profile.get profile=$P | grep -q '^address='"
ctl tunnel.down profile="$P" > /dev/null
ctl tunnel.up profile="$P" > /dev/null
step "state up as a new node" ctl -t 30 wait "$P" up
NEW_IP="$(field status)"
echo "   phone: $OLD_IP -> $NEW_IP"
step "a new address" bash -c "[ -n '$NEW_IP' ] && [ '$NEW_IP' != '$OLD_IP' ]"
step "the tun has the new address and not the old one" bash -c \
    "a=\"\$(ip -n $PH -4 addr show)\"; grep -q 'inet $NEW_IP/32' <<< \"\$a\" && ! grep -q 'inet $OLD_IP/' <<< \"\$a\""
step "the NAS from the new address" within 20 ping_from_phone "$NAS_IP"
if [ $MAGIC = 1 ]; then
    step "MagicDNS again as the new node" within 20 resolv_servers_are "100.100.100.100 10.20.0.1"
fi
# An address the node no longer has, as when an admin gives the node another while the tunnel runs:
# here the profile's cache says 100.64.0.250, which goes on the tun first; the netmap brings the
# real one, and the stale one must come off - the routes taking the real one as their source.
ctl tunnel.down profile="$P" > /dev/null
sed -i "s#^address=$NEW_IP/32\$#address=100.64.0.250/32#" "$STATE/$P.conf"
step "the cache holds a stale address" grep -q '^address=100.64.0.250/32$' "$STATE/$P.conf"
log_mark
ctl tunnel.up profile="$P" > /dev/null
step "state up" ctl -t 30 wait "$P" up
step "the stale address came off the tun" within 10 log_new "address 100.64.0.250/32 is no longer the node's - off the tun"
step "the tun has the node's address and not the stale one" bash -c \
    "a=\"\$(ip -n $PH -4 addr show)\"; grep -q 'inet $NEW_IP/32' <<< \"\$a\" && ! grep -q 'inet 100.64.0.250/' <<< \"\$a\""
step "the route to the tailnet takes the node's address" bash -c \
    "ip -n $PH route get $NAS_IP | grep -q 'src $NEW_IP'"
step "the NAS answers" within 20 ping_from_phone "$NAS_IP"
step "the cache has the node's address again" within 5 grep -q "^address=$NEW_IP/32\$" "$STATE/$P.conf"

if [ $MAGIC = 1 ]; then
    echo "== 6c. always on together: a full WireGuard tunnel and Tailscale"
    ctl settings.set always_on="$WP" > /dev/null
    step "the WireGuard profile in its place" settings_say always_on "$WP"
    step "... Tailscale's stays" settings_say always_on_tailscale "$P"
    daemon_stop
    daemon_start
    step "after a start: Tailscale up by itself" ctl -t 30 wait "$P" up
    step "... and the full WireGuard tunnel" ctl -t 30 wait "$WP" up
    step "the NAS through Tailscale inside the full tunnel" within 30 ping_from_phone "$NAS_IP"
    ctl settings.set always_off="$WP" > /dev/null
    step "always_off: the WireGuard one goes" settings_say always_on ""
    step "... Tailscale's stays" settings_say always_on_tailscale "$P"
    ctl tunnel.down profile="$WP" > /dev/null
    ctl profile.delete profile="$WP" > /dev/null
fi

echo "== 7. delete"
step "profile.delete takes it down" ctl profile.delete profile="$P"
step "... and clears always-on" settings_say always_on_tailscale ""
step "no tun route left" bash -c "! ip netns exec $PH ip route show | grep -q '100.64.0.0/10'"
step "resolv.conf: the system's" resolv_servers_are "10.20.0.1"

# A login by a link (TAILSCALE.md section 11b): no key - control gives a link, the daemon waits at it
# (a register with Followup) while somebody logs in there on another device; here Headscale's
# `auth register` is that login. The link is in the status and the events, never in the log.
echo "== 8. log in by a link"
link_now() { ctl status | sed -n 's/^auth_url=//p' | head -1; }
link_new() { local u; u="$(link_now)"; [ -n "$u" ] && [ "$u" != "$1" ]; }
hs_register() { hs auth register --user stand --auth-id "$1" > /dev/null; }
hs_count() { hs_nodes | grep -c "\"given_name\": *\"$1\"" || true; }
step "import with a key and login=link both: refused" fails ctl profile.import type=tailscale name=Both \
    authkey="$KEY" login=link control="$STAND_CONTROL"
step "login= other than link: refused" fails ctl profile.import type=tailscale name=Odd login=browser \
    control="$STAND_CONTROL"
L="$(ctl -k profile profile.import type=tailscale name=Link login=link control="$STAND_CONTROL" hostname=linkphone)"
step "import without a key: profile $L" test -n "$L"
step "profile.get: login=link" bash -c "'$BIN/btctl' -s '$SOCK' profile.get profile=$L | grep -q '^login=link$'"
step "its .conf keeps no auth key" fails grep -q '^auth_key=' "$STATE/$L.conf"
log_mark
ctl tunnel.up profile="$L" > /dev/null
step "reason browser: a link to open" within 30 bash -c "[ \"\$('$BIN/btctl' -s '$SOCK' status | sed -n 's/^reason=//p' | head -1)\" = browser ]"
URL1="$(link_now)"
step "status: the link, Headscale's /register/<id>" bash -c "grep -q '^$STAND_CONTROL/register/' <<< '$URL1'"
step "the log names the link's host, never the link" bash -c \
    "grep -q 'control gave a login link' '$LOG' && ! grep -qF '$URL1' '$LOG' '$STAND_WORK/daemon.stderr'"
step "the wait at it is held: still browser 3 s later" bash -c \
    "sleep 3; [ \"\$('$BIN/btctl' -s '$SOCK' status | sed -n 's/^reason=//p' | head -1)\" = browser ]"
step "Headscale has no linkphone yet" fails hs_has linkphone
ctl tunnel.down profile="$L" > /dev/null
step "down: the link went with the tunnel" bash -c "[ -z \"\$('$BIN/btctl' -s '$SOCK' status | sed -n 's/^auth_url=//p')\" ]"
ctl tunnel.up profile="$L" > /dev/null
step "up again: a new link" within 30 link_new "$URL1"
URL2="$(link_now)"
# The connection lost while the user logs in (the phone back on its first network): the wait goes on
# at the same link after the reconnect.
log_mark
ip -n "$PH" link set phone0 up
ip -n "$PH" route replace default via 10.20.9.1 dev phone0
ip -n "$PH" link set phone1 down
step "control dropped for the new network" within 10 log_new "control lost: the network changed"
step "control open again" within 30 log_new "control open"
step "the same link after the reconnect, still waited at" bash -c \
    "sleep 1; [ \"\$('$BIN/btctl' -s '$SOCK' status | sed -n 's/^auth_url=//p' | head -1)\" = '$URL2' ]"
step "Headscale: the login at the link (auth register)" hs_register "${URL2##*/}"
step "state up: logged in at the link" ctl -t 30 wait "$L" up
step "the log says so" log_new "logged in at the link"
step "status: no link any more" bash -c "[ -z \"\$('$BIN/btctl' -s '$SOCK' status | sed -n 's/^auth_url=//p')\" ]"
step "profile.get: login=ok" bash -c "'$BIN/btctl' -s '$SOCK' profile.get profile=$L | grep -q '^login=ok$'"
step "Headscale has linkphone" within 5 hs_has linkphone
step "the NAS from the node logged in at the link" within 20 ping_from_phone "$NAS_IP"
# Logging in again by a link: a new node key, the old one named - the same device in the tailnet.
step "profile.update login=link" ctl profile.update profile="$L" login=link
ctl tunnel.down profile="$L" > /dev/null
ctl tunnel.up profile="$L" > /dev/null
step "browser again, with a link" within 30 link_new ""
URL3="$(link_now)"
step "Headscale: the login at the new link" hs_register "${URL3##*/}"
step "up with the new node key" ctl -t 30 wait "$L" up
step "Headscale: one linkphone, not two" test "$(hs_count linkphone)" = 1
ts nas down > /dev/null 2>&1
ts nas up --login-server "$STAND_CONTROL" --hostname nas --accept-dns=false --timeout 30s > /dev/null 2>&1
step "the NAS again" within 20 ping_from_phone "$NAS_IP"
step "profile.delete" ctl profile.delete profile="$L"
step "no ASan / UBSan report from the daemon" no_asan

echo
if [ $FAILED = 0 ]; then echo "Tailscale e2e: all passed"; else echo "Tailscale e2e: FAILURES (logs in $KEEP)"; fi
exit $FAILED
