#!/usr/bin/env bash
#
# Direct paths (docs/TAILSCALE.md, section 11a) on the stand of stand.sh, stage A: the phone and a NAS
# at home behind one router, Headscale outside. Runs in WSL as root; build first (daemon/build.sh
# host, then stand_build.sh):
#
#   MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -u root -- bash /mnt/e/dev/momentics-projects/Tunnel/daemon/test/ts/direct.sh
#
#   ts-inet    the internet: Headscale on 10.20.0.1:8080 (control and its DERP, region 999, STUN :3478),
#              a second STUN server on 10.20.0.3 (stun_stub.py, region 998, STUN only); it forwards
#              between the routers from section 5 on
#   ts-home    the home router: uplink 10.20.77.2 to ts-inet with NAT (nft masquerade), the LAN
#              192.168.77.0/24 on a bridge (192.168.77.1); no port is open from outside (no UPnP)
#   ts-hnas    the NAS at home: the official tailscaled on 192.168.77.15 - direct paths allowed (no
#              TS_DEBUG_ALWAYS_USE_DERP), DERP over plain HTTP as everywhere on stage A
#   ts-phone   bbtunneld on 192.168.77.2, the same LAN; later on 192.168.88.2 and 192.168.99.2
#   ts-away    a network away from home (section 5): uplink 10.20.88.2, NAT - one port for every
#              destination (an easy NAT), LAN 192.168.88.0/24
#   ts-hard    another (section 6): uplink 10.20.99.2, NAT fully-random - a new port for each
#              destination (a hard NAT), LAN 192.168.99.0/24
#
# Scenarios, stage 1 (the LAN): up; our endpoint is the LAN address; the NAS is reached directly (our
# log, tailscale.nodes direct=, and the official side's CurAddr); traffic with control and DERP blocked
# at the router - only a direct path carries it; the LAN path blocked - back to the relays, and direct
# again once it is open. Stage 2 (STUN): the phone away from home - STUN finds its address outside, both
# sides punch through their NATs and the NAS is reached directly at the home router's address, with
# DERP blocked too; a hard NAT - both STUN servers see different ports, the relays carry it and nothing
# breaks; home again - the LAN path. Logs of the last run: daemon/build/ts-direct/.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TUNNEL="$(cd "$HERE/../../.." && pwd)"
BIN="${BT_BIN:-$TUNNEL/daemon/build/host}"
KEEP="$TUNNEL/daemon/build/ts-direct"
STAND_TLS=0
STAND_STUN_ONLY=10.20.0.3
STAND_STUN_ONLY6=2001:db8:20::3
STAND_SOURCED=1
# shellcheck source=stand.sh
. "$HERE/stand.sh"
PH=ts-phone
HOME_NS=ts-home
NAS_NS=ts-hnas
SOCK="$STAND_WORK/d.sock"
STATE="$STAND_WORK/state"
LOG="$STAND_WORK/daemon.txt"
FAILED=0
DPID=

export ASAN_OPTIONS=detect_leaks=0

ctl() { "$BIN/btctl" -s "$SOCK" "$@"; }
inph() { ip netns exec "$PH" "$@"; }
inhome() { ip netns exec "$HOME_NS" "$@"; }

cleanup() {
    set +e
    if [ -n "$DPID" ]; then
        kill "$DPID" 2> /dev/null
        wait "$DPID" 2> /dev/null
    fi
    mkdir -p "$KEEP"
    rm -f "$KEEP"/*
    cp "$STAND_WORK"/daemon*.txt "$STAND_WORK/daemon.stderr" "$STAND_WORK/headscale.log" "$KEEP/" 2> /dev/null
    cp "$STAND_WORK/hnas/tailscaled.log" "$KEEP/hnas.tailscaled.log" 2> /dev/null
    ip netns del "$PH" 2> /dev/null
    rm -rf "/etc/netns/$PH"
    stand_down
    ip netns del "$NAS_NS" 2> /dev/null
    ip netns del "$HOME_NS" 2> /dev/null
    ip netns del ts-away 2> /dev/null
    ip netns del ts-hard 2> /dev/null
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

# By the clock, not by tries.
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

fails() { ! "$@"; }
log_has() { grep -q "$1" "$LOG"; }
ping_nas() { inph ping -c 1 -W 2 "$NAS_IP" > /dev/null 2>&1; }
no_asan() { ! grep -q "ERROR: AddressSanitizer\|runtime error:" "$STAND_WORK/daemon.stderr"; }
nodes_direct() {
    local out
    out="$(ctl tailscale.nodes profile="$P")"
    grep -q "^direct=192\.168\.77\.15:" <<< "$out"
}
nodes_not_direct() {
    local out
    out="$(ctl tailscale.nodes profile="$P")"
    ! grep -q "^direct=" <<< "$out"
}
# The official side: its CurAddr for the phone - a direct address starting with $1 (default: the
# phone's home LAN address), not "" (DERP).
nas_sees_direct() {
    ts hnas status --json | python3 -c '
import json, sys
d = json.load(sys.stdin)
for p in d.get("Peer", {}).values():
    if p.get("HostName") == "phone" and p.get("CurAddr", "").startswith(sys.argv[1]):
        sys.exit(0)
sys.exit(1)' "${1:-192.168.77.2:}"
}
# Our status (ctl status) has a line matching $1.
status_has() {
    local out
    out="$(ctl status)"
    grep -q "$1" <<< "$out"
}
log_mark() { LOG_MARK="$(wc -l < "$LOG")"; }
log_new() { tail -n "+$((LOG_MARK + 1))" "$LOG" | grep -q "$1"; }

# A router to the internet with NAT and a LAN on a bridge: uplink 10.20.$2.2/24, LAN 192.168.$2.0/24;
# the home router's firewall on the uplink (see there). $3 = 1: masquerade fully-random - a new port
# for each destination (a hard NAT).
make_router() {
    local ns="$1" n="$2" nat="masquerade"
    [ "${3:-0}" = 1 ] && nat="masquerade fully-random"
    ip netns del "$ns" 2> /dev/null || true
    ip netns add "$ns"
    ip -n "$ns" link set lo up
    ip link add "r$n-up" netns "$ns" type veth peer name "r$n-up-i" netns "$STAND_INET"
    ip -n "$ns" addr add "10.20.$n.2/24" dev "r$n-up"
    ip -n "$STAND_INET" addr add "10.20.$n.1/24" dev "r$n-up-i"
    ip -n "$ns" link set "r$n-up" up
    ip -n "$STAND_INET" link set "r$n-up-i" up
    ip -n "$ns" route add default via "10.20.$n.1"
    ip -n "$ns" link add br0 type bridge
    ip -n "$ns" addr add "192.168.$n.1/24" dev br0
    ip -n "$ns" link set br0 up
    ip netns exec "$ns" sysctl -q -w net.ipv4.ip_forward=1
    ip netns exec "$ns" nft -f - << EOF
table ip nat {
    chain post {
        type nat hook postrouting priority 100; policy accept;
        oifname "r$n-up" $nat
    }
}
table inet fw {
    chain input {
        type filter hook input priority 0; policy accept;
        iifname "r$n-up" ct state new drop
    }
}
EOF
}

# The phone moves into router $1's LAN 192.168.$2.0/24 (a change of Wi-Fi): its link goes, a new one
# ($3) comes into that bridge, its address .2 and the default route through the router.
PH_IF=ph0
phone_to() {
    local ns="$1" n="$2" ifc="$3"
    ip -n "$PH" link del "$PH_IF" 2> /dev/null || true
    ip link add "$ifc" netns "$PH" type veth peer name "$ifc-b" netns "$ns"
    ip -n "$ns" link set "$ifc-b" master br0
    ip -n "$ns" link set "$ifc-b" up
    ip -n "$PH" addr add "192.168.$n.2/24" dev "$ifc"
    ip -n "$PH" link set "$ifc" up
    ip -n "$PH" route add default via "192.168.$n.1"
    PH_IF="$ifc"
}

# Only a direct path can carry it: control, DERP and STUN (10.20.0.x) dropped at router $1.
block_inet() {
    ip netns exec "$1" nft -f - << 'EOF'
table inet block_derp {
    chain forward_filter {
        type filter hook forward priority 0; policy accept;
        ip daddr 10.20.0.0/24 drop
    }
}
EOF
}
# One TCP exchange with the NAS (as e2e.sh's: -q 3, the listener waited for, so a retry finds the port
# free).
tcp_to_nas() {
    local got lp
    ip netns exec "$NAS_NS" bash -c 'echo pong | timeout 8 nc -l -p 7777 -q 3 > /dev/null' &
    lp=$!
    sleep 0.5
    got="$(echo ping | timeout 8 ip netns exec "$PH" nc -q 3 "$NAS_IP" 7777)" || true
    wait "$lp" 2> /dev/null || true
    [ "$got" = pong ]
}
# A burst of pings to the NAS: all answered.
pings_nas() { inph ping -c 5 -i 0.2 -W 2 "$NAS_IP" > /dev/null 2>&1; }

echo "== the stand (stage A) in $STAND_WORK, a home LAN behind a router"
stand_up
KEY="$(stand_key)"

# The home router: uplink to ts-inet with NAT, the LAN on a bridge.
ip netns del "$HOME_NS" 2> /dev/null || true
ip netns add "$HOME_NS"
ip -n "$HOME_NS" link set lo up
ip link add home-up netns "$HOME_NS" type veth peer name home-up-i netns "$STAND_INET"
ip -n "$HOME_NS" addr add 10.20.77.2/24 dev home-up
ip -n "$STAND_INET" addr add 10.20.77.1/24 dev home-up-i
ip -n "$HOME_NS" link set home-up up
ip -n "$STAND_INET" link set home-up-i up
ip -n "$HOME_NS" route add default via 10.20.77.1
ip -n "$HOME_NS" link add br0 type bridge
ip -n "$HOME_NS" addr add 192.168.77.1/24 dev br0
ip -n "$HOME_NS" link set br0 up
inhome sysctl -q -w net.ipv4.ip_forward=1
# NAT, and the firewall every home router has on its uplink: nothing new to the router itself. Without
# it the hole punching of section 5 never works - for the official client either: our first ping
# reaches the router before the NAS has sent anything, the router takes it as a connection to itself
# (conntrack keeps it, our pings keep it alive), and the NAS's own packet to us then cannot have its
# port - the NAT gives it another one (measured on this stand, 2026-10-22). Dropped at the input, the
# early ping leaves nothing behind.
inhome nft -f - << 'EOF'
table ip nat {
    chain post {
        type nat hook postrouting priority 100; policy accept;
        oifname "home-up" masquerade
    }
}
table inet fw {
    chain input {
        type filter hook input priority 0; policy accept;
        iifname "home-up" ct state new drop
    }
}
EOF

# A host on the LAN: its own namespace, a port on the bridge.
lan_host() {
    local ns="$1" ifc="$2" addr="$3"
    ip netns del "$ns" 2> /dev/null || true
    ip netns add "$ns"
    ip -n "$ns" link set lo up
    ip link add "$ifc" netns "$ns" type veth peer name "$ifc-b" netns "$HOME_NS"
    ip -n "$HOME_NS" link set "$ifc-b" master br0
    ip -n "$HOME_NS" link set "$ifc-b" up
    ip -n "$ns" addr add "$addr/24" dev "$ifc"
    ip -n "$ns" link set "$ifc" up
    ip -n "$ns" route add default via 192.168.77.1
}

# The NAS: the official tailscaled, direct paths allowed.
lan_host "$NAS_NS" hnas0 192.168.77.15
mkdir -p "$STAND_WORK/hnas"
ip netns exec "$NAS_NS" env TS_DEBUG_USE_DERP_HTTP=1 \
    "$STAND_BIN/tailscaled" --state="$STAND_WORK/hnas/state" --socket="$STAND_WORK/hnas/sock" \
    --statedir="$STAND_WORK/hnas" --tun=tshnas > "$STAND_WORK/hnas/tailscaled.log" 2>&1 &
STAND_PIDS+=($!)
for i in $(seq 1 50); do [ -S "$STAND_WORK/hnas/sock" ] && break; sleep 0.1; done
ts hnas up --login-server "$STAND_CONTROL" --authkey "$KEY" --hostname hnas --accept-dns=false --timeout 30s > /dev/null
NAS_IP="$(ts hnas ip -4)"
echo "   NAS: $NAS_IP at 192.168.77.15"

# The phone on the same LAN.
lan_host "$PH" ph0 192.168.77.2
mkdir -p "/etc/netns/$PH"
echo "nameserver 10.20.0.1" > "/etc/netns/$PH/resolv.conf"
ip netns exec "$PH" "$BIN/bbtunneld" --state "$STATE" --socket "$SOCK" --log "$LOG" \
    --dns-file /etc/resolv.conf --egress bind --debug >> "$STAND_WORK/daemon.stderr" 2>&1 &
DPID=$!
for i in $(seq 1 50); do
    [ -S "$SOCK" ] && ctl hello > /dev/null 2>&1 && break
    sleep 0.1
done

echo "== 1. up, our endpoint"
P="$(ctl -k profile profile.import type=tailscale name=Tailnet authkey="$KEY" control="$STAND_CONTROL" hostname=phone)"
ctl tunnel.up profile="$P" > /dev/null
step "state up" ctl -t 30 wait "$P" up
step "our endpoint is the LAN address" within 10 log_has "direct paths: our endpoints 192.168.77.2:"

echo "== 2. the NAS directly"
step "the phone pings the NAS" within 20 ping_nas
# Traffic keeps the search going: a ping a second until the path is direct.
direct_soon() { ping_nas; log_has "hnas directly at 192.168.77.15:"; }
step "our side: the NAS directly at its LAN address" within 30 direct_soon
step "tailscale.nodes says so (direct=)" within 5 nodes_direct
nas_direct_soon() { ping_nas; nas_sees_direct; }
step "the NAS's side: the phone directly (CurAddr 192.168.77.2)" within 30 nas_direct_soon

echo "== 3. only a direct path can carry it: control and DERP blocked at the router"
inhome nft -f - << 'EOF'
table inet block_derp {
    chain forward_filter {
        type filter hook forward priority 0; policy accept;
        ip daddr 10.20.0.1 drop
    }
}
EOF
step "5 pings to the NAS, all answered" pings_nas
step "TCP to the NAS" within 30 tcp_to_nas
inhome nft delete table inet block_derp

echo "== 4. the LAN path blocked: back to the relays, then direct again"
# In the phone itself (WSL's kernel filters no bridge): every UDP datagram to and from the NAS's LAN
# address - the direct path's disco and WireGuard, nothing else goes there.
inph nft -f - << 'EOF'
table inet block_lan {
    chain out_filter {
        type filter hook output priority 0; policy accept;
        ip daddr 192.168.77.15 meta l4proto udp drop
    }
    chain in_filter {
        type filter hook input priority 0; policy accept;
        ip saddr 192.168.77.15 meta l4proto udp drop
    }
}
EOF
back_soon() { ping_nas; log_has "hnas through the relays again"; }
step "our side: through the relays again" within 30 back_soon
step "the NAS still answers (through DERP)" within 20 pings_nas
inph nft delete table inet block_lan
direct_again() { ping_nas; [ "$(grep -c 'hnas directly at 192.168.77.15:' "$LOG")" -ge 2 ]; }
step "direct again once the LAN is open" within 40 direct_again

echo "== 5. away from home: the phone behind another NAT, the NAS behind the home router's (STUN)"
# The internet carries packets between the routers now; the home router still opens no port: without
# our address from STUN the NAS could not reach us, nor we it (both NATs drop what they did not ask for).
ip netns exec "$STAND_INET" sysctl -q -w net.ipv4.ip_forward=1
make_router ts-away 88
log_mark
phone_to ts-away 88 ph1
step "our local endpoint is the new LAN's" within 15 log_new "direct paths: our endpoints 192.168.88.2:"
step "STUN: seen from outside at the away router's address" within 15 log_new "direct paths: seen from outside at 10.20.88.2:"
step "our endpoints: the local one and STUN's" within 5 log_new "our endpoints 192.168.88.2:[0-9]* 10.20.88.2:[0-9]* (STUN)"
step "status: outside=10.20.88.2:..." within 5 status_has "^outside=10\.20\.88\.2:"
step "an easy NAT: no hard_nat" fails status_has "^hard_nat="
away_direct() { ping_nas; log_new "hnas directly at 10\.20\.77\.2:"; }
step "the NAS directly at the home router's address - through both NATs" within 60 away_direct
nas_away() { ping_nas; nas_sees_direct 10.20.88.2:; }
step "the NAS's side: the phone directly (CurAddr 10.20.88.2)" within 30 nas_away
block_inet ts-away
step "control, DERP and STUN blocked away: 5 pings to the NAS, all answered" pings_nas
step "... and TCP" within 30 tcp_to_nas
ip netns exec ts-away nft delete table inet block_derp

echo "== 6. a hard NAT: a new port for each destination - the relays carry it, nothing breaks"
make_router ts-hard 99 1
log_mark
phone_to ts-hard 99 ph2
step "STUN: seen from outside at the hard router's address" within 15 log_new "seen from outside at 10\.20\.99\.2:"
step "the two STUN servers saw two ports: a hard NAT" within 15 log_new "a hard NAT"
step "status: hard_nat=1" within 5 status_has "^hard_nat=1$"
step "the NAS answers through the relays" within 30 pings_nas
quiet_minute() {
    local i
    for i in $(seq 1 20); do ping_nas; sleep 1; done
    ! log_new "hnas directly at"
}
step "20 s of traffic, no direct path (none can get through)" quiet_minute

echo "== 7. home again: the LAN path"
log_mark
phone_to "$HOME_NS" 77 ph3
home_again() { ping_nas; log_new "hnas directly at 192\.168\.77\.15:"; }
step "directly at the NAS's LAN address again" within 60 home_again
step "the hard NAT is forgotten with the network" within 15 bash -c "! '$BIN/btctl' -s '$SOCK' status | grep -q '^hard_nat='"

echo "== 8. IPv6 at home: the LAN path over IPv6 when IPv4 cannot carry it, STUN over IPv6"
# The home's IPv6: a global /64 (2001:db8:77::/64 - documentation space, but not ULA: magicsock offers
# no ULA beside anything else), routed by the home router to ts-inet, where the STUN server answers on
# 2001:db8:20::3 too. No NAT for IPv6, as at home.
ip -n "$HOME_NS" -6 addr add 2001:db8:177::2/64 dev home-up nodad
ip -n "$STAND_INET" -6 addr add 2001:db8:177::1/64 dev home-up-i nodad
ip -n "$HOME_NS" -6 route add default via 2001:db8:177::1
ip -n "$STAND_INET" -6 route add 2001:db8:77::/64 via 2001:db8:177::2
inhome sysctl -q -w net.ipv6.conf.all.forwarding=1
ip -n "$HOME_NS" -6 addr add 2001:db8:77::1/64 dev br0 nodad
ip -n "$NAS_NS" -6 addr add 2001:db8:77::15/64 dev hnas0 nodad
ip -n "$NAS_NS" -6 route add default via 2001:db8:77::1
log_mark
ip -n "$PH" -6 addr add 2001:db8:77::2/64 dev "$PH_IF" nodad
ip -n "$PH" -6 route add default via 2001:db8:77::1
step "our IPv6 endpoint: the LAN's global address" within 15 log_new "our endpoints .*\[2001:db8:77::2\]:"
step "STUN over IPv6: seen from outside at the same address (no NAT)" within 30 log_new "seen from outside at \[2001:db8:77::2\]:"
step "status: outside=[2001:db8:77::2]:..." within 5 status_has "^outside=\[2001:db8:77::2\]:"
# IPv4 between the phone and the NAS closed, in the phone as in section 4: only IPv6 can carry it
# directly (with IPv4 open the LAN's IPv4 path wins - a private address scores higher).
inph nft -f - << 'EOF'
table inet block_lan4 {
    chain out_filter {
        type filter hook output priority 0; policy accept;
        ip daddr 192.168.77.15 meta l4proto udp drop
    }
    chain in_filter {
        type filter hook input priority 0; policy accept;
        ip saddr 192.168.77.15 meta l4proto udp drop
    }
}
EOF
v6_soon() { ping_nas; log_new "hnas directly at \[2001:db8:77::15\]:"; }
step "the NAS directly over IPv6" within 60 v6_soon
nas_v6() { ping_nas; nas_sees_direct "[2001:db8:77::2]:"; }
step "the NAS's side: the phone over IPv6 (CurAddr [2001:db8:77::2])" within 30 nas_v6
step "5 pings to the NAS, all answered" pings_nas
inph nft delete table inet block_lan4

echo "== 9. down"
step "tunnel.down" ctl tunnel.down profile="$P"
step "no ASan / UBSan report from the daemon" no_asan

echo
if [ $FAILED = 0 ]; then echo "Tailscale direct: all passed"; else echo "Tailscale direct: FAILURES (logs in $KEEP)"; fi
exit $FAILED
