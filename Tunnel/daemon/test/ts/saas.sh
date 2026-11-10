#!/usr/bin/env bash
#
# bbtunneld against the official Tailscale (docs/TAILSCALE.md, sections 13-14: the last step before
# the phone). Our daemon in a namespace with a way out to the internet (NAT through WSL), its DNS a
# public resolver, TLS checked by the built-in roots only - as on the phone. Runs in WSL as root;
# build first (daemon/build.sh host):
#
#   MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -u root -- bash /mnt/e/dev/momentics-projects/Tunnel/daemon/test/ts/saas.sh KEYFILE [100.x.y.z]
#   MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -u root -- bash /mnt/e/dev/momentics-projects/Tunnel/daemon/test/ts/saas.sh probe
#
# KEYFILE: a file holding an auth key of the tailnet - best an ephemeral, pre-approved one with a tag:
# the node then leaves the tailnet by itself once this is over. With an address, the node there is
# pinged through the tunnel; SAAS_NAME=name also looks that node up by name through MagicDNS;
# SAAS_REMOVE=seconds waits that long for an admin to remove the node in the console (reason removed;
# best with a key that is NOT ephemeral, so the node stays until then). `probe`: a made-up auth key - no tailnet is touched; control must refuse
# the login in its own words, which proves the way there: DNS, TCP, TLS with the built-in roots,
# ts2021, HTTP/2, the register request and its answer.
#
#   ts-saas   bbtunneld with a real tun; 10.21.0.2/30, out through WSL's default interface (masquerade)
#
# The key goes to the daemon from a file (btctl authkey=@FILE), never on a command line; the daemon
# does not log it. Logs of the last run: daemon/build/ts-saas/.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TUNNEL="$(cd "$HERE/../../.." && pwd)"
BIN="${BT_BIN:-$TUNNEL/daemon/build/host}"
KEEP="$TUNNEL/daemon/build/ts-saas"
NS=ts-saas
MODE="${1:-}"
TARGET="${2:-}"
[ -n "$MODE" ] || { echo "usage: saas.sh KEYFILE [100.x.y.z] | probe" >&2; exit 2; }
[ -x "$BIN/bbtunneld" ] || { echo "build first: daemon/build.sh host" >&2; exit 2; }
WORK="$(mktemp -d /tmp/ts_saas.XXXXXX)"
SOCK="$WORK/d.sock"
LOG="$WORK/daemon.txt"
EG="$(ip route show default | awk '{print $5; exit}')"
FWD_WAS="$(sysctl -n net.ipv4.ip_forward)"
FAILED=0
DPID=
P=

export ASAN_OPTIONS=detect_leaks=0

# The key into a file of our own, without the line end a text file has (the daemon takes no
# whitespace in a key).
(
    umask 077
    if [ "$MODE" = probe ]; then
        printf 'tskey-auth-kBBTunnelProbe-%s' "$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')" > "$WORK/key"
    else
        [ -r "$MODE" ] || { echo "cannot read $MODE" >&2; exit 2; }
        printf '%s' "$(tr -d ' \t\r\n' < "$MODE")" > "$WORK/key"
    fi
)
if [ "$MODE" = probe ]; then NAME=bbtunnel-probe; else NAME=bbtunnel-wsl; fi

ctl() { "$BIN/btctl" -s "$SOCK" "$@"; }

cleanup() {
    set +e
    if [ -n "$DPID" ]; then
        [ -n "$P" ] && ctl profile.delete profile="$P" > /dev/null 2>&1
        kill "$DPID" 2> /dev/null
        wait "$DPID" 2> /dev/null
    fi
    mkdir -p "$KEEP"
    rm -f "$KEEP"/daemon*.txt
    cp "$WORK"/daemon*.txt "$WORK/daemon.stderr" "$KEEP/" 2> /dev/null
    ip netns del "$NS" 2> /dev/null
    rm -rf "/etc/netns/$NS"
    nft delete table ip bt_saas 2> /dev/null
    sysctl -q -w net.ipv4.ip_forward="$FWD_WAS"
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

# By the clock, not by tries (a try may take seconds itself).
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

field() { ctl "$1" | sed -n "s/^$2=//p" | head -1; }
state_is() { [ "$(field status state)" = "$1" ]; }
state_reason_is() { [ "$(field status reason)" = "$1" ]; }

echo "== the way out: $NS -> $EG (masquerade)"
ip netns del "$NS" 2> /dev/null || true
ip netns add "$NS"
ip -n "$NS" link set lo up
ip link add saas0-h type veth peer name saas0 netns "$NS"
ip addr add 10.21.0.1/30 dev saas0-h
ip link set saas0-h up
ip -n "$NS" addr add 10.21.0.2/30 dev saas0
ip -n "$NS" link set saas0 up
ip -n "$NS" route add default via 10.21.0.1
sysctl -q -w net.ipv4.ip_forward=1
nft add table ip bt_saas
nft add chain ip bt_saas post '{ type nat hook postrouting priority 100; }'
nft add rule ip bt_saas post ip saddr 10.21.0.0/30 oifname "$EG" masquerade
mkdir -p "/etc/netns/$NS"
printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > "/etc/netns/$NS/resolv.conf"
step "DNS from the namespace (controlplane.tailscale.com)" within 10 ip netns exec "$NS" getent hosts controlplane.tailscale.com

ip netns exec "$NS" "$BIN/bbtunneld" --state "$WORK/state" --socket "$SOCK" --log "$LOG" \
    --dns-file /etc/resolv.conf --egress bind --debug >> "$WORK/daemon.stderr" 2>&1 &
DPID=$!
for i in $(seq 1 50); do
    [ -S "$SOCK" ] && ctl hello > /dev/null 2>&1 && break
    sleep 0.1
done

echo "== log in ($([ "$MODE" = probe ] && echo "a made-up key" || echo "the tailnet's key"))"
P="$(ctl -k profile profile.import type=tailscale name=Tailnet authkey=@"$WORK/key" hostname="$NAME")"
rm -f "$WORK/key"
step "import: profile $P (the official server)" bash -c "'$BIN/btctl' -s '$SOCK' profile.get profile=$P | grep -q '^control=https://controlplane.tailscale.com$'"
ctl tunnel.up profile="$P" > /dev/null
step "control open over TLS (the built-in roots)" within 30 grep -q "control open (.*, TLSv1" "$LOG"

if [ "$MODE" = probe ]; then
    step "the made-up key refused by control: state error, reason login" within 30 bash -c \
        "s=\"\$('$BIN/btctl' -s '$SOCK' status)\"; grep -q '^state=error$' <<< \"\$s\" && grep -q '^reason=login$' <<< \"\$s\""
    echo "   control said: $(field status detail)"
    step "nothing registered" bash -c "! grep -q ': registered' '$LOG'"
else
    step "up: registered, netmap, home relay" within 60 state_is up
    # Home is the first region to finish a TLS handshake; the whole round (3 s at most) may move it.
    step "home measured: the whole round" within 6 grep -q "home measured" "$LOG"
    echo "---- home: $(grep -o 'home relay: [0-9]*' "$LOG" | tail -1 | grep -o '[0-9]*$') - handshake ms by region:$(grep -o 'answered, ms:.*' "$LOG" | tail -1 | sed 's/^answered, ms://')"
    echo "---- status"
    ctl status | grep -E '^(state|reason|detail|tailnet|ts_address|ts_name|relay|relay_up|outside|hard_nat|nodes|nodes_active)=' | sed 's/^/     /'
    # STUN against the official map's servers (stage 2): where they see us from outside
    step "STUN: seen from outside (the official map's servers)" within 15 grep -q "seen from outside at " "$LOG"
    echo "     $(grep -o 'seen from outside at .*' "$LOG" | tail -1)"
    echo "---- the tailnet's devices"
    ctl tailscale.nodes profile="$P" | grep -E '^(name|address|online|relay|active)=|^$' | sed 's/^/     /'
    if [ -n "$TARGET" ]; then
        step "ping $TARGET through the tunnel" within 30 ip netns exec "$NS" ping -c 1 -W 3 "$TARGET"
        step "... in use now (tailscale.nodes active=1)" bash -c \
            "'$BIN/btctl' -s '$SOCK' tailscale.nodes profile=$P | grep -q '^active=1$'"
        # SAAS_QUIET=s: then that long without traffic and the node again. The relay we last heard it
        # through goes stale: we close its home relay a minute idle, it leaves ours a minute after it
        # last wrote there, and a relay of several servers may not say so (the phone, 2026-10-16:
        # the browser's SYNs to the NAS went on through it into nothing).
        if [ "${SAAS_QUIET:-0}" -gt 0 ]; then
            echo "---- $SAAS_QUIET s without traffic"
            sleep "$SAAS_QUIET"
            step "ping $TARGET again after $SAAS_QUIET s of quiet" within 20 ip netns exec "$NS" ping -c 1 -W 3 "$TARGET"
        fi
    fi
    # SAAS_NAME=name: MagicDNS (TAILSCALE.md section 8a; the tailnet must have it on) - that node by
    # its short name, at $TARGET when given, and a name outside the tailnet forwarded upstream.
    if [ -n "${SAAS_NAME:-}" ]; then
        name_v4() { ip netns exec "$NS" timeout 15 getent ahostsv4 "$1" | awk '{ print $1; exit }'; }
        echo "---- MagicDNS"
        step "MagicDNS on (the tailnet has it)" within 10 grep -q "MagicDNS on, domain" "$LOG"
        echo "     $(grep -o 'MagicDNS on, domain .*' "$LOG" | tail -1)"
        step "resolv.conf: our resolver first" within 5 bash -c \
            "[ \"\$(awk '\$1 == \"nameserver\" { print \$2; exit }' /etc/netns/$NS/resolv.conf)\" = 100.100.100.100 ]"
        sed 's/^/     /' "/etc/netns/$NS/resolv.conf"
        got="$(name_v4 "$SAAS_NAME" || true)"
        echo "     $SAAS_NAME -> ${got:-nothing}"
        if [ -n "$TARGET" ]; then
            step "$SAAS_NAME by name: $TARGET" test "$got" = "$TARGET"
            step "ping $SAAS_NAME by name" within 20 ip netns exec "$NS" ping -c 1 -W 3 "$SAAS_NAME"
        else
            step "$SAAS_NAME by name: an address of the tailnet" bash -c "case '$got' in 100.*) true ;; *) false ;; esac"
        fi
        step "a name outside the tailnet, forwarded: controlplane.tailscale.com" bash -c \
            "ip netns exec $NS timeout 15 getent ahostsv4 controlplane.tailscale.com > /dev/null"
    fi
    # SAAS_TCP=ip:port: a TCP service of the tailnet through the tunnel - its first line (an SSH banner)
    if [ -n "${SAAS_TCP:-}" ]; then
        tcp_banner() { ip netns exec "$NS" timeout 8 bash -c "exec 3<>/dev/tcp/${SAAS_TCP%:*}/${SAAS_TCP##*:}; head -n 1 <&3" 2> /dev/null | tr -d '\r'; }
        got="$(tcp_banner || true)"
        echo "     TCP $SAAS_TCP says: ${got:-nothing}"
        step "TCP to $SAAS_TCP through the tunnel answers" test -n "$got"
    fi
    # split DNS: what the official server sends (its own reverse zones at least)
    echo "     $(grep -o 'split DNS: .*' "$LOG" | tail -1)"
    # SAAS_REMOVE=s: an admin removes this node in the admin console (Machines, bbtunnel-wsl, Remove)
    # within s seconds - what the official server answers then, and that the daemon stops as removed
    # (the phone's node, ephemeral, gone after days offline, 2026-10-22).
    if [ "${SAAS_REMOVE:-0}" -gt 0 ]; then
        echo "---- remove $NAME in the admin console now: Machines, $NAME, Remove (waiting up to $SAAS_REMOVE s)"
        mark="$(wc -l < "$LOG")"
        step "state error after the removal" within "$SAAS_REMOVE" state_is error
        echo "     reason=$(field status reason)"
        echo "     detail=$(field status detail)"
        echo "---- what control said"
        tail -n "+$((mark + 1))" "$LOG" | grep -E "control|map|register|asking|answer|stopped" | sed 's/^/     /' | tail -n 20
        step "reason: removed" state_reason_is removed
    fi
fi
step "no ASan / UBSan report from the daemon" bash -c "! grep -q 'ERROR: AddressSanitizer\|runtime error:' '$WORK/daemon.stderr'"

echo
if [ $FAILED = 0 ]; then echo "Tailscale official: all passed"; else echo "Tailscale official: FAILURES (logs in $KEEP)"; fi
exit $FAILED
