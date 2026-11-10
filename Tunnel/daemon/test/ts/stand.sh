#!/usr/bin/env bash
#
# The Tailscale stand (docs/TAILSCALE.md, section 13): Headscale with its embedded DERP, and official
# tailscaled nodes in network namespaces - everything the daemon's own client will be tested against,
# without a phone or an account. Runs in WSL as root; build the binaries first (stand_build.sh):
#
#   MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -u root -- bash /mnt/e/dev/momentics-projects/Tunnel/daemon/test/ts/stand.sh [tls] [selftest]
#
# Stage A (the default): plain HTTP, no certificates.
#
#   ts-inet   the internet: Headscale on 10.20.0.1:8080 (control and /derp, region 999), STUN on :3478
#   ts-nas    the NAS: official tailscaled, logged in with a pre-auth key, a real tun
#   ts-ref    a reference phone: another official tailscaled - what our client must do too
#
# STAND_STUN_ONLY=<address>: a second STUN server there (stun_stub.py, region 998, STUN only), on
# either stage.
#
# Stage B (`tls`, or STAND_TLS=1): TLS as on the real network.
#
#   ts-inet   Headscale on https://10.20.0.1 (port 443) with a certificate from the stand's own test
#             CA, its embedded DERP the same way (region 999, checked against the CA by the IP);
#             derper on 10.20.0.2:443 with the self-signed certificate derper makes for an IP
#             (region 900, its CertName "sha256-raw:..." in Headscale's DERP map - checked by the pin)
#
# The CA is $STAND_CA: the daemon takes it with --ca-file, tailscaled with SSL_CERT_FILE.
#
# The client namespaces reach ts-inet only; they cannot reach each other (no forwarding in ts-inet),
# so every packet between nodes crosses DERP - as on the phone behind CGNAT. tailscaled runs with
# TS_DEBUG_ALWAYS_USE_DERP=1 (DERP-only, like our client), and on stage A with TS_DEBUG_USE_DERP_HTTP=1
# (DERP over plain HTTP).
#
# `selftest`: the two official nodes see each other and ping over DERP - the stand itself works; on
# stage B also with the two in different regions. Sourced by a test (STAND_SOURCED=1), it only
# defines the functions: stand_up, stand_down, stand_key (a reusable pre-auth key), stand_node <name>
# (an official node in its own namespace).

set -euo pipefail

# A test that sources this sets STAND_TLS itself: a `shift` here would eat the test's own arguments.
if [ "${STAND_SOURCED:-0}" != 1 ] && [ "${1:-}" = tls ]; then
    STAND_TLS=1
    shift
fi
STAND_TLS="${STAND_TLS:-0}"
# MagicDNS (STAND_MAGIC=1, TAILSCALE.md section 8a): the nodes are <name>.$STAND_DOMAIN, with a
# search domain and an extra record beside them; otherwise the tailnet has none.
STAND_MAGIC="${STAND_MAGIC:-0}"
STAND_DOMAIN=stand.ts.net
STAND_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAND_TUNNEL="$(cd "$STAND_HERE/../../.." && pwd)"
STAND_BIN="${STAND_BIN:-$STAND_TUNNEL/daemon/build/stand}"
STAND_WORK="${STAND_WORK:-$(mktemp -d /tmp/ts_stand.XXXXXX)}"
STAND_INET=ts-inet
STAND_CA="$STAND_WORK/ca/ca.crt"
STAND_DERPER=10.20.0.2
if [ "$STAND_TLS" = 1 ]; then
    STAND_CONTROL="https://10.20.0.1"
    STAND_LISTEN="10.20.0.1:443"
else
    STAND_CONTROL="http://10.20.0.1:8080"
    STAND_LISTEN="10.20.0.1:8080"
fi
STAND_PIDS=()
STAND_NODES=()

stand_in() { ip netns exec "$STAND_INET" "$@"; }
hs() { stand_in "$STAND_BIN/headscale" --config "$STAND_WORK/headscale.yaml" "$@"; }

stand_down() {
    set +e
    local p n i alive
    # The processes first, their namespaces after: a tailscaled whose namespace is gone does not
    # finish its SIGTERM, and the `wait` below would wait for it forever. KILL what is left after 3 s.
    for p in "${STAND_PIDS[@]}"; do kill "$p" 2> /dev/null; done
    for i in $(seq 1 30); do
        alive=0
        for p in "${STAND_PIDS[@]}"; do kill -0 "$p" 2> /dev/null && alive=1; done
        [ $alive = 0 ] && break
        sleep 0.1
    done
    for p in "${STAND_PIDS[@]}"; do kill -KILL "$p" 2> /dev/null; done
    wait 2> /dev/null
    for n in "${STAND_NODES[@]}"; do ip netns del "ts-$n" 2> /dev/null; done
    ip netns del "$STAND_INET" 2> /dev/null
    rm -rf "$STAND_WORK"
}

# Stage B: the test CA, and Headscale's certificate for 10.20.0.1 from it. Go takes no name from the
# CN - the address is in the SAN, as on any server today.
stand_certs() {
    local d="$STAND_WORK/ca"
    mkdir -p "$d"
    cat > "$d/openssl.cnf" << 'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = Tunnel stand test CA
[ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[server]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = IP:10.20.0.1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
    openssl req -x509 -config "$d/openssl.cnf" -extensions ca -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
        -nodes -days 3 -keyout "$d/ca.key" -out "$d/ca.crt" 2> "$d/openssl.log"
    openssl req -new -config "$d/openssl.cnf" -subj "/CN=10.20.0.1" -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
        -nodes -keyout "$d/hs.key" -out "$d/hs.csr" 2>> "$d/openssl.log"
    openssl x509 -req -in "$d/hs.csr" -CA "$d/ca.crt" -CAkey "$d/ca.key" -CAcreateserial -days 3 \
        -extfile "$d/openssl.cnf" -extensions server -out "$d/hs.crt" 2>> "$d/openssl.log"
}

# Stage B: derper on 10.20.0.2:443. With an IP for a host name and no certificate in its directory it
# makes a self-signed one, and the region goes into Headscale's DERP map with that certificate's pin
# (the CertName derper itself prints; https://tailscale.com/s/custom-derp). Before Headscale starts:
# it reads the map file once.
stand_derper() {
    local d="$STAND_WORK/derper" i pin
    mkdir -p "$d"
    ip -n "$STAND_INET" addr add "$STAND_DERPER/32" dev lo
    ip netns exec "$STAND_INET" "$STAND_BIN/derper" -c "$d/derper.key" -a "$STAND_DERPER:443" -http-port -1 \
        -hostname "$STAND_DERPER" -certmode manual -certdir "$d" > "$d/derper.log" 2>&1 &
    STAND_PIDS+=($!)
    for i in $(seq 1 100); do
        grep -q "Using self-signed certificate" "$d/derper.log" 2> /dev/null && break
        sleep 0.1
    done
    [ -s "$d/$STAND_DERPER.crt" ] || { echo "derper made no certificate" >&2; tail -5 "$d/derper.log" >&2; return 1; }
    pin="$(openssl x509 -in "$d/$STAND_DERPER.crt" -outform DER | sha256sum | cut -d' ' -f1)"
    grep -q "sha256-raw:$pin" "$d/derper.log" || { echo "the pin is not the one derper printed" >&2; return 1; }
    cat > "$STAND_WORK/derp.yaml" << EOF
regions:
  900:
    regionid: 900
    regioncode: derper
    regionname: Stand derper
    nodes:
      - name: 900a
        regionid: 900
        hostname: $STAND_DERPER
        ipv4: $STAND_DERPER
        stunport: 3478
        derpport: 443
        certname: "sha256-raw:$pin"
EOF
    for i in $(seq 1 50); do
        stand_in bash -c "exec 3<> /dev/tcp/$STAND_DERPER/443" 2> /dev/null && return 0
        sleep 0.1
    done
    echo "derper does not listen" >&2
    return 1
}

# A second STUN server (STAND_STUN_ONLY=<an address in ts-inet>): region 998, STUN only - never a
# relay, never anyone's home - beside Headscale's own. Two servers tell an easy NAT from a hard one
# (direct.sh, TAILSCALE.md section 11a stage 2).
stand_stun_only() {
    local v6=""
    ip -n "$STAND_INET" addr add "$STAND_STUN_ONLY/32" dev lo
    ip netns exec "$STAND_INET" python3 "$STAND_HERE/stun_stub.py" "$STAND_STUN_ONLY" > "$STAND_WORK/stun_stub.log" 2>&1 &
    STAND_PIDS+=($!)
    # STAND_STUN_ONLY6=<an IPv6 address>: the same server over IPv6 as well (direct.sh, IPv6 paths)
    if [ -n "${STAND_STUN_ONLY6:-}" ]; then
        ip -n "$STAND_INET" -6 addr add "$STAND_STUN_ONLY6/128" dev lo nodad
        ip netns exec "$STAND_INET" python3 "$STAND_HERE/stun_stub.py" "$STAND_STUN_ONLY6" > "$STAND_WORK/stun_stub6.log" 2>&1 &
        STAND_PIDS+=($!)
        v6="
        ipv6: $STAND_STUN_ONLY6"
    fi
    cat > "$STAND_WORK/stun.yaml" << EOF
regions:
  998:
    regionid: 998
    regioncode: stun
    regionname: Stand STUN
    nodes:
      - name: 998a
        regionid: 998
        hostname: $STAND_STUN_ONLY
        ipv4: $STAND_STUN_ONLY$v6
        stunport: 3478
        stunonly: true
EOF
}

stand_up() {
    local i tls="" paths="[]" curl_ca="" dns split="{}"
    # STAND_SPLIT="suffix=server": a split-DNS route (DNSConfig.Routes) with MagicDNS on
    if [ -n "${STAND_SPLIT:-}" ]; then
        split="
      ${STAND_SPLIT%%=*}:
        - ${STAND_SPLIT#*=}"
    fi
    if [ "$STAND_MAGIC" = 1 ]; then
        dns="  magic_dns: true
  base_domain: $STAND_DOMAIN
  override_local_dns: false
  nameservers:
    global: []
    split: $split
  search_domains: [corp.example]
  extra_records:
    - name: printer.$STAND_DOMAIN
      type: A
      value: 100.64.0.99"
    else
        dns="  magic_dns: false
  override_local_dns: false
  nameservers:
    global: []
    split: {}
  search_domains: []
  extra_records: []"
    fi
    [ -x "$STAND_BIN/headscale" ] && [ -x "$STAND_BIN/tailscaled" ] || { echo "build first: stand_build.sh" >&2; return 2; }
    ip netns del "$STAND_INET" 2> /dev/null || true
    ip netns add "$STAND_INET"
    ip -n "$STAND_INET" link set lo up
    ip -n "$STAND_INET" addr add 10.20.0.1/32 dev lo
    mkdir -p "$STAND_WORK/hs"
    if [ "$STAND_TLS" = 1 ]; then
        stand_certs
        stand_derper
        tls="tls_cert_path: $STAND_WORK/ca/hs.crt
tls_key_path: $STAND_WORK/ca/hs.key"
        paths="[$STAND_WORK/derp.yaml]"
        curl_ca="--cacert $STAND_CA"
    fi
    if [ -n "${STAND_STUN_ONLY:-}" ]; then
        stand_stun_only
        if [ "$paths" = "[]" ]; then paths="[$STAND_WORK/stun.yaml]"; else paths="${paths%]}, $STAND_WORK/stun.yaml]"; fi
    fi
    cat > "$STAND_WORK/headscale.yaml" << EOF
server_url: $STAND_CONTROL
listen_addr: $STAND_LISTEN
metrics_listen_addr: 127.0.0.1:9090
grpc_listen_addr: 127.0.0.1:50443
grpc_allow_insecure: false
$tls
noise:
  private_key_path: $STAND_WORK/hs/noise_private.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential
derp:
  server:
    enabled: true
    region_id: 999
    region_code: "stand"
    region_name: "Stand DERP"
    verify_clients: true
    stun_listen_addr: "10.20.0.1:3478"
    private_key_path: $STAND_WORK/hs/derp_server_private.key
    automatically_add_embedded_derp_region: true
    ipv4: 10.20.0.1
  urls: []
  paths: $paths
  auto_update_enabled: false
  update_frequency: 3h
disable_check_updates: true
node:
  expiry: 0
database:
  type: sqlite
  sqlite:
    path: $STAND_WORK/hs/db.sqlite
    write_ahead_log: true
log:
  level: info
  format: text
policy:
  mode: file
  path: ""
dns:
$dns
unix_socket: $STAND_WORK/hs/headscale.sock
unix_socket_permission: "0770"
logtail:
  enabled: false
taildrop:
  enabled: false
EOF
    # Straight through `ip netns exec`, not a function: $! must be Headscale's pid (e2e run.sh).
    ip netns exec "$STAND_INET" "$STAND_BIN/headscale" --config "$STAND_WORK/headscale.yaml" serve \
        > "$STAND_WORK/headscale.log" 2>&1 &
    STAND_PIDS+=($!)
    # shellcheck disable=SC2086 # curl_ca: two words or none
    for i in $(seq 1 100); do
        stand_in curl -s -m 1 $curl_ca "$STAND_CONTROL/health" > /dev/null 2>&1 && break
        sleep 0.2
    done
    # shellcheck disable=SC2086
    stand_in curl -s -m 2 $curl_ca "$STAND_CONTROL/health" > /dev/null || { echo "Headscale did not come up" >&2; tail -20 "$STAND_WORK/headscale.log" >&2; return 1; }
    hs users create stand > /dev/null
}

# A reusable pre-auth key of the stand's user.
stand_key() {
    local uid
    uid="$(hs users list -o json | python3 -c 'import json,sys; print([u["id"] for u in json.load(sys.stdin) if u["name"]=="stand"][0])')"
    hs preauthkeys create --user "$uid" --reusable --expiration 24h
}

# An official node in its own namespace ts-<name>, on its own /24 to ts-inet (10.20.<n>.2), logged
# in with `key`. `n` must be unique per node (1-250).
stand_node() {
    local name="$1" n="$2" key="$3" ns="ts-$1" dir="$STAND_WORK/$1" i
    local env=(TS_DEBUG_ALWAYS_USE_DERP=1)
    if [ "$STAND_TLS" = 1 ]; then env+=(SSL_CERT_FILE="$STAND_CA"); else env+=(TS_DEBUG_USE_DERP_HTTP=1); fi
    ip netns del "$ns" 2> /dev/null || true
    ip netns add "$ns"
    STAND_NODES+=("$name")
    ip -n "$ns" link set lo up
    ip link add "${name}0" netns "$ns" type veth peer name "${name}0-i" netns "$STAND_INET"
    ip -n "$ns" addr add "10.20.$n.2/24" dev "${name}0"
    ip -n "$STAND_INET" addr add "10.20.$n.1/24" dev "${name}0-i"
    ip -n "$ns" link set "${name}0" up
    ip -n "$STAND_INET" link set "${name}0-i" up
    ip -n "$ns" route add default via "10.20.$n.1"
    mkdir -p "$dir"
    ip netns exec "$ns" env "${env[@]}" \
        "$STAND_BIN/tailscaled" --state="$dir/state" --socket="$dir/sock" --statedir="$dir" \
        --tun="ts$n" > "$dir/tailscaled.log" 2>&1 &
    STAND_PIDS+=($!)
    for i in $(seq 1 50); do [ -S "$dir/sock" ] && break; sleep 0.1; done
    ip netns exec "$ns" "$STAND_BIN/tailscale" --socket="$dir/sock" up --login-server "$STAND_CONTROL" \
        --authkey "$key" --hostname "$name" --accept-dns=false --timeout 30s
}

ts() { local name="$1"; shift; ip netns exec "ts-$name" "$STAND_BIN/tailscale" --socket="$STAND_WORK/$name/sock" "$@"; }

# The DERP region a node calls home, by its code ("stand" 999, "derper" 900), as the node sees it.
ts_relay() { ts "$1" status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["Relay"])'; }

# Stage B: makes a node call region `region` home (if it can reach it) - at once, not at the next
# netcheck.
ts_home() {
    ts "$1" debug force-prefer-derp "$2" > /dev/null
    ts "$1" debug restun > /dev/null
}

if [ "${STAND_SOURCED:-0}" = 1 ]; then
    return 0
fi

trap stand_down EXIT
if [ "$STAND_TLS" = 1 ]; then
    echo "== stand (stage B: TLS, the test CA, derper with a pin) in $STAND_WORK"
else
    echo "== stand (stage A: plain HTTP, embedded DERP) in $STAND_WORK"
fi
stand_up
KEY="$(stand_key)"
stand_node nas 1 "$KEY"
stand_node ref 2 "$KEY"
if [ "${1:-}" = selftest ]; then
    FAILED=0
    check() { local what="$1"; shift; if "$@" > /dev/null 2>&1; then echo "   ok    $what"; else echo "   FAIL  $what"; FAILED=1; fi; }
    within() { local end=$((SECONDS + $1)); shift; while :; do "$@" > /dev/null 2>&1 && return 0; [ $SECONDS -ge $end ] && return 1; sleep 0.2; done; }
    relay_is() { [ "$(ts_relay "$1")" = "$2" ]; }
    NAS_IP="$(ts nas ip -4)"
    check "the NAS has an address ($NAS_IP)" test -n "$NAS_IP"
    check "the reference phone sees the NAS" bash -c "ip netns exec ts-ref '$STAND_BIN/tailscale' --socket='$STAND_WORK/ref/sock' status | grep -q ' nas '"
    check "tailscale ping over DERP" bash -c "ip netns exec ts-ref '$STAND_BIN/tailscale' --socket='$STAND_WORK/ref/sock' ping -c 3 --until-direct=false nas | grep -q 'via DERP'"
    check "ICMP through the tunnels" ip netns exec ts-ref ping -c 2 -W 3 "$NAS_IP"
    if [ "$STAND_TLS" = 1 ]; then
        ts_home nas 999
        ts_home ref 900
        check "the NAS at home in region 999 (the test CA)" within 20 relay_is nas stand
        check "the reference phone in region 900 (the pin)" within 20 relay_is ref derper
        check "ICMP between the two regions" within 20 ip netns exec ts-ref ping -c 1 -W 2 "$NAS_IP"
    fi
    echo
    if [ $FAILED = 0 ]; then echo "stand selftest: all passed"; else echo "stand selftest: FAILURES"; tail -5 "$STAND_WORK/headscale.log"; fi
    exit $FAILED
fi
echo "stand is up; Ctrl+C tears it down"
sleep infinity
