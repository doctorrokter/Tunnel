#!/bin/sh
#
# Tunnel's AmneziaWG test servers (README.md beside this file), inside amneziavpn/amneziawg-go - the
# reference the engine is checked against (engine/test/interop/run_awg.sh). Two of them:
#
#   awg0  AmneziaWG 2.0: S1-S4, H1-H4 as ranges - UDP 41820, the tunnel 10.77.0.0/24
#   awg1  AmneziaWG 3.1 as AmneziaVPN's installer sets it today (header protection, random trailers,
#         the timers as ranges, its DNS-looking I1) - UDP 41821, the tunnel 10.78.0.0/24
#
# The first start makes the keys and the configs in CONFIG_DIR (/config): the servers' (0600) and four
# for the phone (0644 - a NAS's own File Station reads them; the folder is the admin's), each server
# with only the tunnel's addresses and with all traffic. Later starts reuse them; delete the folder's
# files for new keys. The phone's Endpoint is SERVER_IP. amneziawg-go in userspace (no kernel
# module for AmneziaWG), NAT through OUT_IF (eth0) for the full tunnels - a NAT that does not go in is
# said in the log, and the servers come up without it. Stops cleanly on TERM.

set -eu

: "${SERVER_IP:?set SERVER_IP (this machine's address in the home network)}"
CONFIG_DIR="${CONFIG_DIR:-/config}"
OUT_IF="${OUT_IF:-eth0}"
cd "$CONFIG_DIR"
umask 077
# A NAS's kernel may have no nf_tables: the legacy iptables when there is one.
IPT=$(command -v iptables-legacy || command -v iptables || true)
[ -n "$IPT" ] || { echo "no iptables: the full tunnels need NAT" >&2; exit 1; }

if [ ! -f awg0.conf ] || [ ! -f awg1.conf ]; then
    echo "first start: new keys and configs in $CONFIG_DIR"
    for n in srv2 phone2 srv3 phone3; do
        awg genkey > "$n.key"
        awg pubkey < "$n.key" > "$n.pub"
    done
    awg genpsk > psk2
    awg genpsk > psk3
    awg genkey > hp3.key

    # ---- AmneziaWG 2.0. Shared by both sides: S1-S4, H1-H4; Jc/Jmin/Jmax and I1 are each side's own.
    shared2="S1 = 24
S2 = 32
S3 = 16
S4 = 20
H1 = 100000-100999
H2 = 200000-200999
H3 = 300000-300999
H4 = 400000-499999"

    cat > awg0.conf << EOF
[Interface]
PrivateKey = $(cat srv2.key)
Address = 10.77.0.1/24
ListenPort = 41820
MTU = 1280
Jc = 3
Jmin = 30
Jmax = 60
$shared2
PostUp = $IPT -t nat -A POSTROUTING -s 10.77.0.0/24 -o $OUT_IF -j MASQUERADE || echo "no NAT: only 10.77.0.0/24 itself works"
PostDown = $IPT -t nat -D POSTROUTING -s 10.77.0.0/24 -o $OUT_IF -j MASQUERADE || true

[Peer]
PublicKey = $(cat phone2.pub)
PresharedKey = $(cat psk2)
AllowedIPs = 10.77.0.2/32
EOF

    phone2() {
        cat << EOF
[Interface]
PrivateKey = $(cat phone2.key)
Address = 10.77.0.2/32
MTU = 1280
$1
Jc = 5
Jmin = 10
Jmax = 50
$shared2
I1 = <b 0xc70000000108ce1bfe8e8c5a0f2a><r 32><t>

[Peer]
PublicKey = $(cat srv2.pub)
PresharedKey = $(cat psk2)
Endpoint = $SERVER_IP:41820
AllowedIPs = $2
PersistentKeepalive = 25
EOF
    }

    # ---- AmneziaWG 3.1 as AmneziaVPN's installer writes it (amnezia-client, awgInstaller.cpp). Shared:
    # S1-S4, H1-H4, the header protection key, random trailers; the timers and the junk are each side's.
    shared3="S1 = 12
S2 = 12
S3 = 12
S4 = 12
H1 = 1
H2 = 2
H3 = 3
H4 = 4
HeaderProtectionKey = $(cat hp3.key)
RandomTrailers = on"
    timers3="RekeyAfterTime = 100-120
RekeyTimeout = 3-7
RejectAfterTime = 150-180
KeepaliveTimeout = 5-15
MaxHandshakeAttempts = 15-20
DisableCookies = on"

    cat > awg1.conf << EOF
[Interface]
PrivateKey = $(cat srv3.key)
Address = 10.78.0.1/24
ListenPort = 41821
MTU = 1280
Jc = 4
Jmin = 10
Jmax = 50
$shared3
$timers3
PostUp = $IPT -t nat -A POSTROUTING -s 10.78.0.0/24 -o $OUT_IF -j MASQUERADE || echo "no NAT: only 10.78.0.0/24 itself works"
PostDown = $IPT -t nat -D POSTROUTING -s 10.78.0.0/24 -o $OUT_IF -j MASQUERADE || true

[Peer]
PublicKey = $(cat phone3.pub)
PresharedKey = $(cat psk3)
AllowedIPs = 10.78.0.2/32
EOF

    phone3() {
        cat << EOF
[Interface]
PrivateKey = $(cat phone3.key)
Address = 10.78.0.2/32
MTU = 1280
$1
Jc = 4
Jmin = 10
Jmax = 50
$shared3
$timers3
ContentPaddingAddition = 10-100
I1 = <r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>

[Peer]
PublicKey = $(cat srv3.pub)
PresharedKey = $(cat psk3)
Endpoint = $SERVER_IP:41821
AllowedIPs = $2
PersistentKeepalive = 25-35
EOF
    }

    # Only the tunnel's addresses (the protocol alone), and all traffic through the server (the data path).
    phone2 "" "10.77.0.0/24" > phone-awg2.conf
    phone2 "DNS = 1.1.1.1" "0.0.0.0/0" > phone-awg2-full.conf
    phone3 "" "10.78.0.0/24" > phone-awg3.conf
    phone3 "DNS = 1.1.1.1" "0.0.0.0/0" > phone-awg3-full.conf
    chmod 644 phone-awg2.conf phone-awg2-full.conf phone-awg3.conf phone-awg3-full.conf
fi

down() {
    awg-quick down "$CONFIG_DIR/awg0.conf" > /dev/null 2>&1 || true
    awg-quick down "$CONFIG_DIR/awg1.conf" > /dev/null 2>&1 || true
}
# A container stopped while it is up: the interfaces and the NAT rules go first.
trap 'down; exit 0' TERM INT
# Left over from a start that did not finish (the container restarted): gone before going up.
down
awg-quick up "$CONFIG_DIR/awg0.conf"
awg-quick up "$CONFIG_DIR/awg1.conf"
echo "up: awg0 (AmneziaWG 2.0) on UDP 41820, awg1 (AmneziaWG 3.1) on UDP 41821; the phone's configs in $CONFIG_DIR"
# The peers' handshakes and traffic: `awg show` in the container (it shows no private keys).
while :; do
    sleep 3600 &
    wait $! || true
done
