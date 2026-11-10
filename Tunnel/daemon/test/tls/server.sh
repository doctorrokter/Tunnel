#!/usr/bin/env bash
#
# openssl s_server for test_tls: one certificate setup of the test PKI (certs.sh) on a loopback port.
#
#   server.sh <certdir> <kind> <port> <4|6> [more s_server flags...]
#
#   good        server.pem (server.test, *.wild.test, w*.part.test, 127.0.0.1, ::1) + the intermediate
#   expired     expired.pem (the same names, January 2020) + the intermediate
#   cnonly      cnonly.pem (CN=cnonly.test, no SAN) + the intermediate
#   self        self.pem: self-signed, self.test and alt.test, no IP
#   self_meta   self.pem + derper's kind of meta certificate after it (CN=derpkey..., Ed25519)
#   self_extra  self.pem + the intermediate: two certificates where a pin allows one
#   self_sni    self.pem, and a fatal alert when the SNI is there and is not self.test
#
# The script becomes s_server (exec): the pid the test holds is the server's. With -quiet, stdout
# carries exactly what the client sent and stdin is sent to the client; -no_ign_eof makes the end
# of stdin close the connection (close_notify). By hand, for a look:
#   server.sh <certdir> good 4433 4        and    openssl s_client -connect 127.0.0.1:4433
set -euo pipefail

D="$1"
KIND="$2"
PORT="$3"
FAMILY="$4"
shift 4

if [ "$FAMILY" = 6 ]; then ACCEPT="[::1]:$PORT"; else ACCEPT="127.0.0.1:$PORT"; fi

case "$KIND" in
    good)       ARGS=(-cert "$D/server.pem" -key "$D/server.key" -cert_chain "$D/inter.pem") ;;
    expired)    ARGS=(-cert "$D/expired.pem" -key "$D/server.key" -cert_chain "$D/inter.pem") ;;
    cnonly)     ARGS=(-cert "$D/cnonly.pem" -key "$D/server.key" -cert_chain "$D/inter.pem") ;;
    self)       ARGS=(-cert "$D/self.pem" -key "$D/self.key") ;;
    self_meta)  ARGS=(-cert "$D/self.pem" -key "$D/self.key" -cert_chain "$D/meta.pem") ;;
    self_extra) ARGS=(-cert "$D/self.pem" -key "$D/self.key" -cert_chain "$D/inter.pem") ;;
    self_sni)   ARGS=(-cert "$D/self.pem" -key "$D/self.key" -servername self.test -servername_fatal
                      -cert2 "$D/self.pem" -key2 "$D/self.key") ;;
    *)          echo "server.sh: no such kind: $KIND" >&2; exit 2 ;;
esac

exec openssl s_server -accept "$ACCEPT" "${ARGS[@]}" "$@"
