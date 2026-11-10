#!/usr/bin/env bash
#
# The test PKI for test_tls, made fresh on every run: one certificate has to be expired, the rest
# valid, and dates move.
#
#   certs.sh <out-dir>          (emptied first)
#
#   root.pem / root.key       "bbtunnel test root" - what the client is told to trust (a CA file)
#   inter.pem / inter.key     an intermediate under it; the servers send it, as Let's Encrypt's do
#   server.pem / server.key   by the intermediate: server.test, *.wild.test, w*.part.test (a partial
#                             wildcard, which Go never honours), 127.0.0.1, ::1
#   expired.pem               the same names and key, valid in January 2020 only
#   cnonly.pem                by the intermediate: CN=cnonly.test and no SAN at all (neither Go nor
#                             bt_tls falls back to the CN)
#   self.pem / self.key       self-signed: self.test and alt.test, no IP - the kind a stand derper has
#   meta.pem / meta.key       derper's meta certificate: CN=derpkey<hex>, Ed25519, self-signed (64
#                             characters of CN - the most openssl will write; derper's has 71)
#   self.pin, server.pin, expired.pin
#                             sha256-raw:<hex> of those certificates - by openssl and sha256sum, not
#                             by the code under test
#
# Everything EC P-256 but the meta certificate. Quiet unless something fails.
set -euo pipefail

OUT="${1:?usage: certs.sh <out-dir>}"
rm -rf "$OUT"
mkdir -p "$OUT"
cd "$OUT"

cat > openssl.cnf <<'EOF'
[ req ]
distinguished_name  = dn
prompt              = no
[ dn ]
CN                  = unused

[ v3_root ]
basicConstraints        = critical, CA:TRUE
keyUsage                = critical, keyCertSign, cRLSign
subjectKeyIdentifier    = hash

[ v3_inter ]
basicConstraints        = critical, CA:TRUE, pathlen:0
keyUsage                = critical, keyCertSign, cRLSign
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid

[ v3_server ]
basicConstraints        = critical, CA:FALSE
keyUsage                = critical, digitalSignature
extendedKeyUsage        = serverAuth
subjectAltName          = DNS:server.test, DNS:*.wild.test, DNS:w*.part.test, IP:127.0.0.1, IP:::1
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid

[ v3_cnonly ]
basicConstraints        = critical, CA:FALSE
keyUsage                = critical, digitalSignature
extendedKeyUsage        = serverAuth

[ v3_self ]
basicConstraints        = critical, CA:FALSE
keyUsage                = critical, digitalSignature
extendedKeyUsage        = serverAuth
subjectAltName          = DNS:self.test, DNS:alt.test

[ v3_meta ]
basicConstraints        = critical, CA:FALSE

# `openssl ca` only for the expired certificate: it alone can set dates in the past
[ ca ]
default_ca          = expiring
[ expiring ]
dir                 = .
database            = ./ca.index
new_certs_dir       = .
serial              = ./ca.serial
certificate         = ./inter.pem
private_key         = ./inter.key
default_md          = sha256
policy              = anything
unique_subject      = no
copy_extensions     = none
[ anything ]
commonName          = supplied
EOF

ec_key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2> /dev/null; }
csr() { openssl req -new -config openssl.cnf -key "$1" -subj "$2" -out "$3"; }
pin() { printf 'sha256-raw:%s\n' "$(openssl x509 -in "$1" -outform DER | sha256sum | cut -d' ' -f1)" > "$2"; }

ec_key root.key
openssl req -x509 -new -config openssl.cnf -key root.key -subj "/CN=bbtunnel test root" -days 3650 \
    -extensions v3_root -out root.pem

ec_key inter.key
csr inter.key "/CN=bbtunnel test intermediate" inter.csr
openssl x509 -req -in inter.csr -CA root.pem -CAkey root.key -CAcreateserial -days 3650 \
    -extfile openssl.cnf -extensions v3_inter -out inter.pem 2> /dev/null

ec_key server.key
csr server.key "/CN=server.test" server.csr
openssl x509 -req -in server.csr -CA inter.pem -CAkey inter.key -CAcreateserial -days 30 \
    -extfile openssl.cnf -extensions v3_server -out server.pem 2> /dev/null

: > ca.index
echo 1000 > ca.serial
openssl ca -batch -config openssl.cnf -in server.csr -out expired.pem -notext \
    -startdate 20200101000000Z -enddate 20200131000000Z -extfile openssl.cnf -extensions v3_server 2> /dev/null

csr server.key "/CN=cnonly.test" cnonly.csr
openssl x509 -req -in cnonly.csr -CA inter.pem -CAkey inter.key -CAcreateserial -days 30 \
    -extfile openssl.cnf -extensions v3_cnonly -out cnonly.pem 2> /dev/null

ec_key self.key
csr self.key "/CN=self.test" self.csr
openssl x509 -req -in self.csr -key self.key -days 30 -extfile openssl.cnf -extensions v3_self \
    -out self.pem 2> /dev/null

openssl genpkey -algorithm ED25519 -out meta.key
openssl req -x509 -new -config openssl.cnf -key meta.key -subj "/CN=derpkey$(openssl rand -hex 29 | cut -c1-57)" \
    -days 30 -extensions v3_meta -out meta.pem

pin self.pem self.pin
pin server.pem server.pin
pin expired.pem expired.pin

# The PKI is what the tests think it is, or nothing runs on it.
openssl verify -CAfile root.pem -untrusted inter.pem server.pem > /dev/null
openssl verify -CAfile root.pem -untrusted inter.pem cnonly.pem > /dev/null
! openssl verify -CAfile root.pem -untrusted inter.pem expired.pem > /dev/null 2>&1
