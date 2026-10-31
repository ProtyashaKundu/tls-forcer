#!/usr/bin/env bash
# Creates a throwaway CA plus one server cert per key type, all for localhost.
# The server loads several at once and presents whichever one fits the
# client's signature_algorithms.
set -euo pipefail
OUT=${1:-certs}
mkdir -p "$OUT" && cd "$OUT"

cat > leaf.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key 2>/dev/null
openssl req -x509 -new -key ca.key -subj "/CN=tls-forcer test CA" -days 365 -out ca.crt \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign"

leaf() {
  local name=$1; shift
  if ! openssl genpkey "$@" -out "$name.key" 2>/dev/null; then
    echo "skip $name (not supported by this OpenSSL)"; return; fi
  openssl req -new -key "$name.key" -subj "/CN=localhost" -out "$name.csr"
  openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 365 -extfile leaf.ext -out "$name.crt" 2>/dev/null
  rm "$name.csr"; echo "made $name.crt"
}

leaf ecdsa   -algorithm EC -pkeyopt ec_paramgen_curve:P-256
leaf ed25519 -algorithm ED25519
leaf rsa     -algorithm RSA -pkeyopt rsa_keygen_bits:2048
leaf mldsa65 -algorithm ML-DSA-65   # needs OpenSSL >= 3.5 (or oqsprovider)
