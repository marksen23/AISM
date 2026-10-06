#!/usr/bin/env bash
# Prepares the cloud-fallback scenario (AISM-K3-04, AISM-K3-10): signed cloud test policy and a
# throw-away test CA + server certificate for the mock cloud provider (all generated at runtime).
#   conformance/tests/prepare_cloud_scenario.sh      -> run/policy-cloud/, run/tls/
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/run"
"$HERE/prepare_signed_policy.sh" "$HERE/testdata/policy.conformance-cloud.yaml" "$OUT" >/dev/null
rm -rf "$OUT/policy-cloud"; mv "$OUT/policy" "$OUT/policy-cloud"
"$HERE/prepare_signed_policy.sh" "$HERE/testdata/policy.conformance.yaml" "$OUT" >/dev/null   # restore default
mkdir -p "$OUT/tls"; cd "$OUT/tls"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=AISM Test CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout ca.key -out ca.pem 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=mock-cloud" -keyout server.key -out server.csr 2>/dev/null
printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:mock-cloud\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n" > ext.cnf
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile ext.cnf -out server.pem 2>/dev/null
rm -f server.csr ext.cnf ca.srl ca.key        # CA key not needed after signing
chmod 644 ca.pem server.pem server.key        # test-only key, readable by the mock container
echo "cloud scenario prepared: $OUT/policy-cloud, $OUT/tls"
