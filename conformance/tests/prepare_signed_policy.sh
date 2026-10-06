#!/usr/bin/env bash
# Prepares a SIGNED copy of the conformance test policy with a throw-away test key generated at runtime.
#
#   conformance/tests/prepare_signed_policy.sh [testdata/policy.conformance.yaml] [OUTDIR]
#
# Creates (default OUTDIR = conformance/tests/run):
#   run/policy/policy.yaml + policy.yaml.sig   -> mount as /etc/aism/policy (read-only)
#   run/trust/allowed_signers                  -> mount as /etc/aism/trust (read-only), POLICY_ALLOWED_SIGNERS
#   run/keys/policy-signing.key                -> TEST private key, 0600. Never commit/package it (.gitignore'd);
#                                                 delete it after the run: rm -rf conformance/tests/run/keys
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
SRC="${1:-$HERE/testdata/policy.conformance.yaml}"
OUT="${2:-$HERE/run}"
PY="${PYTHON:-python3}"
ID="aism-conformance-test@localhost"
mkdir -p "$OUT/policy" "$OUT/trust" "$OUT/keys"
chmod 700 "$OUT/keys"
[ -f "$OUT/keys/policy-signing.key" ] || "$PY" "$REPO/tools/aism-policy-sign.py" keygen --out "$OUT/keys" --identity "$ID"
cp "$OUT/keys/allowed_signers" "$OUT/trust/allowed_signers"
cp "$SRC" "$OUT/policy/policy.yaml"
"$PY" "$REPO/tools/aism-policy-sign.py" sign --key "$OUT/keys/policy-signing.key" --identity "$ID" "$OUT/policy/policy.yaml"
"$PY" "$REPO/tools/aism-policy-sign.py" verify --allowed-signers "$OUT/trust/allowed_signers" "$OUT/policy/policy.yaml"
# container user (uid 10001) must be able to read the mounted files
chmod 755 "$OUT" "$OUT/policy" "$OUT/trust"; chmod 644 "$OUT/policy/"* "$OUT/trust/allowed_signers"
