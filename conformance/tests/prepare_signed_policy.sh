#!/usr/bin/env bash
# Prepares a SIGNED copy of the conformance test policy with throw-away test keys generated at runtime.
#
#   conformance/tests/prepare_signed_policy.sh [testdata/policy.conformance.yaml] [OUTDIR]
#
# K3 four-eyes: two Ed25519 keys and a quorum-signed keyring (policy threshold 2).
# Creates (default OUTDIR = conformance/tests/run):
#   run/policy/policy.yaml + policy.yaml.sigs   -> mount as /etc/aism/policy (read-only)
#   run/trust/keyring.yaml + keyring.yaml.sigs  -> mount as /etc/aism/trust (read-only)
#   run/trust/allowed_signers                   -> both public keys, legacy single-sig checks
#   run/keys/manifest                           -> "identity<TAB>relative-private-key" (test only)
#   run/keys/a , run/keys/b                     -> TEST private keys, 0600. Never commit them.
#                                                 delete after the run: rm -rf conformance/tests/run/keys
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
SRC="${1:-$HERE/testdata/policy.conformance.yaml}"
OUT="${2:-$HERE/run}"
PY="${PYTHON:-python3}"
SIGN="$REPO/tools/aism-policy-sign.py"
ID_A="aism-conformance-a@localhost"
ID_B="aism-conformance-b@localhost"
NB="2020-01-01T00:00:00Z"
NA="2100-01-01T00:00:00Z"
KA="$OUT/keys/a"
KB="$OUT/keys/b"
mkdir -p "$OUT/policy" "$OUT/trust" "$OUT/keys"
chmod 700 "$OUT/keys"
[ -f "$KA/policy-signing.key" ] || "$PY" "$SIGN" keygen --out "$KA" --identity "$ID_A"
[ -f "$KB/policy-signing.key" ] || "$PY" "$SIGN" keygen --out "$KB" --identity "$ID_B"
member() {
  printf 'id=%s,pub=%s,roles=policy+keyring,not-before=%s,not-after=%s' "$1" "$2" "$NB" "$NA"
}
if [ ! -f "$OUT/trust/keyring.yaml" ]; then
  "$PY" "$SIGN" init-keyring --out "$OUT/trust/keyring.yaml" \
    --keyring-threshold 2 --policy-threshold 2 \
    --member "$(member "$ID_A" "$KA/policy-signing.key.pub")" \
    --member "$(member "$ID_B" "$KB/policy-signing.key.pub")" \
    --sign "$KA/policy-signing.key=$ID_A" \
    --sign "$KB/policy-signing.key=$ID_B"
fi
cat "$KA/allowed_signers" "$KB/allowed_signers" > "$OUT/trust/allowed_signers"
printf '%s\t%s\n%s\t%s\n' "$ID_A" "a/policy-signing.key" "$ID_B" "b/policy-signing.key" > "$OUT/keys/manifest"
cp "$SRC" "$OUT/policy/policy.yaml"
"$PY" "$SIGN" sign --keyring "$OUT/trust/keyring.yaml" --key "$KA/policy-signing.key" --identity "$ID_A" "$OUT/policy/policy.yaml"
"$PY" "$SIGN" sign --keyring "$OUT/trust/keyring.yaml" --key "$KB/policy-signing.key" --identity "$ID_B" "$OUT/policy/policy.yaml"
"$PY" "$SIGN" verify --keyring "$OUT/trust/keyring.yaml" "$OUT/policy/policy.yaml"
# container user (uid 10001) must be able to read the mounted files; private keys stay 0600
chmod 755 "$OUT" "$OUT/policy" "$OUT/trust" "$OUT/keys"
chmod 644 "$OUT/policy/"* "$OUT/trust/"* "$OUT/keys/manifest"
chmod 700 "$KA" "$KB"
chmod 600 "$KA/policy-signing.key" "$KB/policy-signing.key"
