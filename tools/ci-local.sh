#!/usr/bin/env bash
# Local equivalent of .github/workflows/ci.yml.
#   tools/ci-local.sh lint|unit|policy|signature|pii|pii-cascade|repro|conformance|all
# pii-cascade needs the optional GLiNER install (gateway/requirements-gliner.txt) and is not part of "all".
# Never writes a signing key into the repository. Conformance and repro need Docker.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
STEP="${1:-all}"

lint() {
  python3 -m ruff check gateway orchestrator tools conformance
}

unit() {
  python3 -m pytest -q --import-mode=importlib gateway/tests orchestrator/tests
}

policy() {
  python3 tools/validate_policy.py \
    policy/policy.example.yaml \
    conformance/tests/testdata/policy.conformance.yaml \
    conformance/tests/testdata/policy.conformance-cloud.yaml
}

signature() {
  local tmp
  tmp="$(mktemp -d)"
  cp policy/policy.example.yaml "$tmp/policy.yaml"
  python3 tools/aism-policy-sign.py keygen --out "$tmp/keys" --identity ci@example.invalid
  python3 tools/aism-policy-sign.py sign --key "$tmp/keys/policy-signing.key" \
    --identity ci@example.invalid --revision ci-test "$tmp/policy.yaml"
  python3 tools/aism-policy-sign.py verify --allowed-signers "$tmp/keys/allowed_signers" "$tmp/policy.yaml"
  printf '\n# tamper\n' >> "$tmp/policy.yaml"
  if python3 tools/aism-policy-sign.py verify --allowed-signers "$tmp/keys/allowed_signers" "$tmp/policy.yaml"; then
    rm -rf "$tmp"
    echo "FAIL: tampered policy was accepted" >&2
    exit 1
  fi
  rm -rf "$tmp"
  echo "signature OK (runtime key deleted; tamper rejected)"
}

pii() {
  local out="${AISM_PII_OUT:-conformance/pii-eval/results-ci.json}"
  python3 conformance/pii-eval/evaluate.py \
    --data conformance/pii-eval/pii_eval_de_heldout_v2.jsonl \
    --profile policy \
    --gate conformance/pii-eval/gate.json \
    --no-misses \
    --out "$out"
}

pii_cascade() {
  # Separate from pii(): torch is not in the default image or the default CI job.
  # Held-out v3 is frozen; the checksum fails the job if the file changes.
  (
    cd conformance/pii-eval
    sha256sum -c pii_eval_de_heldout_v3.sha256
  )
  python3 conformance/pii-eval/evaluate.py \
    --data conformance/pii-eval/pii_eval_de_heldout_v2.jsonl \
    --profile cascade \
    --gate conformance/pii-eval/gate-cascade-v2.json \
    --no-misses \
    --out conformance/pii-eval/results-ci-cascade-v2.json
  python3 conformance/pii-eval/evaluate.py \
    --data conformance/pii-eval/pii_eval_de_heldout_v3.jsonl \
    --profile cascade \
    --gate conformance/pii-eval/gate-cascade-v3.json \
    --no-misses \
    --out conformance/pii-eval/results-ci-cascade-v3.json
}

repro() {
  if ! docker buildx inspect aism-repro >/dev/null 2>&1; then
    docker buildx create --name aism-repro --driver docker-container
  fi
  tools/repro_build.sh gateway
  tools/repro_build.sh orchestrator
}

_ensure_env() {
  if [[ -f .env ]]; then
    return 0
  fi
  umask 077
  local v
  for v in AISM_UI_CLIENT_KEY AISM_FORWARD_JWT_SECRET AISM_INTERNAL_TOKEN \
           AISM_QDRANT_API_KEY AISM_N8N_WEBHOOK_TOKEN AISM_SEARXNG_SECRET; do
    printf '%s=%s\n' "$v" "$(openssl rand -hex 32)"
  done > .env
  chmod 600 .env
  echo "wrote .env with runtime secrets (not committed)"
}

_wait_health() {
  python3 - <<'PY'
import time
import urllib.error
import urllib.request

url = "http://127.0.0.1:8000/health"
last = "no attempt"
for i in range(60):
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:
            if resp.status == 200:
                print("gateway /health 200")
                raise SystemExit(0)
            last = f"status {resp.status}"
    except Exception as exc:  # noqa: BLE001 — wait loop
        last = f"{exc.__class__.__name__}: {exc}"
    print(f"wait {i}: {last}")
    time.sleep(3)
raise SystemExit(f"gateway /health did not become ready ({last})")
PY
}

_require_k3() {
  python3 - <<'PY'
import json
import pathlib
import sys

path = pathlib.Path("conformance/reports/ci/aism-report.json")
report = json.loads(path.read_text(encoding="utf-8"))
summary = report["summary"]
print(f"achieved_level={report.get('achieved_level')} summary={summary}")
ok = report.get("achieved_level") == "K3" and summary.get("failed") == 0 and summary.get("skipped") == 0
sys.exit(0 if ok else 1)
PY
}

conformance() {
  _ensure_env
  bash conformance/tests/prepare_cloud_scenario.sh
  # Globals: the EXIT trap runs after this function returns (locals would already be gone).
  COMPOSE_C=(docker compose -f docker-compose.yml -f conformance/tests/compose.conformance.yml)
  COMPOSE_CL=("${COMPOSE_C[@]}" -f conformance/tests/compose.cloud-fallback.yml)
  mkdir -p conformance/reports/ci
  cleanup() {
    "${COMPOSE_CL[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    "${COMPOSE_C[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  }
  trap cleanup EXIT

  # Cloud-fallback first, on the same audit volume the full run will read (K3-04).
  "${COMPOSE_CL[@]}" up -d --build governance-proxy orchestrator aism-mock mock-cloud llama-mock mock-idp
  "${COMPOSE_CL[@]}" stop llama-mock
  _wait_health
  "${COMPOSE_CL[@]}" --profile runner run --rm \
    -e AISM_REPORT=/repo/conformance/reports/ci/cloud-fallback.json \
    aism-runner \
    scenario_cloud_fallback.py test_k3_sovereign.py test_k2_governed.py \
    -k "fallback or audit or egress"
  "${COMPOSE_CL[@]}" down

  "${COMPOSE_C[@]}" up -d --build governance-proxy orchestrator aism-mock mock-idp
  _wait_health
  "${COMPOSE_C[@]}" --profile runner run --rm \
    -e AISM_REPORT=/repo/conformance/reports/ci/aism-report.json \
    aism-runner
  _require_k3
}

case "$STEP" in
  lint) lint ;;
  unit) unit ;;
  policy) policy ;;
  signature) signature ;;
  pii) pii ;;
  pii-cascade) pii_cascade ;;
  repro) repro ;;
  conformance) conformance ;;
  all)
    lint
    unit
    policy
    signature
    pii
    repro
    conformance
    ;;
  *)
    echo "usage: tools/ci-local.sh lint|unit|policy|signature|pii|pii-cascade|repro|conformance|all" >&2
    exit 2
    ;;
esac
