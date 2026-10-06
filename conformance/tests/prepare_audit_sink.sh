#!/usr/bin/env bash
# Runtime S3 credentials for the conformance WORM sink. Nothing here is committed.
# Reads AISM_AUDIT_S3_ACCESS_KEY and AISM_AUDIT_S3_SECRET_KEY from the environment or .env.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
if [[ -f "$ROOT/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT/.env"
  set +a
fi
: "${AISM_AUDIT_S3_ACCESS_KEY:?AISM_AUDIT_S3_ACCESS_KEY is not set}"
: "${AISM_AUDIT_S3_SECRET_KEY:?AISM_AUDIT_S3_SECRET_KEY is not set}"
OUT="$HERE/run/seaweed"
mkdir -p "$OUT"
umask 077
python3 - "$OUT/s3.json" <<'PY'
import json, os, pathlib, sys
path = pathlib.Path(sys.argv[1])
doc = {
    "identities": [{
        "name": "aism-audit",
        "credentials": [{
            "accessKey": os.environ["AISM_AUDIT_S3_ACCESS_KEY"],
            "secretKey": os.environ["AISM_AUDIT_S3_SECRET_KEY"],
        }],
        "actions": ["Admin", "Read", "Write", "List", "Tagging"],
    }]
}
path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
PY
chmod 644 "$OUT/s3.json"
echo "audit sink config: $OUT/s3.json (not committed)"
