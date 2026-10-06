#!/bin/sh
# Entry point of the aism-runner container (compose.conformance.yml, profile "runner").
# Mints test credentials, then runs the suite. Extra args are passed to pytest.
set -eu
export AISM_USER_JWT="$(python3 - <<'PY'
import os, time, jwt
now = int(time.time())
print(jwt.encode({"sub": "conformance-user", "email": "runner@example.invalid", "name": "AISM Runner",
                  "role": "user", "groups": ["it-ops"], "iss": "open-webui", "iat": now, "exp": now + 3600},
                 os.environ["AISM_FORWARD_JWT_SECRET"], algorithm="HS256"))
PY
)"
if [ -n "${AISM_IDP_URL:-}" ]; then
  tok() { python3 -c "import json,sys,urllib.request;print(json.load(urllib.request.urlopen(sys.argv[1],timeout=10))['access_token'])" "$AISM_IDP_URL/token?$1"; }
  # assignments first (a failing $(...) inside `export` would be ignored)
  t_ok="$(tok 'sub=oidc-user&groups=it-ops')"
  t_exp="$(tok 'ttl=-120&groups=it-ops')"; t_aud="$(tok 'aud=other&groups=it-ops')"
  t_rogue="$(tok 'rogue=1&groups=it-ops')"; t_iss="$(tok 'iss=http://evil.example/realms/aism')"
  export AISM_OIDC_TOKEN="$t_ok" AISM_OIDC_NEGATIVE_TOKENS="$t_exp,$t_aud,$t_rogue,$t_iss"
fi
exec python3 -m pytest -q -p no:cacheprovider "$@"
