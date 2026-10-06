# AISM governance gateway (S2) – prototype

Minimal but working implementation of the governance gateway described in
[`../AISM-Spezifikation.md`](../AISM-Spezifikation.md) §6.2. **Prototype – not production-ready.**

## What it does

| Function | Implementation | Spec reference |
|---|---|---|
| OpenAI-compatible API | `POST /v1/chat/completions` (JSON and SSE passthrough), `POST /v1/embeddings`, `GET /v1/models` (local models only unless `cloudEnabled`) | M-06 |
| Policy | loads `POLICY_PATH`, validates against `policy.schema.json` plus semantic checks (references, duplicate IDs/priorities, regexes, tool schemas); SHA-256 digest of the file bytes; reload on file change, the last valid policy stays active on errors | M-15, Policy-Format §6 |
| Policy signature | detached SSHSIG/Ed25519 signature (`metadata.signature.method: ssh-sig`, `policy.yaml.sig`, namespace `aism-policy`) verified against `POLICY_ALLOWED_SIGNERS` (OpenSSH `allowed_signers`) **before** schema validation; unsigned, invalid-signature, unknown-signer or rollback (`effectiveFrom` older than active) policies are refused, the active policy is kept (`policy.load_failed` with `kept_active`); interoperable with `ssh-keygen -Y sign/verify` | S-11, Spez. §6.2.1 |
| Policy endpoint | `GET /aism/v1/policy` → `name`, `version`, `revision`, `digest`, `effective_from`, `signature` (`verified`, `required`, signer, key fingerprint), `last_load_error` (no rule contents) | Spez. §6.2 |
| Confirmations | `GET /aism/v1/confirmations`, `POST /aism/v1/confirmations/{id}/approve|reject`: proxied to S3 with the caller's identity; result is demasked for the caller like a chat answer | S-03, Spez. §6.3.1 |
| Health | `GET /health` → 200 only with a valid policy and working PII detectors | Spez. §6.2 |
| Fail-closed | no valid policy or a detector that cannot load → 503 for all requests; `defaults.decision/route/failMode` are schema constants | M-12, PEP-3 |
| AuthN | client key (`api-key` identity source) as Bearer token; user identity from a forwarded HS256 JWT (`forwarded-jwt-hs256`, e.g. Open WebUI); **OIDC access tokens** (`oidc-bearer`): signature via the IdP JWKS (PyJWKClient, cached 300 s, RS/PS/ES/EdDSA only), `iss`/`aud`/`exp`/`sub` required, 30 s leeway, roles from the configured claim (e.g. `groups`); JWKS unreachable → 503 (fail-closed); no role → 403 (default deny) | PEP-1, S-01 |
| PII masking | regex, checksum (IBAN mod 97, Luhn), a German name gazetteer (`builtin:de-given` / `builtin:de-surnames` or `file:`) and NER (`spacy:<model>` or `gliner:<model>`); overlap resolution (longest span, then higher data class); request-scoped reversible placeholders (`<EMAIL_1>`; same value → same placeholder) held in memory only | M-02, PEP-2 |
| Demasking | JSON and stream; in the stream a possible placeholder prefix (`<EMA…`) is held back until the next chunk, so placeholders split across chunks are restored; only for roles in `demaskFor`; `SECRET` is never demasked | PEP-10 |
| Routing | data class from detected entities/roles → first matching rule by priority; cloud models only if `cloudEnabled`, the rule mode is `local-with-cloud-fallback` and the provider is listed (otherwise 403 `egress_denied`) | M-04, PEP-4 |
| Tools | allowed tools per role/agent/data class are passed to S3 (`X-AISM-Allowed-Tools`); client `tools` not on the list are dropped; `tool_calls` in responses (JSON and stream) that are not allowlisted are removed (defense in depth; S3 enforces first) | M-07, M-08 |
| Trace context | W3C `traceparent` is continued (same trace ID, new span ID) or created; trace ID in every audit entry | S-10 |
| Audit | JSONL, one entry per event, `prev_hash` = `sha256:` + SHA-256 of the previous raw line (genesis: 64 zeros), continues the chain after restart; counts, rule IDs and hashes only – no plaintext PII; JWT `email`/`name` are never written | M-05, S-02 |
| Internal API (port 8001, `X-AISM-Internal-Token`) | `POST /internal/v1/mask` (tool results/RAG chunks, uses the request's placeholder table), `POST /internal/v1/audit` (S3 events: tool calls, RAG), `POST /internal/egress/v1/chat/completions` (policy-checked cloud egress: re-checks the payload for detectable PII, strips `X-AISM-*` headers, writes `egress.cloud` with `payload_sha256`) | PEP-7/8/9 |

## Run locally (no Docker)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r gateway/requirements.txt          # from the repository root
export POLICY_PATH=policy/policy.yaml POLICY_SCHEMA_PATH=policy/policy.schema.json \
       AUDIT_LOG_PATH=/tmp/aism-audit.jsonl INTERNAL_TOKEN=change-me \
       AISM_UI_CLIENT_KEY=change-me AISM_FORWARD_JWT_SECRET=change-me \
       UPSTREAM_ORCHESTRATOR=http://127.0.0.1:9000/v1 \
       LISTEN_PUBLIC=127.0.0.1:8000 LISTEN_INTERNAL=127.0.0.1:8001
cd gateway && python -m aism_gateway
```

With Docker Compose the image is built from the repository root (`docker compose build governance-proxy`, see `Dockerfile`).

| Variable | Default | Meaning |
|---|---|---|
| `POLICY_PATH` | `/etc/aism/policy/policy.yaml` | policy file; mount the directory read-only so that policy and `.sig` change together |
| `POLICY_ALLOWED_SIGNERS` | – | trust anchor (`allowed_signers`); compose: `/etc/aism/trust/allowed_signers` |
| `POLICY_REQUIRE_SIGNATURE` | `true` if `POLICY_ALLOWED_SIGNERS` is set, else `false` | refuse unsigned policies |
| `POLICY_SCHEMA_PATH` | `../policy/policy.schema.json` (image: `/app/policy.schema.json`) | JSON Schema |
| `LISTEN_PUBLIC` / `LISTEN_INTERNAL` | `0.0.0.0:8000` / `0.0.0.0:8001` | listeners |
| `UPSTREAM_ORCHESTRATOR` | `http://orchestrator:9000/v1` | S3 |
| `INTERNAL_TOKEN` | – | required for the internal API (empty → internal API returns 503) |
| `AUDIT_LOG_PATH` | policy `audit.sink.path` | audit JSONL |
| `AISM_CA_BUNDLE` | – | additional CA file for outbound TLS (test CA); certificates are always verified |
| `POLICY_RELOAD_SECONDS` | `5` | polling interval for policy changes |
| secrets | – | referenced by the policy (`secretRef: env:…`), e.g. `AISM_UI_CLIENT_KEY`, `AISM_FORWARD_JWT_SECRET`, `AISM_CLOUD_API_KEY` |

Unit tests: `python -m pytest gateway/tests` (33 tests, passing on 2026-10-06: masking round trip, IBAN checksum incl. IBAN followed by uppercase tokens, split placeholders in the stream, hash chain incl. restart and tamper detection, policy semantics, traceparent, gazetteer pairs and context rules, Erika/Max Mustermann under the example policy, rejection of an absolute gazetteer path, signing (ssh-keygen interop, tamper, unknown signer, rollback, keep-active on reload) and OIDC (valid; expired, wrong `aud`/`iss`, rogue key, unknown `kid`, HS256, no `sub` rejected; JWKS down → 503)). The orchestrator stub has its own tests (`python -m pytest orchestrator/tests`, 7 tests). `tools/ci-local.sh unit` runs both.

The image installs `requirements.lock` (all dependencies with hashes) and is reproducible (see the main README, "Reproducible builds").

## Limitations (known)

- **Name detection is still the weak spot.** EMAIL, IBAN and SECRET masked recall is 1.0 on the synthetic German sets ([`../conformance/pii-eval/`](../conformance/pii-eval/README.md)). PERSON masked recall for the default (gazetteer with context preset `de`, plus `spacy:xx_ent_wiki_sm`) is 0.70 on the fresh held-out set and 0.94 on the older, easier held-out set. In-vocabulary names and names after a strong cue are covered; out-of-vocabulary names in running text are not. spaCy still over-masks some capitalised sentence starts. `ner.minScore` applies to GLiNER only. Switching the policy to `gliner:urchade/gliner_multi_pii-v1` reached masked recall 1.00 on that fresh set at about 80 ms/sentence and is not the default. Synthetic data is not real data – measure with your own.
- **Open WebUI's forwarded JWT has no `groups` claim**; group-based roles need an OIDC token. OIDC was tested only against a local test IdP (`conformance/tests/mock_idp.py`), not Keycloak/Entra ID. The JWKS fetch is synchronous in a worker thread (bounded by the 5 s timeout).
- Non-text content parts (images, files) are rejected (400).
- Signing: one trust anchor file, no key rotation workflow, no multi-signature (four-eyes) requirement, no transparency log. No OpenTelemetry export, no rate limit on the public API (tool rate limits are enforced in S3), no TLS termination (run behind a reverse proxy if needed).
- Placeholder tables live in process memory (single process; TTL 10 minutes as a safety net).
- Fail-closed is stricter than required: when a detector fails, local processing is also refused.
- Cloud egress forwards the policy tool definitions to the provider; whether this is acceptable is a policy decision not modelled yet.
