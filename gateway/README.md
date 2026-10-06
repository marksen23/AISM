# AISM governance gateway (S2) – prototype

Minimal but working implementation of the governance gateway described in
[`../AISM-Spezifikation.md`](../AISM-Spezifikation.md) §6.2. **Prototype – not production-ready.**

## What it does

| Function | Implementation | Spec reference |
|---|---|---|
| OpenAI-compatible API | `POST /v1/chat/completions` (JSON and SSE passthrough), `POST /v1/embeddings`, `GET /v1/models` (local models only unless `cloudEnabled`) | M-06 |
| Policy | loads `POLICY_PATH`, validates against `policy.schema.json` plus semantic checks (references, duplicate IDs/priorities, regexes, tool schemas); SHA-256 digest of the file bytes; reload on file change, the last valid policy stays active on errors | M-15, Policy-Format §6 |
| Policy signature | detached SSHSIG/Ed25519. One signature (`policy.yaml.sig`) is checked against `POLICY_ALLOWED_SIGNERS`. A bundle (`policy.yaml.sigs`) is checked against a quorum keyring (`keyring.yaml` next to that file, or `POLICY_KEYRING`): threshold (K3 default 2), distinct identities, validity window, revocation. Checked **before** schema validation. Unsigned, tampered, under-threshold, unknown, expired, revoked or rolled-back policies are refused; the active policy stays (`policy.load_failed`, `kept_active`) unless the new keyring revokes its signers. Keyring updates need a quorum of the previous ring and a monotonic version | S-11, Spez. §6.2.1 |
| Policy endpoint | `GET /aism/v1/policy` → `name`, `version`, `revision`, `digest`, `effective_from`, `signature` (`verified`, `required`, `signers`, `threshold`, fingerprints), `keyring` (version, signer ids and status) when a ring is loaded, `last_load_error` (no rule contents) | Spez. §6.2 |
| Confirmations | `GET /aism/v1/confirmations`, `POST /aism/v1/confirmations/{id}/approve|reject`: proxied to S3 with the caller's identity; result is demasked for the caller like a chat answer | S-03, Spez. §6.3.1 |
| Health | `GET /health` → 200 only with a valid policy, working PII detectors and an accepting audit sink | Spez. §6.2 |
| Fail-closed | no valid policy, a detector that cannot load, or (when `audit.failClosed` is set) a full audit queue or a faulted required sink → 503 for all requests; `defaults.decision/route/failMode` are schema constants. Audit entries are never dropped | M-12, PEP-3, S-02 |
| AuthN | client key (`api-key` identity source) as Bearer token; user identity from a forwarded HS256 JWT (`forwarded-jwt-hs256`, e.g. Open WebUI); **OIDC access tokens** (`oidc-bearer`): signature via the IdP JWKS (PyJWKClient, cached 300 s, RS/PS/ES/EdDSA only), `iss`/`aud`/`exp`/`sub` required, 30 s leeway, roles from the configured claim (e.g. `groups`); JWKS unreachable → 503 (fail-closed); no role → 403 (default deny) | PEP-1, S-01 |
| PII masking | regex, checksum (IBAN mod 97, Luhn), a German name gazetteer (`builtin:de-given` / `builtin:de-surnames` or `file:`) and NER (`spacy:<model>` or `gliner:<model>`); optional `ner.cascade` runs a heavier model only on suspicious sentences and unions the spans; overlap resolution (longest span, then higher data class); request-scoped reversible placeholders (`<EMAIL_1>`; same value → same placeholder) held in memory only | M-02, PEP-2 |
| Demasking | JSON and stream; in the stream a possible placeholder prefix (`<EMA…`) is held back until the next chunk, so placeholders split across chunks are restored; only for roles in `demaskFor`; `SECRET` is never demasked | PEP-10 |
| Routing | data class from detected entities/roles → first matching rule by priority; cloud models only if `cloudEnabled`, the rule mode is `local-with-cloud-fallback` and the provider is listed (otherwise 403 `egress_denied`) | M-04, PEP-4 |
| Tools | allowed tools per role/agent/data class are passed to S3 (`X-AISM-Allowed-Tools`); client `tools` not on the list are dropped; `tool_calls` in responses (JSON and stream) that are not allowlisted are removed (defense in depth; S3 enforces first) | M-07, M-08 |
| Trace context | W3C `traceparent` is continued (same trace ID, new span ID) or created; trace ID in every audit entry | S-10 |
| Audit | JSONL hash chain (`seq`, `prev_hash` = `sha256:` + SHA-256 of the previous raw line, genesis 64 zeros), continued after restart. Optional sinks from the policy: S3 Object Lock (compliance, per object) and syslog. Every N entries or T seconds an Ed25519 checkpoint (namespace `aism-audit`, keyring role `audit`, Merkle root) is signed and stored in the WORM sink. A bounded durable queue (`audit-queue.json`) is fsync'd with the line; a full queue or a faulted required sink returns 503. `GET /aism/v1/audit` reports depth and sink errors, not entries. Counts, rule IDs and hashes only – no plaintext PII | M-05, S-02 |
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

With Docker Compose the image is built from the repository root (`docker compose build governance-proxy`, see `Dockerfile`). That build does not install torch. The cascade stays off unless the policy sets `ner.cascade`.

Optional GLiNER cascade (not the reproducible image; wheels are not hash-locked):

```bash
pip install -r gateway/requirements.txt -r gateway/requirements-gliner.txt
# or: docker build --build-arg INSTALL_GLINER=1 -f gateway/Dockerfile .
```

`INSTALL_GLINER=1` prefetches `urchade/gliner_multi_pii-v1` into `HF_HOME=/opt/hf`. A policy that sets `ner.cascade` and cannot load the secondary model refuses to start (`/health` stays 503). A runtime failure of the secondary model returns 503 `pii_detector_unavailable` and does not answer with the fast-path spans alone. The commented example is in `policy/policy.example.yaml` (`minScore` 0.55; `listedGivenName` defaults to false).

| Variable | Default | Meaning |
|---|---|---|
| `POLICY_PATH` | `/etc/aism/policy/policy.yaml` | policy file; mount the directory read-only so that policy and `.sig`/`.sigs` change together |
| `POLICY_ALLOWED_SIGNERS` | – | single-signature trust anchor (`allowed_signers`); compose: `/etc/aism/trust/allowed_signers` |
| `POLICY_KEYRING` | `keyring.yaml` next to `allowed_signers`, if that file exists | quorum keyring; when set, it is the trust anchor (the policy cannot lower its threshold) |
| `POLICY_KEYRING_STATE` | `<dir of AUDIT_LOG_PATH>/keyring-state.json` when a keyring is used | last accepted ring (version, digest); rollback of the keyring fails closed |
| `POLICY_REQUIRE_SIGNATURE` | `true` if `POLICY_ALLOWED_SIGNERS` or a keyring is set, else `false` | refuse unsigned policies |
| `POLICY_SCHEMA_PATH` | `../policy/policy.schema.json` (image: `/app/policy.schema.json`) | JSON Schema |
| `LISTEN_PUBLIC` / `LISTEN_INTERNAL` | `0.0.0.0:8000` / `0.0.0.0:8001` | listeners |
| `UPSTREAM_ORCHESTRATOR` | `http://orchestrator:9000/v1` | S3 |
| `INTERNAL_TOKEN` | – | required for the internal API (empty → internal API returns 503) |
| `AUDIT_LOG_PATH` | policy `audit.sink.path` | audit JSONL; checkpoints, `audit-queue.json` and by default `keyring-state.json` sit next to it |
| `AUDIT_SIGNING_KEY` | – | OpenSSH Ed25519 private key for audit checkpoints. Must match the keyring member named by `integrity.checkpoint.signer` (role `audit`). Never commit it |
| `AISM_AUDIT_FAULT_INJECTION` | unset | `1` lets the object `{prefix}fault/block` mark the required sink down (conformance only) |
| `AISM_CA_BUNDLE` | – | additional CA file for outbound TLS (test CA); certificates are always verified |
| `POLICY_RELOAD_SECONDS` | `5` | polling interval for policy changes |
| secrets | – | referenced by the policy (`secretRef: env:…`), e.g. `AISM_UI_CLIENT_KEY`, `AISM_FORWARD_JWT_SECRET`, `AISM_CLOUD_API_KEY`, `AISM_AUDIT_S3_ACCESS_KEY`, `AISM_AUDIT_S3_SECRET_KEY` |

Unit tests: `python -m pytest gateway/tests` (58 tests, passing on 2026-10-06: masking round trip, IBAN checksum incl. IBAN followed by uppercase tokens, split placeholders in the stream, hash chain incl. restart and tamper detection, checkpoint forgery and truncation, queue fail-closed, syslog, RFC 3161 imprint, SigV4 known answer, policy semantics, traceparent, gazetteer pairs and context rules, Erika/Max Mustermann under the example policy, rejection of an absolute gazetteer path, cascade triggers, union plus stream demasking, fail-closed when the secondary model is missing or throws, signing (ssh-keygen interop, tamper, unknown signer, rollback, keep-active on reload) and OIDC (valid; expired, wrong `aud`/`iss`, rogue key, unknown `kid`, HS256, no `sub` rejected; JWKS down → 503)). The orchestrator stub has its own tests (`python -m pytest orchestrator/tests`, 7 tests). `tools/ci-local.sh unit` runs both.

The image installs `requirements.lock` (all dependencies with hashes) and is reproducible (see the main README, "Reproducible builds").

## Limitations (known)

- **Name detection is still the weak spot on the default path.** EMAIL, IBAN and SECRET masked recall is 1.0 on the synthetic German sets ([`../conformance/pii-eval/`](../conformance/pii-eval/README.md)). PERSON masked recall for the default (gazetteer with context preset `de`, plus `spacy:xx_ent_wiki_sm`, cascade off) is 0.703 on held-out v2 and 0.940 on the older v1 set. The optional cascade (same fast detectors, GLiNER only on suspicious sentences, `minScore` 0.55) reached 0.969 on v2 and 1.000 on the frozen v3 set, at a mean of about 49–55 ms/sentence because roughly 60% of those name-dense sentences triggered the secondary model. In-list given names without a cue can still leak (`listedGivenName` is off). Unioning keeps the fast model's false positives, so precision can sit below GLiNER-only. `lowConfidence` rarely fires on `xx_ent_wiki_sm`. The `INSTALL_GLINER` image is not hash-locked. Synthetic data is not real data – measure with your own.
- **Open WebUI's forwarded JWT has no `groups` claim**; group-based roles need an OIDC token. OIDC was tested only against a local test IdP (`conformance/tests/mock_idp.py`), not Keycloak/Entra ID. The JWKS fetch is synchronous in a worker thread (bounded by the 5 s timeout).
- Non-text content parts (images, files) are rejected (400).
- Signing: quorum keyring with rotation (§6.2.1 of the spec). No HSM, no transparency log. No OpenTelemetry export, no rate limit on the public API (tool rate limits are enforced in S3), no TLS termination (run behind a reverse proxy if needed).
- Audit WORM is a separate S3 process. Object Lock is enforced on that API only; do not publish the filer. The verifier does not check a TSA certificate chain and does not apply keyring validity windows to old checkpoints. An operator who holds the S3 credentials can add a new object version; they cannot delete a compliance-locked version, and a differing version fails verification. Syslog is a copy, not an integrity anchor. RFC 3161 witnessing is optional and never blocks a request.
- Placeholder tables live in process memory (single process; TTL 10 minutes as a safety net).
- Fail-closed is stricter than required: when a detector fails, local processing is also refused.
- Cloud egress forwards the policy tool definitions to the provider; whether this is acceptable is a policy decision not modelled yet.
