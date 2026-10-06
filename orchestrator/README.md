# AISM orchestrator (S3) – minimal prototype

Exists so that the gateway prototype and the conformance suite can be run end to end
(tool loop, RAG query, trace propagation). **Not a production orchestrator.**

Implemented:

- Accepts requests only from the gateway (`X-AISM-Internal-Token`); reads the request context from `X-AISM-*` headers.
- Loads the same policy (schema-validated) and offers only the allowlisted tools (`X-AISM-Allowed-Tools`) to the model; client-defined tools are ignored.
- Policy: verifies that it uses the same policy as the gateway (`X-AISM-Policy-Digest`); unknown digest → 503 `policy_mismatch` (signature verification is done by the gateway; both mount the same read-only directory).
- Tool loop (JSON and stream, up to `maxToolRounds`): allowlist, JSON-Schema validation of the arguments, rate limit. Refused calls are answered with a `role: "tool"` message (`{"error":"tool_not_permitted"}`, `invalid_arguments`, `rate_limited`).
- **Confirmation flow** for write tools (`requireConfirmation`/`access: write`): the call is not executed; a pending action is stored (in memory, TTL `CONFIRMATION_TTL_SECONDS`, default 900) and the model gets `{"status":"pending_confirmation","confirmation_id":…}`. Internal endpoints (gateway only): `GET /internal/v1/confirmations`, `POST /internal/v1/confirmations/{id}/approve|reject`; only the same subject; foreign IDs → 404, second decision → 409, expired → `expired`. On approval the tool, roles, agent, data-class rank and argument schema are re-checked against the **current** policy, then executed once. Audit `tool.call.pending|confirmed|rejected`.
- **Web search** (PEP-6): built-in tool `web_search`, offered only if the gateway allows search for this request (`X-AISM-Web-Search: true`) and `SEARXNG_URL` is set. The query is masked via the gateway and remaining placeholders are stripped before `GET {SEARXNG_URL}/search?format=json`; results are masked and wrapped as `untrusted_web_results`; audit `egress.websearch` (query SHA-256, result count, engine host). Allowed calls go to `TOOL_GATEWAY_URL + target`; results are masked via the gateway (`/internal/v1/mask`), fail-closed if masking is unavailable. Audit events via `/internal/v1/audit`.
- RAG: if collections are allowed, the already-masked user message is embedded via `EMBEDDINGS_URL`; Qdrant is queried only if `QDRANT_URL` is set (payload filter on roles); chunks are re-masked before use.
- Cloud: explicit cloud routes and fallback on `local_unavailable` go **only** through the gateway egress endpoint (the gateway decides); a refused fallback (403 from the egress endpoint) becomes `503 upstream_unavailable` for the client. Tested in `conformance/tests/scenario_cloud_fallback.py` with the local model stopped.
- `traceparent` is forwarded with a new span ID on every outbound call.

Not implemented / limitations: pending confirmations are lost on restart and not shared between replicas; the stored arguments are the masked ones (the user may see placeholders when confirming); web-search permission is decided once per request from the incoming data class; Qdrant ingest, OpenTelemetry, streaming of tool-call deltas to the client.

Run: `cd orchestrator && python -m aism_orchestrator` (env: `POLICY_PATH`, `POLICY_SCHEMA_PATH`, `INFERENCE_LOCAL_URL`, `EMBEDDINGS_URL`, `QDRANT_URL`, `QDRANT_API_KEY`, `TOOL_GATEWAY_URL`, `N8N_WEBHOOK_TOKEN`, `GATEWAY_INTERNAL_URL`, `INTERNAL_TOKEN`, `SEARXNG_URL`, `CONFIRMATION_TTL_SECONDS`, `UPSTREAM_TIMEOUT_SECONDS`, `LISTEN`). Docker: built from the repository root via `orchestrator/Dockerfile`.
