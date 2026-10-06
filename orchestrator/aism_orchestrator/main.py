"""AISM orchestrator stub (S3) – minimal, for the gateway prototype and the conformance suite.

Implements (Spez. §6.3): tool injection from the policy, tool loop with allowlist / JSON-Schema /
rate-limit / confirmation checks, tool-result masking via the gateway internal API (PEP-8),
RAG embedding call with the already-masked query (PEP-5), web search via SearXNG as built-in tool
`web_search` (PEP-6, only if the gateway allows it for this request; query masked + placeholders
stripped; results masked), human-in-the-loop confirmation for write tools (pending state, approve/
reject via the gateway's /aism/v1/confirmations API), traceparent propagation, cloud fallback only
via the gateway egress endpoint (PEP-9). Policy binding: S3 only uses the policy whose digest the
gateway (which verifies the signature) announces in X-AISM-Policy-Digest.
NOT implemented: OpenTelemetry export, client-defined tools (ignored), persistent pending store
(in memory, lost on restart). Not production-ready.
"""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
import urllib.parse

import httpx
import jsonschema
import yaml
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

log = logging.getLogger("aism.orchestrator")

POLICY_PATH = os.environ.get("POLICY_PATH", "/etc/aism/policy.yaml")
SCHEMA_PATH = os.environ.get("POLICY_SCHEMA_PATH",
                             os.path.join(os.path.dirname(__file__), "..", "..", "policy", "policy.schema.json"))
INFERENCE = os.environ.get("INFERENCE_LOCAL_URL", "http://llama-server:8080/v1").rstrip("/")
EMBEDDINGS = os.environ.get("EMBEDDINGS_URL", "").rstrip("/")
QDRANT = os.environ.get("QDRANT_URL", "").rstrip("/")
QDRANT_KEY = os.environ.get("QDRANT_API_KEY", "")
TOOL_GW = os.environ.get("TOOL_GATEWAY_URL", "").rstrip("/")
N8N_TOKEN = os.environ.get("N8N_WEBHOOK_TOKEN", "")
GW_INTERNAL = os.environ.get("GATEWAY_INTERNAL_URL", "http://governance-proxy:8001").rstrip("/")
INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "")
TIMEOUT = float(os.environ.get("UPSTREAM_TIMEOUT_SECONDS", "120"))
SEARXNG = os.environ.get("SEARXNG_URL", "").rstrip("/")
CONFIRM_TTL = float(os.environ.get("CONFIRMATION_TTL_SECONDS", "900"))
WEB_TOOL = "web_search"
PLACEHOLDER_RE = re.compile(r"<[A-Z][A-Z0-9_]*_\d+>")


class St:
    policy: dict | None = None
    digest: str | None = None
    mtime: float = 0
    by_digest: dict[str, dict] = {}
    http: httpx.AsyncClient | None = None
    rate: dict = {}
    pending: dict[str, dict] = {}


S = St()


def load_policy() -> dict | None:
    try:
        mtime = os.stat(POLICY_PATH).st_mtime
        if S.policy is not None and mtime == S.mtime:
            return S.policy
        data = open(POLICY_PATH, "rb").read()
        raw = yaml.safe_load(data)
        schema = json.load(open(SCHEMA_PATH, encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(raw)
        S.policy, S.mtime = raw, mtime
        S.digest = "sha256:" + hashlib.sha256(data).hexdigest()
        S.by_digest[S.digest] = raw
        while len(S.by_digest) > 5:
            S.by_digest.pop(next(iter(S.by_digest)))
    except Exception as exc:  # keep last valid policy
        log.error("policy load failed: %s", exc)
    return S.policy


def policy_for(digest: str | None) -> dict | None:
    """The policy the gateway decided with (it verified the signature). Unknown digest -> None (fail-closed)."""
    load_policy()
    if not digest:
        return None
    return S.by_digest.get(digest)


@contextlib.asynccontextmanager
async def lifespan(app):
    S.http = httpx.AsyncClient(timeout=httpx.Timeout(TIMEOUT, connect=5.0))
    load_policy()
    yield
    await S.http.aclose()


app = FastAPI(title="AISM orchestrator stub", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)


def err(status, code, message):
    return JSONResponse({"error": {"message": message, "type": "invalid_request_error" if status < 500 else "server_error",
                                   "code": code}}, status_code=status)


def guard(request: Request):
    tok = request.headers.get("x-aism-internal-token", "")
    if not INTERNAL_TOKEN or not hmac.compare_digest(tok.encode(), INTERNAL_TOKEN.encode()):
        return err(401, "invalid_token", "Nur über das Gateway (S2) erreichbar")
    if load_policy() is None:
        return err(503, "policy_unavailable", "Keine gültige Policy (fail-closed)")
    want = request.headers.get("x-aism-policy-digest")
    if want and policy_for(want) is None:
        # the gateway's (signature-verified) policy differs from the file S3 sees -> do not guess
        return err(503, "policy_mismatch", "Policy von S3 stimmt nicht mit der des Gateways überein (fail-closed)")
    return None


def req_policy(request: Request) -> dict:
    return policy_for(request.headers.get("x-aism-policy-digest")) or S.policy


def sha(obj) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def child_tp(tp: str | None) -> dict:
    parts = (tp or "").split("-")
    if len(parts) == 4:
        return {"traceparent": f"00-{parts[1]}-{secrets.token_hex(8)}-{parts[3]}"}
    return {}


class Ctx:
    def __init__(self, request: Request):
        h = request.headers
        self.request_id = h.get("x-aism-request-id", "")
        self.subject = h.get("x-aism-subject", "")
        self.roles = [r for r in h.get("x-aism-roles", "").split(",") if r]
        self.tools = [t for t in h.get("x-aism-allowed-tools", "").split(",") if t]
        self.collections = [c for c in h.get("x-aism-collections", "").split(",") if c]
        self.route = h.get("x-aism-route", "local")
        self.traceparent = h.get("traceparent")
        self.web = h.get("x-aism-web-search", "false") == "true"
        self.agent = h.get("x-aism-agent") or None
        self.data_class = h.get("x-aism-data-class", "")


async def gw_audit(ctx: Ctx, event: str, **fields):
    try:
        await S.http.post(GW_INTERNAL + "/internal/v1/audit", json={"request_id": ctx.request_id, "event": event, **fields},
                          headers={"X-AISM-Internal-Token": INTERNAL_TOKEN, **child_tp(ctx.traceparent)}, timeout=5)
    except httpx.TransportError:
        log.error("audit via gateway failed for %s", ctx.request_id)


async def gw_mask(ctx: Ctx, text: str, context: str) -> str | None:
    try:
        r = await S.http.post(GW_INTERNAL + "/internal/v1/mask",
                              json={"request_id": ctx.request_id, "content": text, "context": context},
                              headers={"X-AISM-Internal-Token": INTERNAL_TOKEN, **child_tp(ctx.traceparent)}, timeout=10)
        if r.status_code == 200:
            return r.json()["content"]
    except httpx.TransportError:
        pass
    return None  # fail-closed: caller must not forward unmasked content


WEB_TOOL_SCHEMA = {"type": "object", "properties": {"query": {"type": "string", "minLength": 1, "maxLength": 300}},
                   "required": ["query"], "additionalProperties": False}


def tool_specs(pol: dict, allowed: list[str], web: bool = False) -> list[dict]:
    out = [{"type": "function", "function": {"name": t["id"], "description": t.get("description", ""),
                                             "parameters": t["argumentsSchema"]}}
           for t in pol["spec"]["tools"]["definitions"] if t["id"] in allowed]
    if web and SEARXNG:
        out.append({"type": "function", "function": {
            "name": WEB_TOOL, "description": "Websuche (SearXNG). Keine personenbezogenen Daten in die Anfrage.",
            "parameters": WEB_TOOL_SCHEMA}})
    return out


def rate_ok(tool: dict, subject: str) -> bool:
    rl = tool.get("rateLimit")
    if not rl:
        return True
    unit = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    window = int(rl["per"][:-1]) * unit[rl["per"][-1]]
    key = (tool["id"], subject if rl.get("scope", "subject") == "subject" else "*")
    now = time.time()
    hist = [t for t in S.rate.get(key, []) if t > now - window]
    ok = len(hist) < rl["requests"]
    if ok:
        hist.append(now)
    S.rate[key] = hist
    return ok


def _duration(v: str | None, default: float = 10.0) -> float:
    if not v:
        return default
    unit = {"s": 1, "m": 60, "h": 3600}
    return float(v[:-1]) * unit.get(v[-1], 1)


async def run_tool(ctx: Ctx, pol: dict, tc: dict, rnd: int) -> str:
    fn = tc.get("function") or {}
    name, raw_args = fn.get("name"), fn.get("arguments") or "{}"
    tdef = next((t for t in pol["spec"]["tools"]["definitions"] if t["id"] == name), None)
    base = dict(tool=name, round=rnd, tool_call_id=tc.get("id"))

    async def deny(code):
        await gw_audit(ctx, "tool.call.denied", reason=code, args_sha256=sha(raw_args), **base)
        return json.dumps({"error": code})

    if name == WEB_TOOL and tdef is None:
        if not ctx.web or not SEARXNG:
            return await deny("web_search_not_permitted")
        try:
            args = json.loads(raw_args)
            jsonschema.Draft202012Validator(WEB_TOOL_SCHEMA).validate(args)
        except (json.JSONDecodeError, jsonschema.ValidationError):
            return await deny("invalid_arguments")
        return await web_search(ctx, pol, args["query"], base)
    if tdef is None or name not in ctx.tools:
        return await deny("tool_not_permitted")
    try:
        args = json.loads(raw_args)
        jsonschema.Draft202012Validator(tdef["argumentsSchema"]).validate(args)
    except (json.JSONDecodeError, jsonschema.ValidationError):
        return await deny("invalid_arguments")
    needs_confirm = tdef.get("requireConfirmation") or (
        tdef.get("access") == "write" and pol["spec"]["tools"].get("requireConfirmationForWrite", True))
    if needs_confirm:
        cid = "conf_" + secrets.token_hex(12)
        now = time.time()
        S.pending[cid] = {"id": cid, "tool": name, "args": args, "subject": ctx.subject, "agent": ctx.agent,
                          "data_class": ctx.data_class, "request_id": ctx.request_id, "tool_call_id": tc.get("id"),
                          "created": now, "expires": now + CONFIRM_TTL, "status": "pending"}
        await gw_audit(ctx, "tool.call.pending", confirmation_id=cid, args_sha256=sha(args),
                       expires_at=int(now + CONFIRM_TTL), **base)
        return json.dumps({"status": "pending_confirmation", "confirmation_id": cid,
                           "message": "Schreibende Aktion wartet auf Bestätigung durch den Benutzer; noch NICHT ausgeführt."})
    return await execute_tool(ctx, tdef, args, base)


async def execute_tool(ctx: Ctx, tdef: dict, args: dict, base: dict) -> str:
    if not rate_ok(tdef, ctx.subject):
        await gw_audit(ctx, "tool.call.denied", reason="rate_limited", args_sha256=sha(args), **base)
        return json.dumps({"error": "rate_limited"})
    if not TOOL_GW:
        await gw_audit(ctx, "tool.call.denied", reason="tool_gateway_unavailable", args_sha256=sha(args), **base)
        return json.dumps({"error": "tool_gateway_unavailable"})
    await gw_audit(ctx, "tool.call.allowed", args_sha256=sha(args), **base)
    hdrs = {"Content-Type": "application/json", **child_tp(ctx.traceparent)}
    if N8N_TOKEN:
        hdrs["Authorization"] = f"Bearer {N8N_TOKEN}"
    try:
        r = await S.http.post(TOOL_GW + tdef["target"], json=args, headers=hdrs, timeout=_duration(tdef.get("timeout")))
        result = r.text if r.status_code < 400 else json.dumps({"error": "tool_failed", "status": r.status_code})
    except httpx.TransportError:
        result = json.dumps({"error": "tool_unavailable"})
    if tdef.get("maskResult", True):
        masked = await gw_mask(ctx, result, "tool_result")
        result = masked if masked is not None else json.dumps({"error": "tool_result_unavailable"})
    await gw_audit(ctx, "tool.result", result_sha256=sha(result), **base)
    return result


async def web_search(ctx: Ctx, pol: dict, query: str, base: dict) -> str:
    """PEP-6: mask the model-generated query again (it may contain PII), strip placeholders, query SearXNG."""
    ws = pol["spec"].get("webSearch") or {}
    masked = await gw_mask(ctx, query, "web_query")
    if masked is None:
        await gw_audit(ctx, "tool.call.denied", reason="masking_unavailable", **base)
        return json.dumps({"error": "web_search_unavailable"})
    stripped = 0
    if ws.get("stripPlaceholders", True):
        masked, stripped = PLACEHOLDER_RE.subn("", masked)
        masked = re.sub(r"\s{2,}", " ", masked).strip()
    if not masked:
        await gw_audit(ctx, "tool.call.denied", reason="empty_query_after_masking", **base)
        return json.dumps({"error": "empty_query"})
    url = f"{SEARXNG}/search?" + urllib.parse.urlencode({"q": masked, "format": "json"})
    try:
        r = await S.http.get(url, headers=child_tp(ctx.traceparent), timeout=10)
        results = (r.json().get("results") or [])[: int(ws.get("maxResults", 5))] if r.status_code == 200 else None
    except (httpx.TransportError, ValueError):
        results = None
    await gw_audit(ctx, "egress.websearch", query_sha256=sha(masked), placeholders_stripped=stripped,
                   results=len(results) if results is not None else 0, engine_host=urllib.parse.urlsplit(SEARXNG).hostname,
                   decision="allowed", **base)
    if results is None:
        return json.dumps({"error": "web_search_failed"})
    text = json.dumps([{"title": x.get("title", ""), "url": x.get("url", ""), "content": x.get("content", "")}
                       for x in results], ensure_ascii=False)
    out = await gw_mask(ctx, text, "tool_result")   # results are untrusted and may contain PII
    if out is None:
        return json.dumps({"error": "tool_result_unavailable"})
    await gw_audit(ctx, "tool.result", result_sha256=sha(out), **base)
    return json.dumps({"untrusted_web_results": out}, ensure_ascii=False)


async def rag(ctx: Ctx, pol: dict, messages: list[dict]) -> list[dict]:
    """Embeds the (already masked) last user message; queries Qdrant only if configured."""
    if not ctx.collections or not EMBEDDINGS:
        return messages
    query = next((m["content"] for m in reversed(messages) if m.get("role") == "user" and isinstance(m.get("content"), str)), "")
    if not query:
        return messages
    try:
        r = await S.http.post(EMBEDDINGS + "/embeddings", json={"model": pol["spec"]["rag"].get("embeddingModel", "embed"),
                                                               "input": query}, headers=child_tp(ctx.traceparent), timeout=30)
        vec = r.json()["data"][0]["embedding"]
    except Exception:
        log.warning("embedding failed; continuing without RAG")
        return messages
    chunks = []
    if QDRANT:
        rcfg = pol["spec"]["rag"]
        for coll in rcfg["collections"]:
            if coll["id"] not in ctx.collections:
                continue
            body = {"vector": vec, "limit": rcfg.get("maxChunks", 5), "with_payload": True}
            f = coll.get("filter")
            if f:
                body["filter"] = {"must": [{"key": f["payloadKey"], "match": {"any": ctx.roles}}]}
            try:
                q = await S.http.post(f"{QDRANT}/collections/{coll['id']}/points/search", json=body,
                                      headers={"api-key": QDRANT_KEY} if QDRANT_KEY else {}, timeout=10)
                chunks += [p.get("payload", {}).get("text", "") for p in q.json().get("result", [])]
            except Exception:
                log.warning("qdrant search failed for %s", coll["id"])
    await gw_audit(ctx, "rag.query", collections=ctx.collections, chunks=len(chunks))
    if not chunks:
        return messages
    masked = await gw_mask(ctx, "\n---\n".join(c for c in chunks if c), "rag_ingest")
    if masked is None:
        return messages
    return [{"role": "system", "content": "Kontext aus freigegebenen Dokumenten:\n" + masked}] + messages


async def infer(ctx: Ctx, body: dict, stream: bool):
    """Local inference; on connection failure, fallback only via the gateway egress endpoint."""
    hdrs = {"Content-Type": "application/json", **child_tp(ctx.traceparent)}
    if ctx.route.startswith("cloud:"):
        url, hdrs = GW_INTERNAL + "/internal/egress/v1/chat/completions", {
            **hdrs, "X-AISM-Internal-Token": INTERNAL_TOKEN, "X-AISM-Request-ID": ctx.request_id,
            "X-AISM-Fallback-Reason": "explicit"}
        return await S.http.send(S.http.build_request("POST", url, json=body, headers=hdrs), stream=stream)
    try:
        return await S.http.send(S.http.build_request("POST", INFERENCE + "/chat/completions", json=body, headers=hdrs),
                                 stream=stream)
    except httpx.ConnectError:
        url = GW_INTERNAL + "/internal/egress/v1/chat/completions"
        resp = await S.http.send(S.http.build_request("POST", url, json=body, headers={
            **hdrs, "X-AISM-Internal-Token": INTERNAL_TOKEN, "X-AISM-Request-ID": ctx.request_id,
            "X-AISM-Fallback-Reason": "local_unavailable"}), stream=stream)
        if resp.status_code == 403:
            # fallback not permitted by policy: the client sees "local model unavailable", not a policy detail
            await resp.aclose()
            return httpx.Response(503, request=resp.request, json={"error": {
                "message": "Lokales Modell nicht erreichbar; Cloud-Fallback ist für diesen Request nicht freigegeben",
                "type": "server_error", "code": "upstream_unavailable"}})
        return resp


@app.get("/health")
async def health():
    return {"status": "ok" if load_policy() else "unavailable"}


@app.get("/v1/models")
async def models(request: Request):
    if (g := guard(request)) is not None:
        return g
    r = await S.http.get(INFERENCE + "/models")
    return JSONResponse(r.json(), status_code=r.status_code)


@app.post("/v1/embeddings")
async def embeddings(request: Request):
    if (g := guard(request)) is not None:
        return g
    if not EMBEDDINGS:
        return err(503, "upstream_unavailable", "EMBEDDINGS_URL nicht gesetzt")
    r = await S.http.post(EMBEDDINGS + "/embeddings", content=await request.body(),
                          headers={"Content-Type": "application/json", **child_tp(request.headers.get("traceparent"))})
    return JSONResponse(r.json(), status_code=r.status_code)


@app.post("/v1/chat/completions")
async def chat(request: Request):
    if (g := guard(request)) is not None:
        return g
    pol = req_policy(request)
    ctx = Ctx(request)
    body = await request.json()
    stream = bool(body.get("stream"))
    body.pop("tools", None)            # client-defined tools are not executed by the stub
    body.pop("tool_choice", None)
    body["messages"] = await rag(ctx, pol, body["messages"])
    tools = tool_specs(pol, ctx.tools, ctx.web)
    max_rounds = pol["spec"]["defaults"].get("maxToolRounds", 5)

    def round_body(rnd):
        b = dict(body)
        if tools and rnd < max_rounds:
            b["tools"] = tools
        return b

    if not stream:
        for rnd in range(max_rounds + 1):
            try:
                resp = await infer(ctx, round_body(rnd), stream=False)
            except httpx.TransportError:
                return err(502, "upstream_unavailable", "Inferenz nicht erreichbar")
            if resp.status_code != 200:
                return JSONResponse(resp.json(), status_code=resp.status_code)
            data = resp.json()
            msg = (data.get("choices") or [{}])[0].get("message") or {}
            tcs = msg.get("tool_calls") or []
            if not tcs or rnd >= max_rounds:
                return JSONResponse(data)
            body["messages"] = body["messages"] + [{"role": "assistant", "content": msg.get("content"), "tool_calls": tcs}]
            for tc in tcs:
                body["messages"].append({"role": "tool", "tool_call_id": tc.get("id"),
                                         "content": await run_tool(ctx, pol, tc, rnd + 1)})
        return err(500, "tool_loop_exhausted", "maxToolRounds überschritten")

    async def gen():
        for rnd in range(max_rounds + 1):
            try:
                resp = await infer(ctx, round_body(rnd), stream=True)
            except httpx.TransportError:
                yield 'data: {"error":{"message":"Inferenz nicht erreichbar","type":"server_error","code":"upstream_unavailable"}}\n\n'
                yield "data: [DONE]\n\n"
                return
            acc: dict[int, dict] = {}
            saw_tool_finish = False
            try:
                if resp.status_code != 200:
                    raw = await resp.aread()
                    try:
                        e = json.loads(raw).get("error")
                    except Exception:
                        e = None
                    yield "data: " + json.dumps({"error": e or {"message": "Upstream-Fehler", "type": "server_error",
                                                                "code": "upstream_unavailable"}}) + "\n\n"
                    yield "data: [DONE]\n\n"
                    return
                async for line in resp.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    payload = line[5:].strip()
                    if payload == "[DONE]":
                        break
                    chunk = json.loads(payload)
                    forward = False
                    for ch in chunk.get("choices") or []:
                        d = ch.get("delta") or {}
                        for tcd in d.pop("tool_calls", None) or []:
                            a = acc.setdefault(tcd.get("index", 0), {"id": None, "type": "function",
                                                                     "function": {"name": "", "arguments": ""}})
                            a["id"] = tcd.get("id") or a["id"]
                            f = tcd.get("function") or {}
                            a["function"]["name"] += f.get("name") or ""
                            a["function"]["arguments"] += f.get("arguments") or ""
                        if ch.get("finish_reason") == "tool_calls" and rnd < max_rounds:
                            saw_tool_finish = True
                        elif d.get("content") or ch.get("finish_reason") or (d.get("role") and rnd == 0):
                            forward = True
                    if forward:
                        yield "data: " + json.dumps(chunk, ensure_ascii=False) + "\n\n"
            finally:
                await resp.aclose()
            if not (saw_tool_finish and acc):
                yield "data: [DONE]\n\n"
                return
            tcs = [acc[i] for i in sorted(acc)]
            body["messages"] = body["messages"] + [{"role": "assistant", "content": None, "tool_calls": tcs}]
            for tc in tcs:
                body["messages"].append({"role": "tool", "tool_call_id": tc.get("id"),
                                         "content": await run_tool(ctx, pol, tc, rnd + 1)})
        yield "data: [DONE]\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})


# ── confirmations (S-03): called by the gateway only ──────────────────

def _expire():
    now = time.time()
    for cid, p in list(S.pending.items()):
        if p["status"] == "pending" and p["expires"] < now:
            p["status"] = "expired"
        if p["expires"] < now - 3600:
            S.pending.pop(cid, None)


def _public(p: dict) -> dict:
    return {k: p[k] for k in ("id", "tool", "args", "status", "created", "expires")}


@app.get("/internal/v1/confirmations")
async def confirmations(request: Request):
    if (g := guard(request)) is not None:
        return g
    _expire()
    subj = request.headers.get("x-aism-subject", "")
    return {"object": "list", "data": [_public(p) for p in S.pending.values()
                                       if p["subject"] == subj and p["status"] == "pending"]}


def _tool_still_allowed(pol: dict, p: dict, roles: list[str]) -> bool:
    tdef = next((t for t in pol["spec"]["tools"]["definitions"] if t["id"] == p["tool"]), None)
    if tdef is None:
        return False
    a = tdef["allow"]
    if not set(a["roles"]) & set(roles):
        return False
    if a.get("agents") and p["agent"] not in a["agents"]:
        return False
    if "maxDataClassRank" in a:
        rank = next((c["rank"] for c in pol["spec"]["dataClasses"] if c["id"] == p["data_class"]), None)
        if rank is None or rank > a["maxDataClassRank"]:
            return False
    return True


async def _decide(request: Request, cid: str, approve: bool):
    if (g := guard(request)) is not None:
        return g
    _expire()
    pol = req_policy(request)
    ctx = Ctx(request)
    p = S.pending.get(cid)
    if p is None or p["subject"] != ctx.subject:          # foreign ids are indistinguishable from unknown ones
        return err(404, "confirmation_not_found", "Bestätigung unbekannt")
    if p["status"] != "pending":
        return err(409, "confirmation_not_pending", f"Bestätigung ist {p['status']}")
    base = dict(tool=p["tool"], confirmation_id=cid, tool_call_id=p["tool_call_id"])
    if not approve:
        p["status"] = "rejected"
        await gw_audit(ctx, "tool.call.rejected", args_sha256=sha(p["args"]), **base)
        return {"id": cid, "status": "rejected"}
    p["status"] = "approving"                            # single use, also under concurrent approvals
    if not _tool_still_allowed(pol, p, ctx.roles):
        p["status"] = "denied"
        await gw_audit(ctx, "tool.call.denied", reason="tool_not_permitted", stage="confirmation",
                       args_sha256=sha(p["args"]), **base)
        return err(403, "tool_not_permitted", "Tool ist nach aktueller Policy nicht mehr erlaubt")
    tdef = next(t for t in pol["spec"]["tools"]["definitions"] if t["id"] == p["tool"])
    try:
        jsonschema.Draft202012Validator(tdef["argumentsSchema"]).validate(p["args"])
    except jsonschema.ValidationError:
        p["status"] = "denied"
        await gw_audit(ctx, "tool.call.denied", reason="invalid_arguments", stage="confirmation", **base)
        return err(400, "invalid_arguments", "Argumente entsprechen nicht mehr dem Schema")
    await gw_audit(ctx, "tool.call.confirmed", args_sha256=sha(p["args"]), **base)
    result = await execute_tool(ctx, tdef, p["args"], base)
    failed = result.startswith('{"error"')
    p["status"] = "failed" if failed else "executed"
    return {"id": cid, "status": p["status"], "tool": p["tool"], "result": result}


@app.post("/internal/v1/confirmations/{cid}/approve")
async def approve(cid: str, request: Request):
    return await _decide(request, cid, True)


@app.post("/internal/v1/confirmations/{cid}/reject")
async def reject(cid: str, request: Request):
    return await _decide(request, cid, False)
