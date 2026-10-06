"""AISM governance gateway (S2) – prototype.

Public app  (LISTEN_PUBLIC,   default 0.0.0.0:8000): /health, /aism/v1/policy, /v1/models,
                                                       /v1/chat/completions, /v1/embeddings,
                                                       /aism/v1/confirmations[/{id}/approve|reject]
Internal app (LISTEN_INTERNAL, default 0.0.0.0:8001, backend network only, X-AISM-Internal-Token):
             /internal/v1/mask, /internal/v1/audit, /internal/egress/v1/chat/completions

Prototype – not production-ready. See gateway/README.md for limitations.
"""
from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import logging
import os
import secrets
import ssl
import time
from dataclasses import dataclass, field

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from . import trace as tracectx
from .audit import AuditLog, sha256_json
from .auth import AuthError, Subject, authenticate, resolve_secret
from .pii import DetectorUnavailable, Masker, StreamDemasker, Vault, build_detectors, demask
from .policy import (Policy, PolicyError, SignatureConfig, allowed_collections, allowed_tools, data_class,
                     load_policy, match_route, web_search_allowed)

log = logging.getLogger("aism.gateway")

POLICY_PATH = os.environ.get("POLICY_PATH", "/etc/aism/policy.yaml")
SCHEMA_PATH = os.environ.get("POLICY_SCHEMA_PATH",
                             os.path.join(os.path.dirname(__file__), "..", "..", "policy", "policy.schema.json"))
UPSTREAM = os.environ.get("UPSTREAM_ORCHESTRATOR", "http://orchestrator:9000/v1").rstrip("/")
INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "")
AUDIT_PATH_ENV = os.environ.get("AUDIT_LOG_PATH")  # overrides policy audit.sink.path
RELOAD_SECONDS = float(os.environ.get("POLICY_RELOAD_SECONDS", "5"))
UPSTREAM_TIMEOUT = float(os.environ.get("UPSTREAM_TIMEOUT_SECONDS", "120"))
CA_BUNDLE = os.environ.get("AISM_CA_BUNDLE")
# Policy signature (K3-01/K3-08). Trust config lives in the gateway environment, not in the policy.
ALLOWED_SIGNERS = os.environ.get("POLICY_ALLOWED_SIGNERS") or None
_req = os.environ.get("POLICY_REQUIRE_SIGNATURE")
REQUIRE_SIGNATURE = (_req.lower() in ("1", "true", "yes")) if _req else bool(ALLOWED_SIGNERS)
SIG_CFG = SignatureConfig(required=REQUIRE_SIGNATURE, allowed_signers=ALLOWED_SIGNERS)
CTX_TTL = 600
INTERNAL_HEADERS_PREFIX = "x-aism-"


# ── state ────────────────────────────────────────────────────────────

@dataclass
class ReqCtx:
    request_id: str
    trace_id: str
    subject: Subject
    vault: Vault
    data_class: str
    rule: dict
    tools: list[str]
    created: float = field(default_factory=time.time)


class State:
    policy: Policy | None = None
    policy_error: str | None = None
    attempted_mtime: tuple | None = None
    masker: Masker | None = None
    detector_errors: list[str] = []
    audit: AuditLog | None = None
    http: httpx.AsyncClient | None = None
    contexts: dict[str, ReqCtx] = {}
    rate: dict[tuple, list[float]] = {}


S = State()


def _entity_rank(pol: Policy) -> dict[str, int]:
    ranks: dict[str, int] = {}
    for c in pol.spec["dataClasses"]:
        for e in (c.get("assignWhen") or {}).get("detectedEntities", []):
            ranks[e] = max(ranks.get(e, 0), c["rank"])
    return ranks


def _ensure_audit(pol: Policy | None):
    if S.audit is None:
        path = AUDIT_PATH_ENV or (pol.spec["audit"]["sink"].get("path") if pol else None) or "/audit/audit.jsonl"
        S.audit = AuditLog(path)


def audit(event: str, **fields):
    pol = S.policy
    if pol is not None and event not in pol.spec["audit"]["events"]:
        return
    _ensure_audit(pol)
    S.audit.write(event, pol.info() if pol else None, **fields)


def policy_files_state() -> tuple:
    """mtimes of all files in the policy directory (policy + detached signature) and the trust anchor."""
    d = os.path.dirname(os.path.abspath(POLICY_PATH))
    out = []
    try:
        for n in sorted(os.listdir(d)):
            with contextlib.suppress(OSError):
                out.append((n, os.stat(os.path.join(d, n)).st_mtime))
    except OSError:
        pass
    if ALLOWED_SIGNERS:
        with contextlib.suppress(OSError):
            out.append(("@anchor", os.stat(ALLOWED_SIGNERS).st_mtime))
    return tuple(out)


def try_load(initial: bool = False) -> None:
    if initial:
        S.attempted_mtime = policy_files_state()
        if not REQUIRE_SIGNATURE:
            log.warning("policy signature NOT required (POLICY_REQUIRE_SIGNATURE/POLICY_ALLOWED_SIGNERS unset) – "
                        "not sufficient for AISM K3")
    try:
        pol = load_policy(POLICY_PATH, SCHEMA_PATH, SIG_CFG, current=S.policy)
    except PolicyError as exc:
        # fail-closed on start; on reload keep the last valid policy (Policy-Format §6)
        S.policy_error = str(exc)
        if initial:
            S.policy = None
        _ensure_audit(S.policy)
        S.audit.write("policy.load_failed", S.policy.info() if S.policy else None, error=str(exc)[:500],
                      kept_active=bool(S.policy))
        log.error("policy load failed: %s", exc)
        return
    dets, errs = build_detectors(pol.spec, base_dir=os.path.dirname(os.path.abspath(POLICY_PATH)))
    S.policy, S.policy_error = pol, None
    S.masker, S.detector_errors = Masker(dets, _entity_rank(pol)), errs
    _ensure_audit(pol)
    audit("policy.loaded", detectors=[d.id for d in dets], detector_errors=errs or None,
          signature={k: v for k, v in pol.signature.items() if k != "ref"})
    log.info("policy %s loaded (%s)", pol.info()["version"], pol.digest)


async def reload_loop():
    while True:
        await asyncio.sleep(RELOAD_SECONDS)
        state = policy_files_state()
        if state and state != S.attempted_mtime:   # one attempt per file change (no log flooding)
            S.attempted_mtime = state
            await asyncio.to_thread(try_load)
        cutoff = time.time() - CTX_TTL
        for rid in [k for k, v in S.contexts.items() if v.created < cutoff]:
            S.contexts.pop(rid, None)


# ── helpers ──────────────────────────────────────────────────────────

def err(status: int, code: str, message: str, etype: str | None = None) -> JSONResponse:
    etype = etype or ("invalid_request_error" if status < 500 else "server_error")
    return JSONResponse({"error": {"message": message, "type": etype, "code": code}}, status_code=status)


def ready() -> JSONResponse | None:
    if S.policy is None:
        return err(503, "policy_unavailable", "Keine gültige Policy geladen (fail-closed)")
    if S.detector_errors:
        return err(503, "pii_detector_unavailable", "PII-Erkennung nicht verfügbar (fail-closed)")
    return None


def local_models(pol: Policy) -> list[str]:
    out = []
    for p in pol.providers():
        if p["type"] == "local" or pol.spec["routing"].get("cloudEnabled"):
            out += [m for m in p["models"] if m not in out]
    return out


def rate_ok(tool_or_key: str, subject: str, limit: dict | None) -> bool:
    if not limit:
        return True
    unit = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    per = limit["per"]
    window = int(per[:-1]) * unit[per[-1]]
    k = (tool_or_key, subject if limit.get("scope", "subject") == "subject" else "*")
    now = time.time()
    hist = [t for t in S.rate.get(k, []) if t > now - window]
    if len(hist) >= limit["requests"]:
        S.rate[k] = hist
        return False
    hist.append(now)
    S.rate[k] = hist
    return True


def mask_content(content, vault: Vault, context: str):
    """Masks str or OpenAI content-part lists. Returns (masked, entities)."""
    found: set[str] = set()
    if isinstance(content, str):
        out, f = S.masker.mask(content, vault, context)
        return out, f
    if isinstance(content, list):
        parts = []
        for p in content:
            if isinstance(p, dict) and p.get("type") == "text" and isinstance(p.get("text"), str):
                t, f = S.masker.mask(p["text"], vault, context)
                found |= f
                parts.append({**p, "text": t})
            elif isinstance(p, dict) and p.get("type") == "text":
                parts.append(p)
            else:
                # non-text parts (images, files) cannot be inspected -> rejected by caller
                raise ValueError("unsupported_content_part")
        return parts, found
    return content, found


# ── public app ───────────────────────────────────────────────────────

@contextlib.asynccontextmanager
async def lifespan(app):
    if S.http is None:
        # TLS is always verified; AISM_CA_BUNDLE only adds a private CA (e.g. test CA for the mock cloud provider)
        verify = ssl.create_default_context(cafile=CA_BUNDLE) if CA_BUNDLE else True
        S.http = httpx.AsyncClient(timeout=httpx.Timeout(UPSTREAM_TIMEOUT, connect=5.0), verify=verify)
    if S.policy is None and S.policy_error is None:
        await asyncio.to_thread(try_load, True)
        asyncio.get_running_loop().create_task(reload_loop())
    yield


public = FastAPI(title="AISM governance gateway (prototype)", docs_url=None, redoc_url=None, openapi_url=None,
                 lifespan=lifespan)


@public.get("/health")
async def health():
    r = ready()
    if r is not None:
        return JSONResponse({"status": "unavailable", "reason": json.loads(r.body)["error"]["code"]}, status_code=503)
    return {"status": "ok", "policy": S.policy.info()}


@public.get("/aism/v1/policy")
async def policy_info():
    if S.policy is None:
        return err(503, "policy_unavailable", "Keine gültige Policy geladen")
    info = S.policy.info()
    info["loaded_from"] = "file"
    info["schema"] = S.policy.raw["apiVersion"]
    info["signature"] = {**{k: v for k, v in S.policy.signature.items() if k != "ref"}, "required": REQUIRE_SIGNATURE}
    info["effective_from"] = S.policy.meta.get("effectiveFrom")
    if S.policy_error:
        info["last_load_error"] = S.policy_error[:300]   # a newer file was rejected; this policy stays active
    return info


async def _auth(request: Request, trace_id: str | None = None) -> Subject | JSONResponse:
    try:
        # thread: an OIDC JWKS fetch (cache miss) must not block the event loop
        return await asyncio.to_thread(authenticate, S.policy, request.headers)
    except AuthError as exc:
        if trace_id is None:
            trace_id, _ = tracectx.continue_or_start(request.headers.get("traceparent"))
        audit("request.denied", request_id="req_" + secrets.token_hex(8), trace_id=trace_id,
              reason=exc.code, path=request.url.path)
        return err(exc.status, exc.code, exc.message, "authentication_error" if exc.status == 401 else None)


@public.get("/v1/models")
async def models(request: Request):
    if (r := ready()) is not None:
        return r
    subj = await _auth(request)
    if isinstance(subj, JSONResponse):
        return subj
    now = int(time.time())
    return {"object": "list", "data": [{"id": m, "object": "model", "created": now, "owned_by": "aism"}
                                       for m in local_models(S.policy)]}


async def _read_json(request: Request, limit: int):
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > limit:
        return None, err(413, "request_too_large", "Request zu groß")
    raw = await request.body()
    if len(raw) > limit:
        return None, err(413, "request_too_large", "Request zu groß")
    try:
        body = json.loads(raw or b"null")
    except json.JSONDecodeError:
        return None, err(400, "invalid_request", "Body ist kein gültiges JSON")
    if not isinstance(body, dict):
        return None, err(400, "invalid_request", "Body muss ein JSON-Objekt sein")
    return body, None


def _ctx_headers(ctx: ReqCtx, traceparent: str, collections: list[str], web: bool) -> dict:
    return {
        "X-AISM-Request-ID": ctx.request_id,
        "X-AISM-Subject": ctx.subject.id,
        "X-AISM-Roles": ",".join(ctx.subject.roles),
        "X-AISM-Agent": ctx.subject.agent or "",
        "X-AISM-Data-Class": ctx.data_class,
        "X-AISM-Policy-Decision": ctx.rule["id"],
        "X-AISM-Route": "local",
        "X-AISM-Allowed-Tools": ",".join(ctx.tools),
        "X-AISM-Collections": ",".join(collections),
        "X-AISM-Web-Search": "true" if web else "false",
        "X-AISM-Policy-Digest": S.policy.digest,
        "X-AISM-Internal-Token": INTERNAL_TOKEN,
        "traceparent": traceparent,
        "Content-Type": "application/json",
    }


def _filter_tool_calls(tcs, allowed: list[str], ctx: ReqCtx):
    kept = []
    for tc in tcs or []:
        name = (tc.get("function") or {}).get("name")
        if name in allowed:
            kept.append(tc)
        else:
            audit("tool.call.denied", request_id=ctx.request_id, trace_id=ctx.trace_id, subject=ctx.subject.id,
                  tool=name, reason="tool_not_permitted", stage="gateway_response")
    return kept


@public.post("/v1/chat/completions")
async def chat(request: Request):
    if (r := ready()) is not None:
        return r
    pol = S.policy
    trace_id, traceparent = tracectx.continue_or_start(request.headers.get("traceparent"))
    subj = await _auth(request, trace_id)
    if isinstance(subj, JSONResponse):
        return subj
    request_id = "req_" + secrets.token_hex(8)
    body, e = await _read_json(request, pol.spec["defaults"].get("maxRequestBytes", 1048576))
    if e:
        return e
    msgs = body.get("messages")
    if not isinstance(msgs, list) or not msgs or not all(isinstance(m, dict) and "role" in m for m in msgs):
        return err(400, "invalid_request", "messages fehlt oder ist ungültig")

    requested = body.get("model") or "aism-default"
    models_local = [m for p in pol.providers() if p["type"] == "local" for m in p["models"]]
    if requested == "aism-default":
        requested = models_local[0]
    provider = pol.provider_for_model(requested)
    if provider is None:
        return err(404, "model_not_found", f"Modell {requested!r} ist nicht freigegeben")

    vault = Vault()
    entities: set[str] = set()
    masked_msgs = []
    try:
        for m in msgs:
            ctxname = "tool_result" if m.get("role") == "tool" else "prompt"
            nm = dict(m)
            if "content" in m and m["content"] is not None:
                nm["content"], f = mask_content(m["content"], vault, ctxname)
                entities |= f
            masked_msgs.append(nm)
    except ValueError:
        return err(400, "invalid_request", "Nicht-Text-Inhalte werden vom Prototyp nicht unterstützt")
    except DetectorUnavailable:
        log.exception("pii detector failed")
        audit("request.denied", request_id=request_id, trace_id=trace_id, subject=subj.id, client=subj.client,
              reason="pii_detector_unavailable")
        return err(503, "pii_detector_unavailable", "PII-Erkennung nicht verfügbar (fail-closed)")

    dc = data_class(pol, entities, subj.roles)
    rank = pol.data_class_rank(dc)
    rule, rtrace = match_route(pol, dc, subj.roles, subj.agent, requested)
    base = dict(request_id=request_id, trace_id=trace_id, subject=subj.id, client=subj.client)
    if vault.counts:
        audit("pii.masked", **base, pii_masked=dict(vault.counts))
    if rule is None or rule["route"]["mode"] == "deny":
        audit("request.denied", **base, reason="policy_denied", data_class=dc,
              rule_ids=[rule["id"]] if rule else [], rule_trace=rtrace)
        return err(403, "policy_denied", "Policy verweigert den Request (default deny)")

    route = rule["route"]
    if provider["type"] == "cloud":
        if not (pol.spec["routing"].get("cloudEnabled") and route["mode"] == "local-with-cloud-fallback"
                and provider["id"] in route.get("cloudProviders", [])):
            audit("request.denied", **base, reason="egress_denied", data_class=dc, rule_ids=[rule["id"]],
                  provider=provider["id"], rule_trace=rtrace)
            return err(403, "egress_denied", "Cloud-Routing ist für diesen Request nicht freigegeben")
    elif route.get("localProviders") and provider["id"] not in route["localProviders"]:
        audit("request.denied", **base, reason="policy_denied", data_class=dc, rule_ids=[rule["id"]])
        return err(403, "policy_denied", "Provider durch Regel nicht freigegeben")

    tools = allowed_tools(pol, subj.roles, subj.agent, rank)
    collections = allowed_collections(pol, subj.roles)
    web = web_search_allowed(pol, subj.roles, rank)
    ctx = ReqCtx(request_id, trace_id, subj, vault, dc, rule, tools)
    S.contexts[request_id] = ctx

    out = {k: v for k, v in body.items() if k not in ("messages", "tools", "tool_choice", "functions", "function_call")}
    out["model"], out["messages"] = requested, masked_msgs
    client_tools = body.get("tools") or []
    kept = [t for t in client_tools if (t.get("function") or {}).get("name") in tools]
    if kept:
        out["tools"] = kept
    audit("request.accepted", **base, data_class=dc, model=requested, pii_masked=dict(vault.counts),
          tools_permitted=tools, tools_dropped=len(client_tools) - len(kept), collections=collections,
          web_search=web, payload_sha256=sha256_json(out) if pol.spec["audit"].get("storePayloadHash") else None)
    audit("route.decided", **base, route="cloud" if provider["type"] == "cloud" else "local",
          provider=provider["id"], rule_ids=[rule["id"]],
          rule_trace=rtrace if pol.spec["audit"].get("decisionLog", {}).get("includeRuleTrace") else None)

    headers = _ctx_headers(ctx, traceparent, collections, web)
    if provider["type"] == "cloud":
        headers["X-AISM-Route"] = f"cloud:{provider['id']}"
    stream = bool(body.get("stream"))
    url = UPSTREAM + "/chat/completions"
    try:
        upstream_req = S.http.build_request("POST", url, json=out, headers=headers)
        resp = await S.http.send(upstream_req, stream=True)
    except httpx.TimeoutException:
        S.contexts.pop(request_id, None)
        return err(504, "upstream_timeout", "Upstream-Timeout")
    except httpx.TransportError:
        S.contexts.pop(request_id, None)
        return err(502, "upstream_unavailable", "Upstream nicht erreichbar")

    resp_headers = {"X-AISM-Request-ID": request_id, "traceparent": traceparent}
    if resp.status_code != 200 or not stream or not resp.headers.get("content-type", "").startswith("text/event-stream"):
        raw = await resp.aread()
        await resp.aclose()
        S.contexts.pop(request_id, None)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return err(502, "upstream_unavailable", "Ungültige Upstream-Antwort")
        if resp.status_code == 200 and isinstance(data, dict):
            for ch in data.get("choices") or []:
                msg = ch.get("message") or {}
                if isinstance(msg.get("content"), str):
                    msg["content"] = demask(msg["content"], vault, subj.roles)
                if msg.get("tool_calls"):
                    msg["tool_calls"] = _filter_tool_calls(msg["tool_calls"], tools, ctx) or None
                    if not msg["tool_calls"]:
                        msg.pop("tool_calls")
                        ch["finish_reason"] = "stop"
            audit("stream.completed", **base, stream=False, status=200)
        return JSONResponse(data, status_code=resp.status_code, headers=resp_headers)

    return StreamingResponse(_stream(resp, ctx, base), media_type="text/event-stream",
                             headers={**resp_headers, "Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


async def _stream(resp: httpx.Response, ctx: ReqCtx, base: dict):
    demaskers: dict[int, StreamDemasker] = {}
    tc_allowed: dict[tuple[int, int], bool] = {}
    completed = False
    last_meta: dict = {}

    def dm(i):
        if i not in demaskers:
            demaskers[i] = StreamDemasker(ctx.vault, ctx.subject.roles)
        return demaskers[i]

    try:
        async for line in resp.aiter_lines():
            if not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if payload == "[DONE]":
                tail = [(i, d.flush()) for i, d in demaskers.items()]
                tail = [(i, t) for i, t in tail if t]
                if tail:
                    yield "data: " + json.dumps({**last_meta, "object": "chat.completion.chunk", "choices": [
                        {"index": i, "delta": {"content": t}, "finish_reason": None} for i, t in tail]}) + "\n\n"
                yield "data: [DONE]\n\n"
                completed = True
                break
            try:
                chunk = json.loads(payload)
            except json.JSONDecodeError:
                continue
            if "error" in chunk and "choices" not in chunk:
                yield "data: " + json.dumps({"error": chunk["error"]}) + "\n\n"
                continue
            last_meta = {k: chunk.get(k) for k in ("id", "created", "model") if k in chunk}
            for ch in chunk.get("choices") or []:
                i = ch.get("index", 0)
                delta = ch.get("delta") or {}
                if isinstance(delta.get("content"), str):
                    delta["content"] = dm(i).feed(delta["content"])
                if ch.get("finish_reason") and i in demaskers:
                    delta["content"] = (delta.get("content") or "") + demaskers[i].flush()
                if delta.get("tool_calls"):
                    kept = []
                    for tc in delta["tool_calls"]:
                        key = (i, tc.get("index", 0))
                        name = (tc.get("function") or {}).get("name")
                        if key not in tc_allowed and name is not None:
                            tc_allowed[key] = name in ctx.tools
                            if not tc_allowed[key]:
                                audit("tool.call.denied", **base, tool=name, reason="tool_not_permitted",
                                      stage="gateway_stream")
                        if tc_allowed.get(key):
                            kept.append(tc)
                    if kept:
                        delta["tool_calls"] = kept
                    else:
                        delta.pop("tool_calls")
                        if ch.get("finish_reason") == "tool_calls":
                            ch["finish_reason"] = "stop"
            yield "data: " + json.dumps(chunk, ensure_ascii=False) + "\n\n"
        if not completed:
            # upstream ended without [DONE]: flush and terminate cleanly
            for i, d in demaskers.items():
                t = d.flush()
                if t:
                    yield "data: " + json.dumps({**last_meta, "object": "chat.completion.chunk", "choices": [
                        {"index": i, "delta": {"content": t}, "finish_reason": None}]}) + "\n\n"
            yield "data: [DONE]\n\n"
            completed = True
    except httpx.TransportError:
        yield "data: " + json.dumps({"error": {"message": "Upstream-Stream abgebrochen", "type": "server_error",
                                               "code": "upstream_unavailable"}}) + "\n\n"
    finally:
        await resp.aclose()
        S.contexts.pop(ctx.request_id, None)
        audit("stream.completed" if completed else "stream.aborted", **base, stream=True)


@public.post("/v1/embeddings")
async def embeddings(request: Request):
    if (r := ready()) is not None:
        return r
    pol = S.policy
    trace_id, traceparent = tracectx.continue_or_start(request.headers.get("traceparent"))
    subj = await _auth(request, trace_id)
    if isinstance(subj, JSONResponse):
        return subj
    request_id = "req_" + secrets.token_hex(8)
    body, e = await _read_json(request, pol.spec["defaults"].get("maxRequestBytes", 1048576))
    if e:
        return e
    inp = body.get("input")
    single = isinstance(inp, str)
    items = [inp] if single else inp
    if not isinstance(items, list) or not items or not all(isinstance(x, str) for x in items):
        return err(400, "invalid_request", "input muss ein String oder eine Liste von Strings sein")
    base = dict(request_id=request_id, trace_id=trace_id, subject=subj.id, client=subj.client)
    if not subj.roles:
        audit("request.denied", **base, reason="policy_denied", endpoint="embeddings")
        return err(403, "policy_denied", "Keine Rolle – Embeddings verweigert (default deny)")
    vault, ents, masked = Vault(), set(), []
    try:
        for x in items:
            t, f = S.masker.mask(x, vault, "rag_ingest")
            masked.append(t)
            ents |= f
    except DetectorUnavailable:
        log.exception("pii detector failed")
        audit("request.denied", **base, reason="pii_detector_unavailable", endpoint="embeddings")
        return err(503, "pii_detector_unavailable", "PII-Erkennung nicht verfügbar (fail-closed)")
    out = {**body, "input": masked[0] if single else masked}
    audit("request.accepted", **base, endpoint="embeddings", pii_masked=dict(vault.counts), inputs=len(items))
    try:
        resp = await S.http.post(UPSTREAM + "/embeddings", json=out, headers={
            "X-AISM-Request-ID": request_id, "X-AISM-Subject": subj.id, "X-AISM-Roles": ",".join(subj.roles),
            "X-AISM-Internal-Token": INTERNAL_TOKEN, "traceparent": traceparent})
    except httpx.TransportError:
        return err(502, "upstream_unavailable", "Upstream nicht erreichbar")
    return Response(resp.content, status_code=resp.status_code, media_type="application/json",
                    headers={"X-AISM-Request-ID": request_id})


# ── human-in-the-loop confirmations (S-03) ───────────────────────────
# Pending write-tool calls live in the orchestrator (S3). The gateway authenticates the user,
# creates a request context (audit, masking) and forwards to S3's internal API. Only the subject
# that triggered the tool call can list/approve/reject it.

async def _confirm_proxy(request: Request, method: str, path: str):
    if (r := ready()) is not None:
        return r
    trace_id, traceparent = tracectx.continue_or_start(request.headers.get("traceparent"))
    subj = await _auth(request, trace_id)
    if isinstance(subj, JSONResponse):
        return subj
    request_id = "req_" + secrets.token_hex(8)
    vault = Vault()
    rule = {"id": "human-confirmation", "route": {"mode": "deny"}}
    ctx = ReqCtx(request_id, trace_id, subj, vault, "n/a", rule, [])
    S.contexts[request_id] = ctx
    headers = _ctx_headers(ctx, traceparent, [], False)
    try:
        resp = await S.http.request(method, UPSTREAM.rsplit("/v1", 1)[0] + path, headers=headers)
    except httpx.TransportError:
        S.contexts.pop(request_id, None)
        return err(502, "upstream_unavailable", "Orchestrator nicht erreichbar")
    try:
        data = resp.json()
    except ValueError:
        S.contexts.pop(request_id, None)
        return err(502, "upstream_unavailable", "Ungültige Orchestrator-Antwort")
    if resp.status_code == 200 and isinstance(data, dict) and isinstance(data.get("result"), str):
        data["result"] = demask(data["result"], vault, subj.roles)   # tool result was masked via this context
    S.contexts.pop(request_id, None)
    return JSONResponse(data, status_code=resp.status_code, headers={"X-AISM-Request-ID": request_id,
                                                                      "traceparent": traceparent})


@public.get("/aism/v1/confirmations")
async def confirmations_list(request: Request):
    return await _confirm_proxy(request, "GET", "/internal/v1/confirmations")


@public.post("/aism/v1/confirmations/{cid}/approve")
async def confirmations_approve(cid: str, request: Request):
    if not cid.replace("_", "").isalnum():
        return err(400, "invalid_request", "ungültige confirmation_id")
    return await _confirm_proxy(request, "POST", f"/internal/v1/confirmations/{cid}/approve")


@public.post("/aism/v1/confirmations/{cid}/reject")
async def confirmations_reject(cid: str, request: Request):
    if not cid.replace("_", "").isalnum():
        return err(400, "invalid_request", "ungültige confirmation_id")
    return await _confirm_proxy(request, "POST", f"/internal/v1/confirmations/{cid}/reject")


# ── internal app (S3 only) ───────────────────────────────────────────

internal = FastAPI(title="AISM gateway internal API", docs_url=None, redoc_url=None, openapi_url=None)
INTERNAL_AUDIT_EVENTS = {"tool.call.allowed", "tool.call.denied", "tool.result", "rag.query", "egress.websearch",
                         "tool.call.pending", "tool.call.confirmed", "tool.call.rejected"}
INTERNAL_AUDIT_FIELDS = {"tool", "decision", "reason", "args_sha256", "result_sha256", "collections", "chunks",
                         "round", "pii_masked", "stage", "tool_call_id", "confirmation_id", "expires_at",
                         "query_sha256", "results", "placeholders_stripped", "engine_host"}


def _internal_guard(request: Request) -> JSONResponse | None:
    if not INTERNAL_TOKEN:
        return err(503, "internal_token_missing", "INTERNAL_TOKEN nicht gesetzt (fail-closed)")
    tok = request.headers.get("x-aism-internal-token", "")
    if not hmac.compare_digest(tok.encode(), INTERNAL_TOKEN.encode()):
        return err(401, "invalid_token", "Internes Token ungültig")
    return ready()


@internal.post("/internal/v1/mask")
async def internal_mask(request: Request):
    if (g := _internal_guard(request)) is not None:
        return g
    body = await request.json()
    ctx = S.contexts.get(body.get("request_id", ""))
    if ctx is None:
        return err(404, "unknown_request", "Request-Kontext unbekannt oder abgelaufen")
    context = body.get("context", "tool_result")
    if context not in ("tool_result", "rag_ingest", "web_query", "prompt", "response"):
        return err(400, "invalid_request", "context ungültig")
    content = body.get("content")
    if not isinstance(content, str):
        return err(400, "invalid_request", "content muss ein String sein")
    before = dict(ctx.vault.counts)
    try:
        masked, _ = S.masker.mask(content, ctx.vault, context)
    except DetectorUnavailable:
        log.exception("pii detector failed")
        audit("request.denied", request_id=ctx.request_id, trace_id=ctx.trace_id, subject=ctx.subject.id,
              reason="pii_detector_unavailable", context=context)
        return err(503, "pii_detector_unavailable", "PII-Erkennung nicht verfügbar (fail-closed)")
    delta = {k: v - before.get(k, 0) for k, v in ctx.vault.counts.items() if v - before.get(k, 0)}
    if delta:
        audit("pii.masked", request_id=ctx.request_id, trace_id=ctx.trace_id, subject=ctx.subject.id,
              context=context, pii_masked=delta)
    return {"content": masked, "pii_masked": delta}


@internal.post("/internal/v1/audit")
async def internal_audit(request: Request):
    if (g := _internal_guard(request)) is not None:
        return g
    body = await request.json()
    ctx = S.contexts.get(body.get("request_id", ""))
    if ctx is None:
        return err(404, "unknown_request", "Request-Kontext unbekannt oder abgelaufen")
    ev = body.get("event")
    if ev not in INTERNAL_AUDIT_EVENTS:
        return err(400, "invalid_request", "event nicht zulässig")
    fields = {k: v for k, v in body.items() if k in INTERNAL_AUDIT_FIELDS}
    audit(ev, request_id=ctx.request_id, trace_id=ctx.trace_id, subject=ctx.subject.id, source="orchestrator", **fields)
    return {"ok": True}


@internal.post("/internal/egress/v1/chat/completions")
async def internal_egress(request: Request):
    if (g := _internal_guard(request)) is not None:
        return g
    pol = S.policy
    ctx = S.contexts.get(request.headers.get("x-aism-request-id", ""))
    if ctx is None:
        return err(404, "unknown_request", "Request-Kontext unbekannt oder abgelaufen")
    base = dict(request_id=ctx.request_id, trace_id=ctx.trace_id, subject=ctx.subject.id)
    body = await request.json()
    route = ctx.rule["route"]
    reason = request.headers.get("x-aism-fallback-reason", "explicit")
    provider = pol.provider_for_model(body.get("model", "")) if body.get("model") else None
    if provider is None or provider["type"] != "cloud":
        provider = next((pol.provider(p) for p in route.get("cloudProviders", [])), None)
    ok = (pol.spec["routing"].get("cloudEnabled") and route["mode"] == "local-with-cloud-fallback"
          and provider is not None and provider["id"] in route.get("cloudProviders", [])
          and (reason == "explicit" or reason in route.get("fallbackOn", [])))
    # PEP-9: re-check that the outgoing payload contains no detectable PII
    probe = Vault()
    try:
        for m in body.get("messages") or []:
            if isinstance(m.get("content"), str):
                S.masker.mask(m["content"], probe, "prompt")
    except DetectorUnavailable:
        log.exception("pii detector failed")
        audit("request.denied", **base, reason="pii_detector_unavailable", detail="egress")
        return err(503, "pii_detector_unavailable", "PII-Erkennung nicht verfügbar (fail-closed)")
    if probe.counts:
        ok = False
        reason = "pii_detected_in_egress_payload"
    if not ok:
        audit("request.denied", **base, reason="egress_denied", detail=reason, rule_ids=[ctx.rule["id"]])
        return err(403, "egress_denied", "Cloud-Egress nicht freigegeben")
    key = resolve_secret(provider.get("credentialRef"))
    if not key:
        return err(503, "upstream_unavailable", "Cloud-Credential fehlt")
    body = {**body, "model": body.get("model") if body.get("model") in provider["models"] else provider["models"][0]}
    audit("egress.cloud", **base, provider=provider["id"], rule_ids=[ctx.rule["id"]], reason=reason,
          payload_sha256=sha256_json(body))
    hdrs = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    if request.headers.get("traceparent"):
        hdrs["traceparent"] = request.headers["traceparent"]   # X-AISM-* headers are NOT forwarded
    try:
        resp = await S.http.send(S.http.build_request("POST", provider["endpoint"].rstrip("/") + "/chat/completions",
                                                      json=body, headers=hdrs), stream=True)
    except httpx.TransportError:
        return err(502, "upstream_unavailable", "Cloud-Provider nicht erreichbar")

    async def passthrough():
        try:
            async for b in resp.aiter_raw():
                yield b
        finally:
            await resp.aclose()
    return StreamingResponse(passthrough(), status_code=resp.status_code,
                             media_type=resp.headers.get("content-type", "application/json"))
