"""AISM K2 Governed: PII masking, tool allowlist, audit, RAG after masking, policy loaded."""
from __future__ import annotations

import json
import os
import re
import urllib.parse

import httpx
import jsonschema
import pytest

from aism_helpers import chat_body, compose_env as _env, find_plaintext, parse_sse, tool_messages


def _pii_values(synthetic_pii):
    return [e["value"] for e in synthetic_pii["entities"]]


# ── live ──────────────────────────────────────────────────────────────


@pytest.mark.live
@pytest.mark.aism(id="AISM-K2-01", level="K2", req="MUSS", refs=["M-15"])
def test_policy_loaded_endpoint(gateway):
    r = gateway.get("/aism/v1/policy")
    assert r.status_code == 200, f"/aism/v1/policy lieferte {r.status_code}"
    info = r.json()
    for key in ("name", "version", "digest"):
        assert info.get(key), f"Feld {key} fehlt"
    assert str(info["digest"]).startswith("sha256:")
    assert "spec" not in info, "Endpunkt darf keine Regelinhalte ausgeben"


@pytest.mark.live
@pytest.mark.capture
@pytest.mark.aism(id="AISM-K2-03", level="K2", req="MUSS", refs=["M-02", "PEP-2"])
def test_pii_masked_before_inference(gateway, model, capture, synthetic_pii, nonce):
    prompt = f"[{nonce}] " + synthetic_pii["prompts"]["de"]
    r = gateway.post("/v1/chat/completions", json=chat_body(model, prompt))
    assert r.status_code == 200, r.text[:300]
    reqs = [c for c in capture.captured("/v1/chat/completions") if nonce in json.dumps(c["body"])]
    assert reqs, "Upstream (Mock) hat keinen passenden Inferenz-Request erhalten"
    for c in reqs:
        dumped = json.dumps(c["body"], ensure_ascii=False)
        leaked = find_plaintext(dumped, _pii_values(synthetic_pii))
        assert not leaked, f"Klartext-PII an S6 übermittelt: {leaked}"
    dumped = json.dumps(reqs[0]["body"], ensure_ascii=False)
    assert any(p in dumped for p in synthetic_pii["expected_placeholder_prefixes"]), "keine Platzhalter gefunden"


@pytest.mark.live
@pytest.mark.capture
@pytest.mark.aism(id="AISM-K2-04", level="K2", req="MUSS", refs=["M-02", "M-09", "PEP-5"])
def test_rag_query_masked(gateway, model, capture, synthetic_pii, nonce):
    prompt = f"[{nonce}] Suche in der Dokumentation: " + synthetic_pii["prompts"]["de"]
    r = gateway.post("/v1/chat/completions", json=chat_body(model, prompt))
    assert r.status_code == 200, r.text[:300]
    emb = capture.captured("/v1/embeddings")
    if not emb:
        pytest.skip("Kein Embedding-Request beobachtet (RAG für diesen Request nicht aktiv?)")
    for c in emb:
        leaked = find_plaintext(json.dumps(c["body"], ensure_ascii=False), _pii_values(synthetic_pii))
        assert not leaked, f"Klartext-PII im Embedding-Request: {leaked}"


@pytest.mark.live
@pytest.mark.capture
@pytest.mark.aism(id="AISM-K2-05", level="K2", req="MUSS", refs=["M-07", "M-08", "PEP-7"])
def test_disallowed_tool_rejected(gateway, model, capture, nonce):
    r = gateway.post("/v1/chat/completions",
                     json=chat_body(model, f"[{nonce}] AISM-TEST:DISALLOWED_TOOL Lösche Ticket INC-2026-0042."))
    assert r.status_code < 500, f"Gateway-Fehler {r.status_code}"
    hooks = capture.captured("/webhook/")
    assert not hooks, f"Nicht erlaubtes Tool wurde ausgeführt: {[h['path'] for h in hooks]}"
    follow_ups = [c["body"] for c in capture.captured("/v1/chat/completions") if tool_messages(c["body"])]
    if r.status_code == 200:
        assert follow_ups, "Keine role=tool-Fehlermeldung an S6 zurückgegeben"
        tm = tool_messages(follow_ups[-1])[-1]
        assert tm.get("tool_call_id") == "call_mock01", "tool_call_id fehlt oder passt nicht"
        assert "mock" not in str(tm.get("content", "")), "Tool-Ergebnis stammt aus einer Ausführung"


@pytest.mark.live
@pytest.mark.capture
@pytest.mark.aism(id="AISM-K2-06", level="K2", req="MUSS", refs=["M-08", "PEP-7"])
def test_schema_invalid_arguments_rejected(gateway, model, capture, nonce):
    r = gateway.post("/v1/chat/completions",
                     json=chat_body(model, f"[{nonce}] AISM-TEST:INVALID_ARGS Status von Ticket?"))
    assert r.status_code < 500, f"Gateway-Fehler {r.status_code}"
    hooks = capture.captured("/webhook/")
    assert not hooks, f"Tool mit schemawidrigen Argumenten wurde ausgeführt: {[h['body'] for h in hooks]}"
    if r.status_code == 200:
        follow_ups = [c["body"] for c in capture.captured("/v1/chat/completions") if tool_messages(c["body"])]
        assert follow_ups, "Keine role=tool-Fehlermeldung an S6 zurückgegeben"


@pytest.mark.live
@pytest.mark.capture
@pytest.mark.aism(id="AISM-K2-16", level="K2", req="MUSS", refs=["M-07", "Spez. §6.3"])
def test_allowed_tool_executed_and_returned_as_tool_message(gateway, model, capture, nonce):
    """Positive control: without it, K2-05/K2-06 would also pass if no tool ever runs."""
    r = gateway.post("/v1/chat/completions",
                     json=chat_body(model, f"[{nonce}] AISM-TEST:ALLOWED_TOOL Status von Ticket INC-2026-0042?"))
    assert r.status_code == 200, r.text[:300]
    hooks = capture.captured("/webhook/ticket-status-lookup")
    assert len(hooks) == 1, f"erwartet genau 1 Tool-Ausführung, beobachtet {len(hooks)}"
    assert hooks[0]["body"] == {"ticket_id": "INC-2026-0042"}, f"Argumente verändert: {hooks[0]['body']}"
    follow_ups = [c["body"] for c in capture.captured("/v1/chat/completions") if tool_messages(c["body"])]
    assert follow_ups, "Tool-Ergebnis nicht als role=tool an S6 zurückgegeben"
    tm = tool_messages(follow_ups[-1])[-1]
    assert tm.get("tool_call_id") == "call_mock01"
    roles = [m.get("role") for m in follow_ups[-1]["messages"]]
    assert "assistant" in roles[:roles.index("tool")], "assistant-Nachricht mit tool_calls fehlt vor role=tool"


@pytest.mark.live
@pytest.mark.capture
@pytest.mark.aism(id="AISM-K2-07", level="K2", req="SOLLTE", refs=["Policy-Format §4.7"])
def test_only_permitted_tools_offered(gateway, model, capture, policy, nonce):
    r = gateway.post("/v1/chat/completions", json=chat_body(model, f"[{nonce}] Welche Tools hast du?"))
    assert r.status_code == 200
    allowed = {t["id"] for t in policy["spec"]["tools"]["definitions"]}
    if (policy["spec"].get("webSearch") or {}).get("enabled"):
        allowed.add("web_search")   # built-in tool of the reference orchestrator for S5, only offered if the policy allows web search
    for c in capture.captured("/v1/chat/completions"):
        offered = {t.get("function", {}).get("name") for t in (c["body"].get("tools") or [])}
        assert offered <= allowed, f"Nicht in der Policy definierte Tools angeboten: {offered - allowed}"


@pytest.mark.live
@pytest.mark.capture
@pytest.mark.aism(id="AISM-K2-18", level="K2", req="SOLLTE", refs=["PEP-10", "Spez. §6.6"])
def test_stream_demasking_handles_split_placeholders(gateway, model, capture, synthetic_pii, nonce):
    """Mock echoes the masked prompt in 3-char chunks; the client stream must contain each value
    either as plaintext (demasked for the subject's role) or as a complete placeholder – never a fragment."""
    emails = [e["value"] for e in synthetic_pii["entities"] if e["entity"] == "EMAIL"]
    prompt = f"[{nonce}] AISM-TEST:ECHO Kontakt: {emails[0]} und {emails[1]}."
    with gateway.stream("POST", "/v1/chat/completions", json=chat_body(model, prompt, stream=True)) as r:
        assert r.status_code == 200
        chunks, saw_done, problems = parse_sse(r.iter_lines())
    assert not problems and saw_done, problems
    text = "".join((c["choices"][0].get("delta") or {}).get("content") or "" for c in chunks if c.get("choices"))
    up = [c for c in capture.captured("/v1/chat/completions") if nonce in json.dumps(c["body"])]
    assert up and not find_plaintext(json.dumps(up[0]["body"], ensure_ascii=False), emails), "PII an S6 übermittelt"
    whole = re.sub(r"<[A-Z][A-Z_]*_\d+>", "", text)
    assert "<EMAIL" not in whole and "EMAIL_" not in whole, f"Platzhalter-Fragment im Stream: {text!r}"
    for e in emails:
        assert e in text or re.search(r"<EMAIL_\d+>", text), f"{e} weder demaskiert noch als Platzhalter"


def _first_offered(capture, nonce) -> set[str]:
    reqs = [c for c in capture.captured("/v1/chat/completions") if nonce in json.dumps(c["body"])]
    return {t.get("function", {}).get("name") for t in (reqs[0]["body"].get("tools") or [])} if reqs else set()


def _rank_of_entity(policy, entity) -> int:
    return max([c["rank"] for c in policy["spec"]["dataClasses"]
                if entity in (c.get("assignWhen") or {}).get("detectedEntities", [])] or [0])


@pytest.mark.live
@pytest.mark.capture
@pytest.mark.aism(id="AISM-K2-13", level="K2", req="MUSS", refs=["M-11", "PEP-6"])
def test_web_search_blocked_when_policy_disallows(gateway, model, capture, policy, synthetic_pii, nonce):
    """Automated variant: the mock always proposes `web_search`; for a request the policy does not
    allow to search (webSearch disabled, or data class above webSearch.allow.maxDataClassRank because
    the prompt contains PII), no request may reach SearXNG."""
    ws = policy["spec"].get("webSearch") or {}
    max_rank = (ws.get("allow") or {}).get("maxDataClassRank")
    if ws.get("enabled") and (max_rank is None or _rank_of_entity(policy, "EMAIL") <= max_rank):
        pytest.skip("Policy erlaubt Web-Suche auch für PII-Prompts; Verbotsfall nicht konstruierbar")
    prompt = f"[{nonce}] AISM-TEST:WEB_SEARCH Bitte im Web nachsehen. " + synthetic_pii["prompts"]["de"]
    r = gateway.post("/v1/chat/completions", json=chat_body(model, prompt))
    assert r.status_code < 500, f"Gateway-Fehler {r.status_code}"
    searches = capture.captured("/search")
    assert not searches, f"Suchanfrage an S5 trotz Policy-Verbot: {[s['path'] for s in searches]}"
    assert "web_search" not in _first_offered(capture, nonce), "web_search trotz Verbot angeboten"
    if r.status_code == 200:
        follow = [c["body"] for c in capture.captured("/v1/chat/completions") if tool_messages(c["body"])]
        assert follow, "keine role=tool-Fehlermeldung an S6"
        assert "untrusted_web_results" not in json.dumps(follow[-1])


@pytest.mark.live
@pytest.mark.capture
@pytest.mark.aism(id="AISM-K2-19", level="K2", req="SOLLTE", refs=["PEP-6", "M-02"])
def test_web_search_query_masked_and_results_masked(gateway, model, capture, policy, synthetic_pii, nonce):
    if not (policy["spec"].get("webSearch") or {}).get("enabled"):
        pytest.skip("webSearch.enabled=false")
    r = gateway.post("/v1/chat/completions",
                     json=chat_body(model, f"[{nonce}] AISM-TEST:WEB_SEARCH Wie ist der Status von INC-2026-0042?"))
    assert r.status_code == 200, r.text[:300]
    if "web_search" not in _first_offered(capture, nonce):
        pytest.skip("web_search für diesen Testclient nicht freigegeben (Rolle/Datenklasse)")
    searches = capture.captured("/search")
    assert len(searches) == 1, f"erwartet genau 1 Suchanfrage, beobachtet {len(searches)}"
    q = urllib.parse.unquote_plus(searches[0]["path"])
    leaked = find_plaintext(q, _pii_values(synthetic_pii))
    assert not leaked, f"Klartext-PII in der Suchanfrage: {leaked}"
    if (policy["spec"]["webSearch"]).get("stripPlaceholders", True):
        assert not re.search(r"<[A-Z][A-Z_]*_\d+>", q), f"Platzhalter nicht entfernt: {q}"
    follow = [c["body"] for c in capture.captured("/v1/chat/completions") if tool_messages(c["body"])]
    assert follow, "Suchergebnis nicht als role=tool an S6 zurückgegeben"
    dumped = json.dumps(tool_messages(follow[-1]), ensure_ascii=False)
    assert "untrusted_web_results" in dumped, "Ergebnis nicht als nicht vertrauenswürdig gekennzeichnet (S-05)"
    assert "max.mustermann@example.org" not in dumped, "PII aus dem Suchergebnis unmaskiert an S6"


def _write_tool(policy):
    return next((t for t in policy["spec"]["tools"]["definitions"] if t["id"] == "ticket_add_comment"), None)


@pytest.mark.live
@pytest.mark.capture
@pytest.mark.aism(id="AISM-K2-20", level="K2", req="SOLLTE", refs=["S-03", "M-08"])
def test_write_tool_requires_confirmation(gateway, anon_gateway, model, capture, policy, nonce):
    tdef = _write_tool(policy)
    if tdef is None or not (tdef.get("requireConfirmation") or tdef.get("access") == "write"):
        pytest.skip("Policy definiert kein bestätigungspflichtiges Tool ticket_add_comment")
    hdrs = {"X-AISM-Agent": tdef["allow"]["agents"][0]} if tdef["allow"].get("agents") else {}

    def trigger(tag):
        r = gateway.post("/v1/chat/completions", headers=hdrs,
                         json=chat_body(model, f"[{nonce}-{tag}] AISM-TEST:WRITE_TOOL Kommentar an INC-2026-0042"))
        assert r.status_code == 200, r.text[:300]
        if "ticket_add_comment" not in _first_offered(capture, f"{nonce}-{tag}"):
            pytest.skip("ticket_add_comment für diesen Testclient nicht freigegeben")
        follow = [c["body"] for c in capture.captured("/v1/chat/completions")
                  if tool_messages(c["body"]) and f"{nonce}-{tag}" in json.dumps(c["body"])]
        assert follow, "keine role=tool-Nachricht an S6"
        res = json.loads(tool_messages(follow[-1])[-1]["content"])
        assert res.get("status") == "pending_confirmation", f"keine ausstehende Bestätigung: {res}"
        return res["confirmation_id"]

    cid = trigger("a")
    assert not capture.captured("/webhook/"), "schreibendes Tool ohne Bestätigung ausgeführt"
    lst = gateway.get("/aism/v1/confirmations")
    assert lst.status_code == 200 and cid in [x["id"] for x in lst.json()["data"]], lst.text[:300]
    assert anon_gateway.post(f"/aism/v1/confirmations/{cid}/approve").status_code == 401
    ok = gateway.post(f"/aism/v1/confirmations/{cid}/approve", headers=hdrs)
    assert ok.status_code == 200 and ok.json().get("status") == "executed", ok.text[:300]
    hooks = capture.captured("/webhook/ticket-add-comment")
    assert len(hooks) == 1, f"erwartet genau 1 Ausführung nach Bestätigung, beobachtet {len(hooks)}"
    assert gateway.post(f"/aism/v1/confirmations/{cid}/approve", headers=hdrs).status_code == 409, "Bestätigung mehrfach verwendbar"
    cid2 = trigger("b")
    rej = gateway.post(f"/aism/v1/confirmations/{cid2}/reject", headers=hdrs)
    assert rej.status_code == 200 and rej.json().get("status") == "rejected"
    assert gateway.post(f"/aism/v1/confirmations/{cid2}/approve", headers=hdrs).status_code == 409
    assert len(capture.captured("/webhook/ticket-add-comment")) == 1, "abgelehnte Aktion wurde ausgeführt"


@pytest.mark.live
@pytest.mark.aism(id="AISM-K2-21", level="K2", req="SOLLTE", refs=["S-01"])
def test_oidc_bearer_validated_via_jwks(cfg, gateway, model):
    """Needs AISM_OIDC_TOKEN (valid IdP access token). Optional AISM_OIDC_NEGATIVE_TOKENS: comma-separated
    tokens that must be rejected (expired, wrong audience, unknown key, ...). A copy of the valid token
    with a modified signature is always tested."""
    tok = os.environ.get("AISM_OIDC_TOKEN")
    if not tok:
        pytest.skip("AISM_OIDC_TOKEN nicht gesetzt")
    h, p, s = tok.split(".")
    mid = len(s) // 2
    forged = f"{h}.{p}.{s[:mid]}{'A' if s[mid] != 'A' else 'B'}{s[mid + 1:]}"
    negatives = [forged] + [x for x in os.environ.get("AISM_OIDC_NEGATIVE_TOKENS", "").split(",") if x]
    with httpx.Client(base_url=cfg.base_url, timeout=cfg.timeout) as c:
        r = c.post("/v1/chat/completions", headers={"Authorization": f"Bearer {tok}"},
                   json=chat_body(model, "AISM conformance: OIDC"))
        assert r.status_code == 200, f"gültiges OIDC-Token abgelehnt: {r.status_code} {r.text[:200]}"
        for i, bad in enumerate(negatives):
            rb = c.post("/v1/chat/completions", headers={"Authorization": f"Bearer {bad}"},
                        json=chat_body(model, "AISM conformance: OIDC negativ"))
            assert rb.status_code == 401, f"ungültiges Token #{i} nicht abgelehnt: {rb.status_code}"


@pytest.mark.live
@pytest.mark.aism(id="AISM-K2-10", level="K2", req="MUSS", refs=["M-04", "PEP-4"])
def test_cloud_route_denied_when_disabled(gateway, policy, cfg):
    if policy["spec"]["routing"].get("cloudEnabled"):
        pytest.skip("Policy erlaubt Cloud-Routing (cloudEnabled=true); Test nicht anwendbar")
    cloud_models = [m for p in policy["spec"]["routing"]["providers"] if p["type"] == "cloud" for m in p["models"]]
    if not cloud_models:
        pytest.skip("Keine Cloud-Modelle in der Policy definiert")
    r = gateway.post("/v1/chat/completions", json=chat_body(cloud_models[0], "AISM conformance: Cloud-Test"))
    if r.status_code == 200:
        assert r.json().get("model") != cloud_models[0], "Antwort stammt vom Cloud-Modell trotz cloudEnabled=false"
    else:
        assert r.status_code in (400, 403, 404), f"unerwarteter Status {r.status_code}"
        assert isinstance(r.json().get("error"), dict)


# ── audit (requires AISM_AUDIT_LOG) ───────────────────────────────────


@pytest.mark.audit
@pytest.mark.aism(id="AISM-K2-08", level="K2", req="MUSS", refs=["M-05", "AUD"])
def test_audit_has_no_plaintext_pii(audit_entries, synthetic_pii):
    blob = "\n".join(json.dumps(e, ensure_ascii=False) for e in audit_entries)
    leaked = find_plaintext(blob, _pii_values(synthetic_pii))
    assert not leaked, f"Klartext-PII im Audit-Log: {leaked}"


@pytest.mark.audit
@pytest.mark.aism(id="AISM-K2-09", level="K2", req="MUSS", refs=["M-15", "AUD"])
def test_audit_entries_carry_policy_version(audit_entries):
    missing = [e.get("request_id", "?") for e in audit_entries
               if not (isinstance(e.get("policy"), dict) and e["policy"].get("version") and e["policy"].get("digest"))]
    assert not missing, f"{len(missing)} Audit-Einträge ohne policy.version/digest"


# ── static ────────────────────────────────────────────────────────────


@pytest.mark.static
@pytest.mark.aism(id="AISM-K2-02", level="K2", req="MUSS", refs=["M-15", "Policy-Format §8"])
def test_static_policy_schema_valid(cfg, policy):
    schema = json.loads(cfg.policy_schema.read_text(encoding="utf-8"))
    errors = sorted(jsonschema.Draft202012Validator(schema).iter_errors(policy), key=lambda e: e.json_path)
    assert not errors, "; ".join(f"{e.json_path}: {e.message}" for e in errors[:10])


@pytest.mark.static
@pytest.mark.aism(id="AISM-K2-11", level="K2", req="MUSS", refs=["M-02", "Spez. §6.1"])
def test_static_ui_builtin_rag_and_search_disabled(compose):
    env = _env(compose["services"]["open-webui"])
    expected = {
        "ENABLE_WEB_SEARCH": "false",
        "USER_PERMISSIONS_FEATURES_WEB_SEARCH": "false",
        "USER_PERMISSIONS_CHAT_FILE_UPLOAD": "false",
        "BYPASS_EMBEDDING_AND_RETRIEVAL": "true",
        "ENABLE_RETRIEVAL_QUERY_GENERATION": "false",
        "ENABLE_SEARCH_QUERY_GENERATION": "false",
        "ENABLE_PERSISTENT_CONFIG": "false",
    }
    wrong = {k: env.get(k) for k, v in expected.items() if env.get(k, "").lower() != v}
    assert not wrong, f"Abweichende Werte: {wrong}"
    assert "RAG_EMBEDDING_ENGINE" not in env and "VECTOR_DB" not in env, "UI-eigene RAG-Konfiguration vorhanden"


@pytest.mark.static
@pytest.mark.aism(id="AISM-K2-12", level="K2", req="MUSS", refs=["M-15"])
def test_static_policy_mounted_readonly(compose):
    svc = compose["services"]["governance-proxy"]
    ppath = _env(svc).get("POLICY_PATH", "/etc/aism/policy.yaml")
    vols = [v for v in (svc.get("volumes") or []) if isinstance(v, str) and v.count(":") >= 1]
    def target(v):
        parts = v.split(":")
        return parts[1] if len(parts) >= 2 else ""
    hits = [v for v in vols if ppath == target(v) or ppath.startswith(target(v).rstrip("/") + "/")]
    assert hits, f"POLICY_PATH {ppath} liegt in keinem Volume-Mount"
    assert all(v.endswith(":ro") for v in hits), "Policy-Mount ist nicht read-only"


@pytest.mark.static
@pytest.mark.aism(id="AISM-K2-15", level="K2", req="SOLLTE", refs=["S-12"])
def test_static_backend_network_internal(compose):
    nets = compose.get("networks") or {}
    assert (nets.get("backend") or {}).get("internal") is True, "Netz backend ist nicht internal"
    for name in ("llama-server", "llama-embed", "qdrant", "orchestrator"):
        svc_nets = compose["services"][name].get("networks") or []
        svc_nets = list(svc_nets) if not isinstance(svc_nets, dict) else list(svc_nets.keys())
        assert svc_nets == ["backend"], f"{name} hängt an {svc_nets}"
