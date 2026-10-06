"""AISM K1 Basic: gateway enforced, OpenAI-compatible API, health."""
from __future__ import annotations

import httpx
import pytest

from aism_helpers import chat_body, compose_env as _env, parse_sse

# ── live tests against S2 ─────────────────────────────────────────────


@pytest.mark.live
@pytest.mark.aism(id="AISM-K1-01", level="K1", req="MUSS", refs=["Spez. §6.2 (GET /health)"])
def test_health(gateway):
    r = gateway.get("/health")
    assert r.status_code == 200, f"/health lieferte {r.status_code}"


@pytest.mark.live
@pytest.mark.aism(id="AISM-K1-02", level="K1", req="MUSS", refs=["M-06"])
def test_models_list_format(gateway):
    r = gateway.get("/v1/models")
    assert r.status_code == 200
    body = r.json()
    assert body.get("object") == "list"
    assert isinstance(body.get("data"), list) and body["data"], "data muss eine nicht-leere Liste sein"
    for m in body["data"]:
        assert isinstance(m.get("id"), str) and m["id"]


@pytest.mark.live
@pytest.mark.aism(id="AISM-K1-03", level="K1", req="MUSS", refs=["M-06"])
def test_chat_completion_schema(gateway, model):
    r = gateway.post("/v1/chat/completions", json=chat_body(model, "AISM conformance: antworte mit OK."))
    assert r.status_code == 200, r.text[:300]
    body = r.json()
    assert body.get("object") == "chat.completion"
    choice = body["choices"][0]
    assert choice["message"]["role"] == "assistant"
    assert choice.get("finish_reason") in {"stop", "length", "tool_calls"}


@pytest.mark.live
@pytest.mark.aism(id="AISM-K1-04", level="K1", req="MUSS", refs=["M-06", "Spez. §6.6"])
def test_sse_stream_format(gateway, model):
    with gateway.stream("POST", "/v1/chat/completions",
                        json=chat_body(model, "AISM conformance: zähle bis drei.", stream=True)) as r:
        assert r.status_code == 200, r.read()[:300]
        ctype = r.headers.get("content-type", "")
        assert ctype.startswith("text/event-stream"), f"Content-Type ist {ctype!r}"
        chunks, saw_done, problems = parse_sse(r.iter_lines())
    assert not problems, problems
    assert chunks, "keine chat.completion.chunk-Ereignisse"
    assert saw_done, "Stream endet nicht mit data: [DONE]"
    finish = [c["choices"][0].get("finish_reason") for c in chunks if c.get("choices")]
    assert any(f in {"stop", "length", "tool_calls"} for f in finish), "kein finish_reason im Stream"


@pytest.mark.live
@pytest.mark.aism(id="AISM-K1-05", level="K1", req="MUSS", refs=["M-01", "S-06"])
def test_gateway_bypass_not_possible(cfg, gateway):
    """Backend endpoints (S3, S4, S6) must not be reachable from the client network.

    Any HTTP response (regardless of status) counts as reachable. Run the suite from the
    client network (e.g. a container attached to `aism_frontend`) for a meaningful result.
    """
    reachable = []
    for url in cfg.direct_urls:
        if url.rstrip("/").startswith(cfg.base_url):
            continue
        try:
            r = httpx.get(url, timeout=3)
            reachable.append(f"{url} -> HTTP {r.status_code}")
        except httpx.TransportError:
            pass
    assert not reachable, "Direkt erreichbar (Gateway-Bypass möglich): " + "; ".join(reachable)


@pytest.mark.live
@pytest.mark.aism(id="AISM-K1-06", level="K1", req="MUSS", refs=["Spez. §6.2 Schritt 1", "PEP-1"])
def test_unauthenticated_request_rejected(anon_gateway, model):
    r = anon_gateway.post("/v1/chat/completions", json=chat_body(model, "AISM conformance: ohne Token"))
    assert r.status_code == 401, f"erwartet 401, erhalten {r.status_code}"


@pytest.mark.live
@pytest.mark.aism(id="AISM-K1-07", level="K1", req="SOLLTE", refs=["Spez. §6 (Fehlerformat)"])
def test_error_object_format(gateway, model):
    r = gateway.post("/v1/chat/completions", json={"model": model})  # messages missing
    assert 400 <= r.status_code < 500, f"erwartet 4xx, erhalten {r.status_code}"
    err = r.json().get("error")
    assert isinstance(err, dict) and isinstance(err.get("message"), str), "OpenAI-Fehlerobjekt fehlt"


# ── static checks on docker-compose.yml ──────────────────────────────

UI_SERVICES = ("open-webui",)
INFERENCE_SERVICES = ("llama-server", "llama-embed")


@pytest.mark.static
@pytest.mark.aism(id="AISM-K1-08", level="K1", req="MUSS", refs=["M-01", "Spez. §6.1"])
def test_static_ui_only_talks_to_gateway(compose):
    for name in UI_SERVICES:
        svc = compose["services"].get(name)
        assert svc, f"Dienst {name} fehlt"
        env = _env(svc)
        assert env.get("OPENAI_API_BASE_URL", "").startswith("http://governance-proxy:"), env.get("OPENAI_API_BASE_URL")
        assert "OLLAMA_BASE_URL" not in env and "OLLAMA_BASE_URLS" not in env
        assert env.get("ENABLE_OLLAMA_API", "").lower() == "false"
        assert env.get("ENABLE_DIRECT_CONNECTIONS", "").lower() == "false"


@pytest.mark.static
@pytest.mark.aism(id="AISM-K1-09", level="K1", req="MUSS", refs=["M-01", "S-06"])
def test_static_inference_not_published(compose):
    for name in INFERENCE_SERVICES:
        svc = compose["services"].get(name)
        assert svc, f"Dienst {name} fehlt"
        assert not svc.get("ports"), f"{name} veröffentlicht Ports: {svc.get('ports')}"
        assert svc.get("network_mode") != "host", f"{name} nutzt network_mode: host"


@pytest.mark.static
@pytest.mark.aism(id="AISM-K1-10", level="K1", req="MUSS", refs=["M-13"])
def test_static_no_privileged_containers(compose):
    bad = [n for n, s in compose["services"].items() if s.get("privileged")]
    assert not bad, f"privileged: true bei {bad}"
