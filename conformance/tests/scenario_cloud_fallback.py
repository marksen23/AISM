"""Scenario AISM-K3-10: cloud fallback when the local model (S6) is down.

Run only with compose.cloud-fallback.yml (local inference container stopped, cloud test policy,
HTTPS mock cloud provider). Not collected by default (file name does not match test_*.py):
    pytest scenario_cloud_fallback.py test_k3_sovereign.py test_k2_governed.py -k "fallback or audit or egress"
Env: AISM_CLOUD_MOCK_URL (capture port of the mock cloud), AISM_LOCAL_DOWN=1, AISM_FORWARD_JWT_SECRET.
"""
from __future__ import annotations

import json
import os
import time

import httpx
import jwt
import pytest

from aism_helpers import chat_body, find_plaintext, parse_sse

pytestmark = pytest.mark.skipif(os.environ.get("AISM_LOCAL_DOWN") != "1" or not os.environ.get("AISM_CLOUD_MOCK_URL"),
                                reason="nur im Szenario compose.cloud-fallback.yml (AISM_LOCAL_DOWN=1)")


@pytest.fixture()
def cloud():
    with httpx.Client(base_url=os.environ["AISM_CLOUD_MOCK_URL"], timeout=10) as c:
        c.post("/_reset").raise_for_status()
        yield c


def _cloud_reqs(cloud, nonce):
    return [e for e in cloud.get("/_captured").json() if e["path"] == "/v1/chat/completions" and nonce in json.dumps(e["body"])]


def _staff_only_headers(cfg):
    now = int(time.time())
    t = jwt.encode({"sub": "staff-user", "role": "user", "iss": "open-webui", "iat": now, "exp": now + 600},
                   os.environ["AISM_FORWARD_JWT_SECRET"], algorithm="HS256")
    return {"Authorization": f"Bearer {cfg.api_key}", cfg.user_jwt_header: t}


@pytest.mark.live
@pytest.mark.aism(id="AISM-K3-10", level="K3", req="SOLLTE", refs=["M-04", "PEP-9", "S-13"])
def test_cloud_fallback_only_as_policy_allows(cfg, gateway, cloud, model, synthetic_pii, nonce):
    pol = gateway.get("/aism/v1/policy").json()
    assert pol.get("signature", {}).get("verified"), "Szenario-Policy nicht signaturgeprüft"
    # a) it-ops, no PII (data class internal) -> rule internal-fallback-it-ops -> cloud
    r = gateway.post("/v1/chat/completions", json=chat_body(model, f"[{nonce}-a] Wie viele Tickets sind offen?"))
    assert r.status_code == 200, f"Fallback fehlgeschlagen: {r.status_code} {r.text[:200]}"
    reqs = _cloud_reqs(cloud, f"{nonce}-a")
    assert len(reqs) == 1, f"erwartet 1 Cloud-Request, beobachtet {len(reqs)}"
    assert reqs[0]["body"]["model"] == "example-large-model"
    assert reqs[0]["headers"].get("authorization-present") == "true"
    assert not any(k.startswith("x-aism-") for k in reqs[0]["headers"]), "interne X-AISM-Header an die Cloud"
    # a2) streaming via cloud
    with gateway.stream("POST", "/v1/chat/completions",
                        json=chat_body(model, f"[{nonce}-s] Status bitte", stream=True)) as rs:
        assert rs.status_code == 200
        chunks, done, problems = parse_sse(rs.iter_lines())
    assert done and not problems and chunks, problems
    assert len(_cloud_reqs(cloud, f"{nonce}-s")) == 1
    # b) PII -> confidential-local-only -> no cloud, error to the client
    rb = gateway.post("/v1/chat/completions", json=chat_body(model, f"[{nonce}-b] " + synthetic_pii["prompts"]["de"]))
    assert rb.status_code >= 500 and isinstance(rb.json().get("error"), dict), f"unerwartet: {rb.status_code}"
    allc = json.dumps(cloud.get("/_captured").json(), ensure_ascii=False)
    assert f"{nonce}-b" not in allc, "vertraulicher Request ging an die Cloud"
    assert not find_plaintext(allc, [e["value"] for e in synthetic_pii["entities"]]), "PII an die Cloud"
    # c) staff without it-ops -> baseline-local (local-only) -> no cloud
    with httpx.Client(base_url=cfg.base_url, timeout=cfg.timeout) as c:
        rc = c.post("/v1/chat/completions", headers=_staff_only_headers(cfg),
                    json=chat_body(model, f"[{nonce}-c] Wie viele Tickets sind offen?"))
    assert rc.status_code >= 500, f"unerwartet: {rc.status_code}"
    assert not _cloud_reqs(cloud, f"{nonce}-c"), "Request ohne Fallback-Freigabe ging an die Cloud"
