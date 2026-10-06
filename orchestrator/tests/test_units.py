"""Unit tests for the orchestrator stub (run: python -m pytest orchestrator/tests)."""
import pathlib
import sys

from fastapi.testclient import TestClient

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "orchestrator"))

import aism_orchestrator.main as orch  # noqa: E402

POLICY = ROOT / "policy" / "policy.example.yaml"
SCHEMA = ROOT / "policy" / "policy.schema.json"


def _reset_policy():
    orch.POLICY_PATH = str(POLICY)
    orch.SCHEMA_PATH = str(SCHEMA)
    orch.S.policy = None
    orch.S.digest = None
    orch.S.mtime = 0
    orch.S.by_digest.clear()


def test_child_traceparent_keeps_trace_id():
    trace = "ab" * 16
    span = "cd" * 8
    header = orch.child_tp(f"00-{trace}-{span}-01")
    parts = header["traceparent"].split("-")
    assert parts[0] == "00" and parts[1] == trace and parts[3] == "01"
    assert parts[2] != span and len(parts[2]) == 16
    assert orch.child_tp("not-a-traceparent") == {}


def test_duration():
    assert orch._duration("2m") == 120
    assert orch._duration(None) == 10
    assert orch._duration("") == 10


def test_load_policy_digest_binding():
    _reset_policy()
    loaded = orch.load_policy()
    assert loaded is not None and loaded["metadata"]["name"]
    digest = orch.S.digest
    assert digest.startswith("sha256:")
    assert orch.policy_for(digest) is loaded
    assert orch.policy_for("sha256:" + "0" * 64) is None
    assert orch.policy_for(None) is None
    assert orch.policy_for("") is None
    orch.POLICY_PATH = "/no/such/aism-policy.yaml"
    orch.S.mtime = 0
    assert orch.load_policy() is loaded


def test_guard_rejects_missing_token_and_unknown_digest():
    _reset_policy()
    orch.INTERNAL_TOKEN = "test-internal-token"
    with TestClient(orch.app) as client:
        denied = client.get("/v1/models")
        assert denied.status_code == 401
        mismatch = client.get("/v1/models", headers={
            "x-aism-internal-token": "test-internal-token",
            "x-aism-policy-digest": "sha256:" + "ab" * 32,
        })
        assert mismatch.status_code == 503
        assert mismatch.json()["error"]["code"] == "policy_mismatch"


def test_rate_ok_per_subject():
    orch.S.rate.clear()
    tool = {"id": "ticket_status_lookup", "rateLimit": {"requests": 2, "per": "1m", "scope": "subject"}}
    assert orch.rate_ok(tool, "alice")
    assert orch.rate_ok(tool, "alice")
    assert orch.rate_ok(tool, "alice") is False
    assert orch.rate_ok(tool, "bob")
    orch.S.rate.clear()


def test_tool_specs_filters_allowlist():
    pol = {"spec": {"tools": {"definitions": [
        {"id": "ticket_status_lookup", "description": "read", "argumentsSchema": {"type": "object"}},
        {"id": "delete_ticket", "description": "no", "argumentsSchema": {"type": "object"}},
    ]}}}
    names = [spec["function"]["name"] for spec in orch.tool_specs(pol, ["ticket_status_lookup"])]
    assert names == ["ticket_status_lookup"]
    old = orch.SEARXNG
    orch.SEARXNG = "http://searxng:8080"
    try:
        with_web = [spec["function"]["name"] for spec in orch.tool_specs(pol, ["ticket_status_lookup"], web=True)]
    finally:
        orch.SEARXNG = old
    assert with_web == ["ticket_status_lookup", "web_search"]


def test_health_without_policy(monkeypatch):
    orch.POLICY_PATH = "/no/such/aism-policy.yaml"
    orch.S.policy = None
    orch.S.mtime = 0
    orch.S.by_digest.clear()
    monkeypatch.setattr(orch, "INTERNAL_TOKEN", "t")
    with TestClient(orch.app) as client:
        body = client.get("/health").json()
    assert body["status"] == "unavailable"
