"""AISM conformance suite – shared configuration, fixtures and report plugin.

Configuration via environment variables or pytest options (options win):

  AISM_BASE_URL      --aism-base-url     Gateway (S2) base URL, default http://127.0.0.1:8000
  AISM_API_KEY       --aism-api-key      Client key sent as Bearer token
  AISM_USER_JWT      --aism-user-jwt     Optional user JWT (sent in AISM_USER_JWT_HEADER)
  AISM_USER_JWT_HEADER                   Header for AISM_USER_JWT, default X-OpenWebUI-User-Jwt
  AISM_MODEL         --aism-model        Model id; default: first id from /v1/models
  AISM_MOCK_URL      --aism-mock-url     Capture mock upstream (see mock_upstream.py), e.g. http://127.0.0.1:18080
  AISM_DIRECT_URLS                       Comma-separated URLs that MUST NOT be reachable from the client network
  AISM_COMPOSE_FILE                      Compose file for static checks, default ../../docker-compose.yml
  AISM_POLICY_FILE                       Policy file, default ../../policy/policy.yaml, fallback policy.example.yaml
  AISM_AUDIT_LOG                         Path to the audit JSONL file (optional)
  AISM_TIMEOUT                           HTTP timeout in seconds, default 30
  AISM_REPORT                            Report path, default aism-report.json (badge files next to it)
  AISM_ALLOWED_SIGNERS                   allowed_signers file; K3-01 verifies a single-signature policy with it
  AISM_KEYRING                           keyring.yaml; K3-01 verifies a .sigs bundle, K3-12 rotates it
  AISM_SIGNING_KEYS                      manifest (identity, relative key path) for K3-12; test keys only
  AISM_POLICY_FAULT_INJECTION            1 = K3-08 temporarily replaces the mounted policy (restored afterwards)
  AISM_POLICY_RELOAD_WAIT                seconds to wait for a policy reload (K3-08), default 15
  AISM_AUDIT_S3_ENDPOINT/BUCKET/PREFIX   WORM sink for K3-13..15 (prefix default aism/)
  AISM_AUDIT_S3_ACCESS_KEY/SECRET_KEY    runtime S3 credentials (never committed)
  AISM_AUDIT_SIGNER                      keyring identity with role audit
  AISM_KEYRING_STATE                     keyring-state.json next to the audit log
  AISM_AUDIT_FAULT_INJECTION             1 = K3-15 may plant {prefix}fault/block (removed afterwards)
  AISM_OIDC_TOKEN, AISM_OIDC_NEGATIVE_TOKENS   IdP tokens for K2-21 (valid / must be rejected)
  AISM_LOCAL_DOWN, AISM_CLOUD_MOCK_URL   cloud-fallback scenario only (scenario_cloud_fallback.py)
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import pathlib
import uuid

import httpx
import pytest
import yaml

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
SUITE_VERSION = "0.3.0"

DEFAULT_DIRECT_URLS = ",".join([
    "http://127.0.0.1:8080/health",    # llama-server default port
    "http://127.0.0.1:8081/health",    # common alternative for embeddings
    "http://127.0.0.1:6333/",          # Qdrant REST
    "http://127.0.0.1:9000/v1/models", # orchestrator
    "http://llama-server:8080/health", # service name (only resolvable inside Docker networks)
    "http://llama-embed:8080/health",
    "http://qdrant:6333/",
    "http://orchestrator:9000/v1/models",
])


def pytest_addoption(parser):
    g = parser.getgroup("aism")
    g.addoption("--aism-base-url", default=None)
    g.addoption("--aism-api-key", default=None)
    g.addoption("--aism-user-jwt", default=None)
    g.addoption("--aism-model", default=None)
    g.addoption("--aism-mock-url", default=None)


class AismConfig:
    def __init__(self, config: pytest.Config):
        opt = config.getoption
        env = os.environ.get
        self.base_url = (opt("--aism-base-url") or env("AISM_BASE_URL") or "http://127.0.0.1:8000").rstrip("/")
        self.api_key = opt("--aism-api-key") or env("AISM_API_KEY") or ""
        self.user_jwt = opt("--aism-user-jwt") or env("AISM_USER_JWT") or ""
        self.user_jwt_header = env("AISM_USER_JWT_HEADER", "X-OpenWebUI-User-Jwt")
        self.model = opt("--aism-model") or env("AISM_MODEL") or ""
        self.mock_url = (opt("--aism-mock-url") or env("AISM_MOCK_URL") or "").rstrip("/")
        self.direct_urls = [u.strip() for u in env("AISM_DIRECT_URLS", DEFAULT_DIRECT_URLS).split(",") if u.strip()]
        self.compose_file = pathlib.Path(env("AISM_COMPOSE_FILE", str(REPO / "docker-compose.yml")))
        pf = env("AISM_POLICY_FILE")
        if pf:
            self.policy_file = pathlib.Path(pf)
        else:
            p = REPO / "policy" / "policy.yaml"
            self.policy_file = p if p.exists() else REPO / "policy" / "policy.example.yaml"
        self.policy_schema = REPO / "policy" / "policy.schema.json"
        al = env("AISM_AUDIT_LOG")
        self.audit_log = pathlib.Path(al) if al else None
        self.timeout = float(env("AISM_TIMEOUT", "30"))
        self.report = pathlib.Path(env("AISM_REPORT", "aism-report.json"))

    def auth_headers(self) -> dict[str, str]:
        h = {}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        if self.user_jwt:
            h[self.user_jwt_header] = self.user_jwt
        return h


# ── fixtures ──────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def cfg(pytestconfig) -> AismConfig:
    return AismConfig(pytestconfig)


@pytest.fixture(scope="session")
def gateway(cfg):
    """httpx client for S2. Skips live tests if the gateway is not reachable."""
    client = httpx.Client(base_url=cfg.base_url, headers=cfg.auth_headers(), timeout=cfg.timeout)
    try:
        client.get("/health", timeout=5)
    except httpx.TransportError as exc:
        client.close()
        pytest.skip(f"Gateway {cfg.base_url} nicht erreichbar ({exc.__class__.__name__}); Live-Tests übersprungen")
    yield client
    client.close()


@pytest.fixture(scope="session")
def anon_gateway(cfg, gateway):
    """Client without credentials (for PEP-1 tests)."""
    with httpx.Client(base_url=cfg.base_url, timeout=cfg.timeout) as c:
        yield c


@pytest.fixture(scope="session")
def model(cfg, gateway) -> str:
    if cfg.model:
        return cfg.model
    r = gateway.get("/v1/models")
    r.raise_for_status()
    data = r.json().get("data") or []
    if not data:
        pytest.skip("/v1/models liefert keine Modelle; AISM_MODEL setzen")
    return data[0]["id"]


class CaptureMock:
    def __init__(self, client: httpx.Client):
        self.client = client

    def reset(self):
        self.client.post("/_reset").raise_for_status()

    def captured(self, path_prefix: str = "") -> list[dict]:
        r = self.client.get("/_captured")
        r.raise_for_status()
        return [e for e in r.json() if e["path"].startswith(path_prefix)]


@pytest.fixture()
def capture(cfg):
    if not cfg.mock_url:
        pytest.skip("AISM_MOCK_URL nicht gesetzt (Capture-Mock erforderlich, siehe README)")
    with httpx.Client(base_url=cfg.mock_url, timeout=10) as c:
        try:
            m = CaptureMock(c)
            m.reset()
        except httpx.TransportError as exc:
            pytest.skip(f"Capture-Mock {cfg.mock_url} nicht erreichbar: {exc}")
        yield m


@pytest.fixture(scope="session")
def synthetic_pii() -> dict:
    return json.loads((HERE / "testdata" / "synthetic_pii.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def compose(cfg) -> dict:
    if not cfg.compose_file.exists():
        pytest.skip(f"Compose-Datei fehlt: {cfg.compose_file}")
    return yaml.safe_load(cfg.compose_file.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def policy(cfg) -> dict:
    if not cfg.policy_file.exists():
        pytest.skip(f"Policy-Datei fehlt: {cfg.policy_file}")
    return yaml.safe_load(cfg.policy_file.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def audit_entries(cfg) -> list[dict]:
    if not cfg.audit_log:
        pytest.skip("AISM_AUDIT_LOG nicht gesetzt")
    if not cfg.audit_log.exists():
        pytest.skip(f"Audit-Log fehlt: {cfg.audit_log}")
    lines = [l for l in cfg.audit_log.read_text(encoding="utf-8").splitlines() if l.strip()]
    return [json.loads(l) for l in lines]


@pytest.fixture()
def nonce() -> str:
    return "aism-" + uuid.uuid4().hex[:12]


# ── report plugin ─────────────────────────────────────────────────────

LEVELS = ["K1", "K2", "K3"]
LEVEL_NAMES = {"K1": "Basic", "K2": "Governed", "K3": "Sovereign/Auditable"}
_results: dict[str, dict] = {}


def _meta(item) -> dict | None:
    m = item.get_closest_marker("aism")
    return dict(m.kwargs) if m else None


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    meta = _meta(item)
    if not meta:
        return
    if rep.when == "call" or (rep.when == "setup" and rep.outcome != "passed"):
        msg = ""
        if rep.outcome == "skipped" and isinstance(rep.longrepr, tuple):
            msg = rep.longrepr[2]
        elif rep.outcome == "failed":
            msg = (rep.longreprtext or "").strip().splitlines()[-1][:500] if rep.longreprtext else ""
        _results[meta["id"]] = {
            "id": meta["id"],
            "level": meta["level"],
            "requirement": meta["req"],
            "spec_refs": list(meta.get("refs", [])),
            "test": item.nodeid,
            "outcome": rep.outcome,
            "duration_s": round(rep.duration, 3),
            "message": msg,
        }


def _evaluate(results: list[dict]) -> tuple[dict, str]:
    levels = {}
    achieved = "none"
    chain_ok = True
    for lvl in LEVELS:
        musts = [r for r in results if r["level"] == lvl and r["requirement"] == "MUSS"]
        failed = [r["id"] for r in musts if r["outcome"] == "failed"]
        not_run = [r["id"] for r in musts if r["outcome"] == "skipped"]
        should_failed = [r["id"] for r in results if r["level"] == lvl and r["requirement"] == "SOLLTE" and r["outcome"] == "failed"]
        ok = bool(musts) and not failed and not not_run
        levels[lvl] = {"name": LEVEL_NAMES[lvl], "achieved": ok and chain_ok, "must_failed": failed,
                       "must_not_run": not_run, "should_failed": should_failed}
        chain_ok = chain_ok and ok
        if levels[lvl]["achieved"]:
            achieved = lvl
    return levels, achieved


def _badge_svg(label: str, message: str, color: str) -> str:
    lw, mw = 7 * len(label) + 12, 7 * len(message) + 12
    w = lw + mw
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" role="img" aria-label="{label}: {message}">'
            f'<rect width="{lw}" height="20" fill="#555"/><rect x="{lw}" width="{mw}" height="20" fill="{color}"/>'
            f'<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11" text-anchor="middle">'
            f'<text x="{lw/2}" y="14">{label}</text><text x="{lw + mw/2}" y="14">{message}</text></g></svg>')


def pytest_sessionfinish(session, exitstatus):
    if not _results:
        return
    cfg = AismConfig(session.config)
    results = sorted(_results.values(), key=lambda r: r["id"])
    levels, achieved = _evaluate(results)
    summary = {k: sum(1 for r in results if r["outcome"] == k) for k in ("passed", "failed", "skipped")}
    report = {
        "aism_report_version": "1",
        "suite_version": SUITE_VERSION,
        "generated_at": _dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "target": {"base_url": cfg.base_url, "compose_file": str(cfg.compose_file), "policy_file": str(cfg.policy_file)},
        "summary": summary,
        "levels": levels,
        "achieved_level": achieved,
        "results": results,
    }
    cfg.report.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    message = f"{achieved} {LEVEL_NAMES[achieved]}" if achieved != "none" else "nicht konform"
    color = {"none": "#e05d44", "K1": "#dfb317", "K2": "#97ca00", "K3": "#4c1"}[achieved]
    stem = cfg.report.with_suffix("")
    (stem.parent / (stem.name + "-badge.json")).write_text(json.dumps(
        {"schemaVersion": 1, "label": "AISM", "message": message, "color": color.lstrip("#")}, ensure_ascii=False), encoding="utf-8")
    (stem.parent / (stem.name + "-badge.svg")).write_text(_badge_svg("AISM", message, color), encoding="utf-8")
