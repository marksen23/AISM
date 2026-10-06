"""AISM K3 Sovereign/Auditable: signed policy, end-to-end trace IDs, egress proof, pinned deployment."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import re
import sys
import time

import pytest

from aism_helpers import chat_body

DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
FROM_RE = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*(\S+)", re.I | re.M)
REPO = pathlib.Path(__file__).resolve().parent.parent.parent


def _policysig():
    """AISM reference verifier (SSHSIG/Ed25519, needs `cryptography`); equivalent: ssh-keygen -Y verify."""
    path = REPO / "gateway" / "aism_gateway" / "policysig.py"
    spec = importlib.util.spec_from_file_location("aism_policysig", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod          # dataclasses need the module to be registered
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.static
@pytest.mark.aism(id="AISM-K3-01", level="K3", req="MUSS", refs=["S-11", "Policy-Format §6"])
def test_static_policy_signature_declared(cfg, policy):
    sig = policy.get("metadata", {}).get("signature")
    assert sig and sig.get("method") and sig.get("ref"), "metadata.signature fehlt"
    assert policy["metadata"].get("revision"), "metadata.revision fehlt"
    anchors = os.environ.get("AISM_ALLOWED_SIGNERS")
    if sig["method"] == "ssh-sig" and anchors:
        ps = _policysig()
        sigfile = cfg.policy_file.parent / sig["ref"]
        try:
            ps.verify(cfg.policy_file.read_bytes(), sigfile.read_text(), pathlib.Path(anchors).read_text(), sig.get("signer"))
        except (OSError, ps.SignatureError) as exc:
            pytest.fail(f"Signaturprüfung fehlgeschlagen: {exc}")


@pytest.mark.live
@pytest.mark.aism(id="AISM-K3-09", level="K3", req="MUSS", refs=["S-11", "M-15"])
def test_gateway_reports_verified_signature(gateway):
    info = gateway.get("/aism/v1/policy").json()
    sig = info.get("signature") or {}
    assert info.get("revision"), "aktive Policy ohne revision"
    assert sig.get("verified") is True, f"aktive Policy nicht signaturgeprüft: {sig}"
    assert sig.get("required") is True, "Gateway erzwingt keine Signatur (unsignierte Policies würden geladen)"


@pytest.mark.live
@pytest.mark.capture
@pytest.mark.aism(id="AISM-K3-02", level="K3", req="MUSS", refs=["S-10"])
def test_traceparent_propagated(gateway, model, capture, nonce):
    trace_id = hashlib.sha256(nonce.encode()).hexdigest()[:32]
    tp = f"00-{trace_id}-{'1' * 16}-01"
    r = gateway.post("/v1/chat/completions", json=chat_body(model, f"[{nonce}] trace test"),
                     headers={"traceparent": tp})
    assert r.status_code == 200
    reqs = [c for c in capture.captured("/v1/chat/completions") if nonce in json.dumps(c["body"])]
    assert reqs, "kein Inferenz-Request beobachtet"
    got = reqs[0]["headers"].get("traceparent", "")
    assert got.split("-")[1:2] == [trace_id], f"Trace-ID nicht weitergereicht (erhalten: {got!r})"


@pytest.mark.audit
@pytest.mark.aism(id="AISM-K3-03", level="K3", req="MUSS", refs=["S-10", "AUD"])
def test_audit_entries_have_trace_id(audit_entries):
    req_events = [e for e in audit_entries if str(e.get("event", "")).startswith(("request.", "route.", "tool.", "egress."))]
    if not req_events:
        pytest.skip("keine request-bezogenen Audit-Einträge")
    missing = [e.get("request_id", "?") for e in req_events if not re.fullmatch(r"[0-9a-f]{32}", str(e.get("trace_id", "")))]
    assert not missing, f"{len(missing)} Einträge ohne gültige trace_id"


@pytest.mark.audit
@pytest.mark.aism(id="AISM-K3-04", level="K3", req="MUSS", refs=["S-13", "M-04"])
def test_cloud_egress_has_proof(audit_entries):
    egress = [e for e in audit_entries if e.get("event") == "egress.cloud"]
    if not egress:
        pytest.skip("keine egress.cloud-Ereignisse im Audit-Log (Szenario mit Cloud-Fallback erforderlich)")
    required = ("rule_ids", "provider", "policy", "payload_sha256")
    bad = [e.get("request_id", "?") for e in egress if not all(e.get(k) for k in required)]
    assert not bad, f"egress.cloud ohne vollständigen Nachweis: {bad}"


@pytest.mark.audit
@pytest.mark.aism(id="AISM-K3-07", level="K3", req="MUSS", refs=["S-02"])
def test_audit_hash_chain(cfg, audit_entries):
    lines = [l for l in cfg.audit_log.read_text(encoding="utf-8").splitlines() if l.strip()]
    for i in range(1, len(lines)):
        expected = "sha256:" + hashlib.sha256(lines[i - 1].encode("utf-8")).hexdigest()
        got = json.loads(lines[i]).get("prev_hash")
        assert got == expected, f"Hash-Kette unterbrochen in Zeile {i + 1}"


@pytest.mark.static
@pytest.mark.aism(id="AISM-K3-05", level="K3", req="MUSS", refs=["S-07"])
def test_static_images_pinned_by_digest(cfg, compose):
    """Pulled images: `image:` pinned by digest. Locally built services (`build:`): every FROM in the
    Dockerfile pinned by digest (the built image itself gets its digest only when pushed; see README)."""
    unpinned = {}
    for n, s in compose["services"].items():
        if s.get("build"):
            b = s["build"] if isinstance(s["build"], dict) else {"context": s["build"]}
            ctx = (cfg.compose_file.parent / b.get("context", ".")).resolve()
            df = ctx / b.get("dockerfile", "Dockerfile")
            if not df.exists():
                unpinned[n] = f"Dockerfile fehlt: {df}"
                continue
            bad = [f for f in FROM_RE.findall(df.read_text(encoding="utf-8"))
                   if not DIGEST_RE.search(f) and f.lower() != "scratch"]
            if bad:
                unpinned[n] = f"FROM ohne Digest: {bad}"
        elif s.get("image") and not DIGEST_RE.search(s["image"]):
            unpinned[n] = s["image"]
    assert not unpinned, f"Images ohne @sha256-Digest: {unpinned}"


@pytest.mark.live
@pytest.mark.inject
@pytest.mark.aism(id="AISM-K3-08", level="K3", req="MUSS", refs=["S-11", "Policy-Format §6"])
def test_unsigned_or_tampered_policy_not_activated(cfg, gateway):
    """Opt-in fault injection (AISM_POLICY_FAULT_INJECTION=1): modifies the policy file the gateway
    reads (AISM_POLICY_FILE, must be the mounted file) and restores it afterwards."""
    if os.environ.get("AISM_POLICY_FAULT_INJECTION") != "1":
        pytest.skip("AISM_POLICY_FAULT_INJECTION=1 nicht gesetzt (verändert die Policy-Datei temporär)")
    wait = float(os.environ.get("AISM_POLICY_RELOAD_WAIT", "15"))
    before = gateway.get("/aism/v1/policy").json()
    if not (before.get("signature") or {}).get("verified"):
        pytest.skip("aktive Policy ist nicht signaturgeprüft (siehe AISM-K3-09)")
    orig = cfg.policy_file.read_bytes()
    unsigned = re.sub(rb"(?m)^  signature:\n(?:    .*\n)+", b"", orig) + b"\n# AISM-K3-08 unsigned\n"
    tampered = orig.replace(b"maxToolRounds: 5", b"maxToolRounds: 50") + b"\n# AISM-K3-08 tampered\n"
    assert unsigned != orig and tampered != orig

    def wait_for(pred):
        deadline = time.time() + wait
        while time.time() < deadline:
            info = gateway.get("/aism/v1/policy").json()
            if pred(info):
                return info
            time.sleep(0.5)
        return gateway.get("/aism/v1/policy").json()

    def restore():
        cfg.policy_file.write_bytes(orig)
        wait_for(lambda i: not i.get("last_load_error"))   # the reference gateway reports the last rejected load; others: full wait

    try:
        for label, content in (("unsigniert", unsigned), ("manipuliert", tampered)):
            cfg.policy_file.write_bytes(content)
            info = wait_for(lambda i: i.get("last_load_error") or i.get("digest") != before["digest"])
            assert info.get("digest") == before["digest"], f"{label}e Policy wurde aktiviert"
            assert gateway.get("/health").status_code == 200, f"Gateway nach {label}er Policy nicht mehr bereit"
            restore()
    finally:
        restore()
