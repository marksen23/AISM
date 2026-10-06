"""AISM K3 Sovereign/Auditable: signed policy, end-to-end trace IDs, egress proof, pinned deployment."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
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
    if sig["method"] == "ssh-sig" and str(sig["ref"]).endswith(".sigs"):
        kr = os.environ.get("AISM_KEYRING")
        if not kr:
            pytest.fail("Mehrfachsignatur (.sigs) ohne AISM_KEYRING")
        sys.path.insert(0, str(REPO / "gateway"))
        from aism_gateway.keyring import accept_path, verify_policy
        try:
            doc = accept_path(kr, state_path=None, persist=False)
            bundle = (cfg.policy_file.parent / sig["ref"]).read_text(encoding="utf-8")
            verify_policy(cfg.policy_file.read_bytes(), bundle, doc, str(policy["metadata"]["revision"]), sig.get("threshold"))
        except Exception as exc:  # noqa: BLE001 — conformance assertion, any verifier error is a failure
            pytest.fail(f"Signaturprüfung fehlgeschlagen: {exc}")
        return
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


def _manifest_keys(manifest: pathlib.Path) -> list[tuple[str, pathlib.Path]]:
    rows = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        ident, rel = line.split("\t", 1)
        rows.append((ident, manifest.parent / rel))
    return rows


@pytest.mark.live
@pytest.mark.aism(id="AISM-K3-11", level="K3", req="MUSS", refs=["S-11"])
def test_four_eyes_signers_reported(cfg, gateway):
    info = gateway.get("/aism/v1/policy").json()
    sig = info.get("signature") or {}
    signers = list(sig.get("signers") or [])
    assert sig.get("threshold", 0) >= 2, f"K3-Schwelle unter 2: {sig}"
    assert len(set(signers)) >= 2, f"weniger als zwei Signierer: {signers}"
    assert info.get("digest", "").startswith("sha256:")
    if not cfg.audit_log or not cfg.audit_log.exists():
        pytest.fail("AISM_AUDIT_LOG fehlt; Signierer müssen in der Hash-Kette stehen")
    loaded = []
    for line in cfg.audit_log.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        if entry.get("event") == "policy.loaded":
            loaded.append(entry)
    assert loaded, "kein policy.loaded im Audit"
    audited = (loaded[-1].get("signature") or {}).get("signers") or []
    assert set(audited) == set(signers), f"Audit-Signierer {audited} passen nicht zu {signers}"
    assert "BEGIN OPENSSH PRIVATE" not in json.dumps(loaded[-1])


@pytest.mark.live
@pytest.mark.aism(id="AISM-K3-12", level="K3", req="MUSS", refs=["S-11", "Policy-Format §6.2"])
def test_keyring_rotation_overlap(cfg, gateway):
    kr = os.environ.get("AISM_KEYRING")
    manifest = os.environ.get("AISM_SIGNING_KEYS")
    if not kr or not manifest or not os.path.isfile(kr) or not os.path.isfile(manifest):
        pytest.skip("AISM_KEYRING oder AISM_SIGNING_KEYS fehlt")
    keys = _manifest_keys(pathlib.Path(manifest))
    assert len(keys) >= 2, "Quorum braucht mindestens zwei Testschlüssel"
    sign = REPO / "tools" / "aism-policy-sign.py"
    wait = float(os.environ.get("AISM_POLICY_RELOAD_WAIT", "15"))
    before = gateway.get("/aism/v1/policy").json()
    assert (before.get("keyring") or {}).get("version"), f"Gateway meldet keinen Schlüsselring: {before}"
    digest = before["digest"]
    version = before["keyring"]["version"]

    def wait_for(pred):
        deadline = time.time() + wait
        last = before
        while time.time() < deadline:
            last = gateway.get("/aism/v1/policy").json()
            if pred(last):
                return last
            time.sleep(0.5)
        return last

    with tempfile.TemporaryDirectory() as tmp:
        new_dir, rejected_dir = pathlib.Path(tmp) / "new", pathlib.Path(tmp) / "rejected"
        gen = subprocess.run([sys.executable, str(sign), "keygen", "--out", str(new_dir), "--identity", "aism-rotate@localhost"],
                             capture_output=True, text=True)
        assert gen.returncode == 0, gen.stderr
        gen2 = subprocess.run([sys.executable, str(sign), "keygen", "--out", str(rejected_dir),
                               "--identity", "aism-rejected@localhost"], capture_output=True, text=True)
        assert gen2.returncode == 0, gen2.stderr
        member = (
            "id=aism-rotate@localhost,"
            f"pub={new_dir / 'policy-signing.key.pub'},roles=policy+keyring,"
            "not-before=2020-01-01T00:00:00Z,not-after=2035-01-01T00:00:00Z"
        )
        cmd = [sys.executable, str(sign), "rotate-key", "--keyring", kr,
               "--retire", keys[0][0], "--retire-not-after", "2030-01-01T00:00:00Z",
               "--member", member]
        for ident, path in keys[:2]:
            cmd += ["--sign", f"{path}={ident}"]
        rotated = subprocess.run(cmd, capture_output=True, text=True)
        assert rotated.returncode == 0, rotated.stderr + rotated.stdout
        info = wait_for(lambda i: (i.get("keyring") or {}).get("version") == version + 1)
        assert (info.get("keyring") or {}).get("version") == version + 1, f"Rotation nicht übernommen: {info.get('keyring')}"
        assert info.get("digest") == digest, "Policy-Digest hat sich bei der überlappenden Rotation geändert"
        assert gateway.get("/health").status_code == 200
        # one currently valid key must not add another
        solo = [sys.executable, str(sign), "add-key", "--keyring", kr, "--member",
                "id=aism-rejected@localhost,"
                f"pub={rejected_dir / 'policy-signing.key.pub'},roles=policy+keyring,"
                "not-before=2020-01-01T00:00:00Z,not-after=2035-01-01T00:00:00Z",
                "--sign", f"{keys[1][1]}={keys[1][0]}"]
        refused = subprocess.run(solo, capture_output=True, text=True)
        assert refused.returncode != 0 and "Quorum" in (refused.stderr + refused.stdout)
        stayed = gateway.get("/aism/v1/policy").json()
        assert stayed["keyring"]["version"] == version + 1 and stayed["digest"] == digest
        assert gateway.get("/health").status_code == 200


def _require_audit_env():
    needed = (
        "AISM_AUDIT_LOG", "AISM_KEYRING", "AISM_AUDIT_SIGNER", "AISM_KEYRING_STATE",
        "AISM_AUDIT_S3_ENDPOINT", "AISM_AUDIT_S3_BUCKET",
        "AISM_AUDIT_S3_ACCESS_KEY", "AISM_AUDIT_S3_SECRET_KEY",
    )
    missing = [name for name in needed if not os.environ.get(name)]
    if missing:
        pytest.fail("WORM-Prüfung ohne Umgebung: " + ", ".join(missing))


def _audit_prefix() -> str:
    prefix = os.environ.get("AISM_AUDIT_S3_PREFIX", "aism/")
    if prefix and not prefix.endswith("/"):
        prefix += "/"
    return prefix


def _s3():
    sys.path.insert(0, str(REPO / "gateway"))
    from aism_gateway.s3client import S3Client
    return S3Client(
        os.environ["AISM_AUDIT_S3_ENDPOINT"],
        os.environ["AISM_AUDIT_S3_ACCESS_KEY"],
        os.environ["AISM_AUDIT_S3_SECRET_KEY"],
        os.environ.get("AISM_AUDIT_S3_REGION", "us-east-1"),
    )


def _wait_audit_stable(gateway, timeout: float = 90):
    """Checkpoint covers every local line, the queue is empty, the keyring anchor is in WORM."""
    deadline = time.time() + timeout
    last: dict = {}
    state_path = pathlib.Path(os.environ["AISM_KEYRING_STATE"])
    while time.time() < deadline:
        response = gateway.get("/aism/v1/audit")
        if response.status_code != 200:
            last = {"http": response.status_code, "body": response.text[:500]}
            time.sleep(0.5)
            continue
        last = response.json()
        checkpoint = last.get("checkpoint") or {}
        try:
            digest = "sha256:" + hashlib.sha256(state_path.read_bytes()).hexdigest()
        except OSError as exc:
            last = {**last, "keyring_state_error": str(exc)}
            time.sleep(0.5)
            continue
        queued = (last.get("queue") or {}).get("depth")
        if (last.get("accepting") and last.get("checkpoint_seq", 0) >= 1 and queued == 0
                and checkpoint.get("entries") == last.get("entries") and last.get("entries", 0) >= 1
                and digest in (last.get("keyring_state_acked") or [])
                and last.get("worm_objects", 0) >= last.get("entries", 0)):
            return last
        time.sleep(0.5)
    pytest.fail("Audit-Senke nicht stabil: " + json.dumps(last, ensure_ascii=False)[:2000])


@pytest.mark.live
@pytest.mark.aism(id="AISM-K3-14", level="K3", req="MUSS", refs=["S-02"])
def test_audit_checkpoint_and_worm_verify(gateway):
    """Chain, checkpoint signatures and the WORM mirror, including the keyring anchor."""
    _require_audit_env()
    _wait_audit_stable(gateway)
    report_path = pathlib.Path(os.environ.get("AISM_REPORT", "aism-report.json")).parent / "audit-verify.json"
    cmd = [
        sys.executable, str(REPO / "tools" / "aism-audit-verify.py"),
        "--log", os.environ["AISM_AUDIT_LOG"],
        "--keyring", os.environ["AISM_KEYRING"],
        "--signer", os.environ["AISM_AUDIT_SIGNER"],
        "--s3-endpoint", os.environ["AISM_AUDIT_S3_ENDPOINT"],
        "--s3-bucket", os.environ["AISM_AUDIT_S3_BUCKET"],
        "--s3-prefix", _audit_prefix(),
        "--keyring-state", os.environ["AISM_KEYRING_STATE"],
        "--report", str(report_path),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        report = {"raw": (proc.stdout + proc.stderr)[:2000]}
    assert proc.returncode == 0 and report.get("ok") is True, json.dumps(report, ensure_ascii=False)[:2000]


@pytest.mark.live
@pytest.mark.aism(id="AISM-K3-13", level="K3", req="MUSS", refs=["S-02"])
def test_audit_worm_object_lock_holds(gateway):
    """A COMPLIANCE version cannot be deleted. A later version with different bytes is removed again."""
    _require_audit_env()
    _wait_audit_stable(gateway)
    client = _s3()
    bucket = os.environ["AISM_AUDIT_S3_BUCKET"]
    prefix = _audit_prefix()
    versions, _markers = client.list_versions(bucket, prefix + "entries/")
    locked = [item for item in versions if str(item.get("key", "")).startswith(prefix + "entries/") and item.get("version_id")]
    assert locked, f"keine versionierte Entry-Kopie unter {prefix}entries/"
    target = locked[0]
    key, version_id = target["key"], target["version_id"]
    original, _vid = client.get_bytes(bucket, key, version_id)
    denied = client.delete(bucket, key, version_id)
    if denied < 300:
        until = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 86400))
        client.put_bytes(bucket, key, original, lock_mode="COMPLIANCE", retain_until=until)
        pytest.fail(f"COMPLIANCE-Version ließ sich löschen (HTTP {denied})")
    still, _vid = client.get_bytes(bucket, key, version_id)
    assert still == original, "gesperrte Version hat sich geändert"
    status, new_version = client.put_plain(bucket, key, b'{"tampered":true}\n')
    try:
        unchanged, _vid = client.get_bytes(bucket, key, version_id)
        assert unchanged == original, "PUT hat die gesperrte Version überschrieben"
        if status < 300:
            assert new_version and new_version != version_id, f"PUT ohne neue Version-ID (HTTP {status})"
            removed = client.delete(bucket, key, new_version)
            assert removed < 300, f"Schattenversion nicht entfernt (HTTP {removed})"
        latest, _vid = client.get_bytes(bucket, key)
        assert latest == original, "aktuelle Sicht ist nicht mehr die gesperrte Fassung"
    except Exception:
        if new_version and new_version != version_id:
            client.delete(bucket, key, new_version)
        raise


@pytest.mark.live
@pytest.mark.capture
@pytest.mark.aism(id="AISM-K3-15", level="K3", req="MUSS", refs=["S-02", "M-12"])
def test_audit_sink_outage_fails_closed(gateway, model, capture, nonce):
    """A fault marker makes the required sink unavailable: 503, and the mock sees nothing."""
    _require_audit_env()
    client = _s3()
    bucket = os.environ["AISM_AUDIT_S3_BUCKET"]
    key = _audit_prefix() + "fault/block"
    created = None
    try:
        status, created = client.put_plain(bucket, key, b"block")
        assert status < 300, f"Störungsmarker nicht angelegt (HTTP {status})"
        deadline = time.time() + 20
        last: dict = {}
        while time.time() < deadline:
            response = gateway.get("/aism/v1/audit")
            last = response.json() if response.status_code == 200 else {"http": response.status_code, "body": response.text[:400]}
            if last.get("faulted") and last.get("accepting") is False:
                break
            time.sleep(0.4)
        else:
            pytest.fail("Senke wurde nicht als ausgefallen erkannt: " + json.dumps(last, ensure_ascii=False)[:1500])
        assert gateway.get("/health").status_code == 503
        refused = gateway.post("/v1/chat/completions", json=chat_body(model, f"[{nonce}] outage"))
        assert refused.status_code == 503, refused.text[:300]
        assert refused.json()["error"]["code"] == "audit_unavailable"
        seen = [item for item in capture.captured("/v1/chat/completions") if nonce in json.dumps(item["body"])]
        assert not seen, "Anfrage wurde trotz Audit-Ausfall weitergeleitet"
    finally:
        try:
            versions, _markers = client.list_versions(bucket, key)
        except Exception:
            versions = []
        for item in versions:
            if item.get("key") == key and item.get("version_id"):
                client.delete(bucket, key, item["version_id"])
        if created:
            client.delete(bucket, key, created)
        client.delete(bucket, key, None)
        deadline = time.time() + 20
        while time.time() < deadline:
            health = gateway.get("/health")
            status_response = gateway.get("/aism/v1/audit")
            if (health.status_code == 200 and status_response.status_code == 200
                    and status_response.json().get("accepting") and not status_response.json().get("faulted")):
                break
            time.sleep(0.4)
        else:
            pytest.fail("Gateway nach Entfernen der Störung nicht bereit")
