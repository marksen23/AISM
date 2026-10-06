"""Audit chain tampering, checkpoints, queue fail-closed and the verifier CLI."""
import hashlib
import json
import pathlib
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "gateway"))

from aism_gateway.audit import (  # noqa: E402
    GENESIS, AuditConfig, AuditLog, AuditUnavailable, canonical_json, line_hash,
)
from aism_gateway.auditverify import build_report, classify_chain  # noqa: E402
from aism_gateway.s3client import EMPTY_SHA, authorization  # noqa: E402
from aism_gateway.tsa import response_ok, timestamp_request  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import load_ssh_private_key  # noqa: E402

from aism_gateway.s3client import S3Error  # noqa: E402


def _kinds(findings):
    return {item["kind"] for item in findings}


def _log(tmp_path, n=4, **cfg):
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(str(path))
    if cfg:
        audit.configure(AuditConfig(**cfg), background=False)
    for i in range(n):
        audit.write("request.accepted", {"name": "p", "version": "1", "digest": GENESIS}, request_id=f"r{i}")
    return audit, path


def _lines(path):
    return [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def test_chain_detects_modified_reorder_and_gap(tmp_path):
    _audit, path = _log(tmp_path, 4)
    original = _lines(path)
    assert classify_chain(original) == []

    modified = list(original)
    modified[1] = modified[1].replace("r1", "rX")
    assert "modified" in _kinds(classify_chain(modified))

    reordered = [original[0], original[2], original[1], original[3]]
    assert "reorder" in _kinds(classify_chain(reordered))

    gap = [original[0], original[2], original[3]]
    assert "gap" in _kinds(classify_chain(gap))


def test_checkpoint_detects_truncation_modification_and_forgery(tmp_path):
    key = Ed25519PrivateKey.generate()
    audit, path = _log(tmp_path, 3, every_entries=10, every_seconds=10_000, signer_id="audit@test", signing_key=key)
    body = audit.checkpoint_now()
    assert body and body["entries"] == 3
    from aism_gateway.audit import public_blob
    blob = public_blob(key)
    envelopes = [json.loads(p.read_text(encoding="utf-8")) for p in (tmp_path / "checkpoints").glob("*.json")]
    ok = build_report(lines=_lines(path), envelopes=envelopes, trust_blob=blob, signer="audit@test")
    assert ok["ok"], ok

    truncated = build_report(lines=_lines(path)[:-1], envelopes=envelopes, trust_blob=blob, signer="audit@test")
    assert "truncation" in _kinds(truncated["findings"])

    changed = _lines(path)
    changed[-1] = changed[-1].replace("r2", "rZ")
    modified = build_report(lines=changed, envelopes=envelopes, trust_blob=blob, signer="audit@test")
    assert "modified" in _kinds(modified["findings"])

    forged = json.loads(json.dumps(envelopes[0]))
    forged["signature"] = forged["signature"].replace("A", "B").replace("B", "C", 1)
    bad = build_report(lines=_lines(path), envelopes=[forged], trust_blob=blob, signer="audit@test")
    assert "forged_checkpoint" in _kinds(bad["findings"])

    other = Ed25519PrivateKey.generate()
    wrong_key = build_report(lines=_lines(path), envelopes=envelopes, trust_blob=public_blob(other), signer="audit@test")
    assert "forged_checkpoint" in _kinds(wrong_key["findings"])

    duplicated = build_report(lines=_lines(path), envelopes=envelopes + envelopes, trust_blob=blob, signer="audit@test")
    assert duplicated["ok"], duplicated


class _MemorySink:
    def __init__(self):
        self.fail = False
        self.objects = {}
        self.id = "mem"
        self.required = True

    def put(self, key, body):
        if self.fail:
            raise S3Error(503, "Unavailable", "sink down")
        if key in self.objects and self.objects[key] != body:
            raise S3Error(409, "ImmutableConflict", key)
        self.objects[key] = body
        return "v1"


def test_sink_outage_queues_then_blocks_and_never_drops(tmp_path):
    sink = _MemorySink()
    sink.fail = True
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(str(path))
    audit.configure(AuditConfig(fail_closed=True, max_queued=2, worms=[sink]), background=False)
    audit.write("request.accepted", None, request_id="a")
    audit.write("request.accepted", None, request_id="b")
    with pytest.raises(AuditUnavailable):
        audit.write("request.accepted", None, request_id="c")
    assert not audit.accepting()
    assert sink.objects == {}
    assert [json.loads(ln)["request_id"] for ln in _lines(path)] == ["a", "b"]
    sink.fail = False
    audit.flush()
    assert set(sink.objects) == {"entries/00000000000000000001", "entries/00000000000000000002"}
    assert audit.accepting()
    audit.write("request.accepted", None, request_id="c")
    audit.flush()
    assert b'"c"' in sink.objects["entries/00000000000000000003"]
    audit.flush()
    stored = sink.objects["entries/00000000000000000001"]
    assert stored == _lines(path)[0].encode()


def test_optional_syslog_is_observable_when_it_fails(tmp_path):
    audit, _path = _log(tmp_path, 0)
    audit.configure(AuditConfig(syslog=[("tcp://127.0.0.1:1", False)]), background=False)
    audit.write("request.accepted", None, request_id="s")
    assert audit.status()["syslog_failures"] >= 1
    assert audit.status()["sink_errors"].get("syslog")


def test_syslog_udp_receives_the_line(tmp_path):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    try:
        audit = AuditLog(str(tmp_path / "audit.jsonl"))
        audit.configure(AuditConfig(syslog=[(f"udp://127.0.0.1:{port}", False)]), background=False)
        audit.write("request.accepted", None, request_id="udp1")
        sock.settimeout(2)
        data, _addr = sock.recvfrom(65535)
    finally:
        sock.close()
    assert b"udp1" in data
    assert data.startswith(b"<")


def test_rfc3161_imprint_roundtrip():
    digest = hashlib.sha256(b"checkpoint-body").digest()
    request = timestamp_request(digest, nonce=7)
    assert request[0] == 0x30

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            # status granted + an OCTET STRING of the imprint
            token = bytes([0x30, 0x27, 0x30, 0x03, 0x02, 0x01, 0x00, 0x04, 0x20]) + digest
            self.send_response(200)
            self.send_header("Content-Type", "application/timestamp-reply")
            self.send_header("Content-Length", str(len(token)))
            self.end_headers()
            self.wfile.write(token)

        def log_message(self, fmt, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        from aism_gateway.tsa import request_timestamp
        token = request_timestamp(f"http://127.0.0.1:{server.server_port}/tsa", digest, timeout=2)
    finally:
        server.shutdown()
    ok, detail = response_ok(token, digest)
    assert ok, detail
    assert response_ok(token, b"\x00" * 32)[0] is False


def test_sigv4_matches_aws_get_object_example():
    # https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
    headers = {
        "host": "examplebucket.s3.amazonaws.com",
        "range": "bytes=0-9",
        "x-amz-content-sha256": EMPTY_SHA,
        "x-amz-date": "20130524T000000Z",
    }
    auth, canon = authorization(
        "GET", "/test.txt", [], headers, EMPTY_SHA,
        access_key="AKIAIOSFODNN7EXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        region="us-east-1", amz_date="20130524T000000Z",
    )
    assert canon == "\n".join([
        "GET",
        "/test.txt",
        "",
        "host:examplebucket.s3.amazonaws.com",
        "range:bytes=0-9",
        "x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "x-amz-date:20130524T000000Z",
        "",
        "host;range;x-amz-content-sha256;x-amz-date",
        EMPTY_SHA,
    ])
    assert auth.endswith("Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")


def test_verifier_cli_ok_and_truncated(tmp_path):
    sign = ROOT / "tools" / "aism-policy-sign.py"
    audit_dir = tmp_path / "audit-key"
    alice = tmp_path / "alice"
    bob = tmp_path / "bob"
    subprocess.check_call([sys.executable, str(sign), "keygen", "--out", str(audit_dir), "--identity", "audit@test"])
    subprocess.check_call([sys.executable, str(sign), "keygen", "--out", str(alice), "--identity", "alice@test"])
    subprocess.check_call([sys.executable, str(sign), "keygen", "--out", str(bob), "--identity", "bob@test"])
    member = "id={id},pub={pub},roles={roles},not-before=2020-01-01T00:00:00Z,not-after=2100-01-01T00:00:00Z"
    kr = tmp_path / "keyring.yaml"
    subprocess.check_call([
        sys.executable, str(sign), "init-keyring", "--out", str(kr),
        "--keyring-threshold", "2", "--policy-threshold", "2",
        "--member", member.format(id="alice@test", pub=alice / "policy-signing.key.pub", roles="policy+keyring"),
        "--member", member.format(id="bob@test", pub=bob / "policy-signing.key.pub", roles="policy+keyring"),
        "--member", member.format(id="audit@test", pub=audit_dir / "policy-signing.key.pub", roles="audit"),
        "--sign", f"{alice / 'policy-signing.key'}=alice@test",
        "--sign", f"{bob / 'policy-signing.key'}=bob@test",
    ])
    key = load_ssh_private_key((audit_dir / "policy-signing.key").read_bytes(), None)
    log_path = tmp_path / "audit.jsonl"
    audit = AuditLog(str(log_path))
    audit.configure(AuditConfig(every_entries=2, every_seconds=3600, signer_id="audit@test", signing_key=key),
                    background=False)
    audit.write("request.accepted", None, request_id="cli")
    audit.write("request.accepted", None, request_id="cli2")
    report = tmp_path / "report.json"
    tool = ROOT / "tools" / "aism-audit-verify.py"
    good = subprocess.run([sys.executable, str(tool), "--log", str(log_path), "--keyring", str(kr),
                           "--signer", "audit@test", "--report", str(report)], capture_output=True, text=True)
    assert good.returncode == 0, good.stderr
    assert json.loads(report.read_text(encoding="utf-8"))["ok"] is True
    kept = _lines(log_path)
    log_path.write_text(kept[0] + "\n", encoding="utf-8")
    bad = subprocess.run([sys.executable, str(tool), "--log", str(log_path), "--keyring", str(kr),
                          "--signer", "audit@test", "--report", str(report)], capture_output=True, text=True)
    assert bad.returncode == 1
    assert "truncation" in _kinds(json.loads(report.read_text(encoding="utf-8"))["findings"])


def test_canonical_checkpoint_is_stable():
    raw = canonical_json({"b": 1, "a": "x"})
    assert raw == b'{"a":"x","b":1}'
    assert line_hash('{"a":1}') == "sha256:" + hashlib.sha256(b'{"a":1}').hexdigest()
