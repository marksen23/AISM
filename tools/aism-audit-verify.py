#!/usr/bin/env python3
"""Verify an AISM audit trail (local hash chain, checkpoints, optional WORM sink).

Exit 0 when the machine-readable report is ok, 1 when it is not, 2 on usage errors.
Private keys are not read. The audit public key is taken from a keyring member
with role ``audit`` (the keyring file's signatures are checked).

  python3 tools/aism-audit-verify.py --log /audit/audit.jsonl \\
      --keyring config/policy-trust/keyring.yaml --signer audit@example.com \\
      --s3-endpoint http://127.0.0.1:8333 --s3-bucket aism-audit --s3-prefix aism/ \\
      --s3-access-key-env AISM_AUDIT_S3_ACCESS_KEY --s3-secret-key-env AISM_AUDIT_S3_SECRET_KEY \\
      --keyring-state /audit/keyring-state.json --report -
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gateway"))

from aism_gateway.auditverify import build_report  # noqa: E402
from aism_gateway.keyring import KeyringError, load_tip  # noqa: E402
from aism_gateway.s3client import S3Client, S3Error  # noqa: E402


def _lines(path: pathlib.Path) -> list[str]:
    if not path.is_file():
        sys.exit(f"audit log not found: {path}")
    return [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def _envelopes(directory: pathlib.Path) -> list[dict]:
    if not directory.is_dir():
        return []
    out = []
    for path in sorted(directory.glob("*.json")):
        try:
            out.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError) as exc:
            out.append({"checkpoint": {"seq": None}, "signature": "", "_error": str(exc)})
    return out


def _trust(keyring_path: pathlib.Path, signer: str):
    try:
        doc = load_tip(keyring_path)
    except (OSError, KeyringError) as exc:
        sys.exit(f"keyring: {exc}")
    member = doc.key_by_id(signer)
    if member is None or "audit" not in member.roles:
        sys.exit(f"{signer} is not an audit signer in {keyring_path}")
    return member.blob


def _worm(args, prefix: str):
    access = os.environ.get(args.s3_access_key_env or "")
    secret = os.environ.get(args.s3_secret_key_env or "")
    if not access or not secret:
        sys.exit("S3 credentials are not in the environment")
    client = S3Client(args.s3_endpoint, access, secret, args.s3_region)
    try:
        versions, markers = client.list_versions(args.s3_bucket, prefix)
    except S3Error as exc:
        sys.exit(f"WORM list failed: {exc}")
    grouped: dict[str, list[tuple[bytes, str | None]]] = {}
    delete_markers = []
    keyring_bodies = []
    for marker in markers:
        key = marker["key"]
        if key.startswith(prefix):
            delete_markers.append(key[len(prefix):])
    for item in versions:
        key = item["key"]
        if not key.startswith(prefix):
            continue
        rel = key[len(prefix):]
        try:
            body, vid = client.get_bytes(args.s3_bucket, key, item.get("version_id"))
        except S3Error as exc:
            sys.exit(f"WORM get {rel} failed: {exc}")
        grouped.setdefault(rel, []).append((body, vid or item.get("version_id")))
        if rel.startswith("keyring-state/"):
            keyring_bodies.append(body)
    return grouped, delete_markers, keyring_bodies


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify an AISM audit hash chain and its checkpoints")
    parser.add_argument("--log", required=True, help="audit JSONL path")
    parser.add_argument("--keyring", required=True, help="keyring.yaml (audit role public key)")
    parser.add_argument("--signer", required=True, help="keyring identity with role audit")
    parser.add_argument("--checkpoints", help="directory of checkpoint envelopes (default: <log dir>/checkpoints)")
    parser.add_argument("--keyring-state", help="keyring-state.json to compare with the WORM copy")
    parser.add_argument("--s3-endpoint")
    parser.add_argument("--s3-bucket")
    parser.add_argument("--s3-region", default="us-east-1")
    parser.add_argument("--s3-prefix", default="")
    parser.add_argument("--s3-access-key-env", default="AISM_AUDIT_S3_ACCESS_KEY")
    parser.add_argument("--s3-secret-key-env", default="AISM_AUDIT_S3_SECRET_KEY")
    parser.add_argument("--report", default="-", help="report path, or - for stdout")
    args = parser.parse_args()
    log_path = pathlib.Path(args.log)
    lines = _lines(log_path)
    ckpt_dir = pathlib.Path(args.checkpoints) if args.checkpoints else log_path.parent / "checkpoints"
    envelopes = _envelopes(ckpt_dir)
    blob = _trust(pathlib.Path(args.keyring), args.signer)
    worm_checked = bool(args.s3_endpoint or args.s3_bucket)
    if worm_checked and not (args.s3_endpoint and args.s3_bucket):
        sys.exit("--s3-endpoint and --s3-bucket are both required")
    prefix = args.s3_prefix or ""
    if prefix and not prefix.endswith("/"):
        prefix += "/"
    versions = markers = None
    keyring_bodies: list[bytes] = []
    if worm_checked:
        versions, markers, keyring_bodies = _worm(args, prefix)
        for bodies in versions.values():
            for body, _vid in bodies:
                if body[:1] == b"{":
                    try:
                        env = json.loads(body.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        continue
                    if isinstance(env, dict) and "checkpoint" in env and "signature" in env:
                        envelopes.append(env)
    state = None
    if args.keyring_state:
        try:
            state = pathlib.Path(args.keyring_state).read_bytes()
        except OSError as exc:
            sys.exit(f"keyring state: {exc}")
    report = build_report(
        lines=lines, envelopes=envelopes, trust_blob=blob, signer=args.signer,
        worm_versions=versions, delete_markers=markers, keyring_state=state,
        worm_keyring=keyring_bodies, worm_checked=worm_checked,
    )
    text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.report == "-":
        sys.stdout.write(text)
    else:
        pathlib.Path(args.report).write_text(text, encoding="utf-8")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(1)
