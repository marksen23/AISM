"""Verify an AISM audit hash chain, signed checkpoints and the WORM mirror.

Used by tools/aism-audit-verify.py and by the unit tests. A report is ok only when
every finding list is empty. Delete markers and a second version with different
bytes are findings: a simple S3 DELETE hides the latest view even when the locked
version remains, and that is not an acceptable state for this log.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json

from . import policysig
from .audit import AUDIT_NAMESPACE, GENESIS, MERKLE_ALG, canonical_json, line_hash, merkle_root
from .tsa import response_ok


def _finding(kind: str, **detail) -> dict:
    out = {"kind": kind}
    out.update(detail)
    return out


def classify_chain(lines: list[str]) -> list[dict]:
    """Detect a broken prev_hash link, a seq gap, a reorder, or a modified line.

    A modified last line keeps the chain internally consistent; checkpoints and the
    WORM mirror catch that case.
    """
    findings: list[dict] = []
    hashes = []
    parsed = []
    for i, line in enumerate(lines):
        try:
            parsed.append(json.loads(line))
            hashes.append(line_hash(line))
        except json.JSONDecodeError:
            parsed.append(None)
            hashes.append(line_hash(line))
            findings.append(_finding("modified", line=i + 1, detail="line is not JSON"))
    known = set(hashes)
    seqs = [obj.get("seq") if isinstance(obj, dict) else None for obj in parsed]
    prev = GENESIS
    for i, obj in enumerate(parsed):
        n = i + 1
        if obj is None:
            prev = hashes[i]
            continue
        seq = obj.get("seq")
        if isinstance(seq, int) and not isinstance(seq, bool) and seq != n:
            if n not in seqs and seq > n:
                findings.append(_finding("gap", line=n, detail=f"seq {seq}, expected {n}"))
            else:
                findings.append(_finding("reorder", line=n, detail=f"seq {seq}, expected {n}"))
        got = obj.get("prev_hash")
        if got != prev:
            if i > 0 and got not in known:
                findings.append(_finding("modified", line=i, detail="next prev_hash does not match this line"))
            elif got in known and got != prev:
                findings.append(_finding("reorder", line=n, detail="prev_hash matches a different line"))
            else:
                findings.append(_finding("chain_break", line=n, detail="prev_hash does not match the previous line"))
        prev = hashes[i]
    return findings


def _checkpoint_bytes(body: dict) -> bytes:
    return canonical_json(body)


def _dedupe_envelopes(envelopes: list[dict]) -> list[dict]:
    """Drop a second copy of the same signed checkpoint (local file and WORM mirror)."""
    seen: set[bytes] = set()
    out: list[dict] = []
    for env in envelopes:
        body = env.get("checkpoint") if isinstance(env, dict) else None
        if not isinstance(body, dict):
            out.append(env)
            continue
        marker = canonical_json(body) + b"\n" + str(env.get("signature", "")).encode("utf-8")
        if marker in seen:
            continue
        seen.add(marker)
        out.append(env)
    return out


def verify_checkpoints(lines: list[str], envelopes: list[dict], trust_blob: bytes | None,
                       signer: str | None) -> tuple[list[dict], list[dict]]:
    """Returns (findings, checked checkpoint bodies in seq order)."""
    findings: list[dict] = []
    checked: list[dict] = []
    prev_hash = GENESIS
    prev_seq = 0
    for env in _dedupe_envelopes(envelopes):
        if not isinstance(env, dict) or "checkpoint" not in env or "signature" not in env:
            findings.append(_finding("forged_checkpoint", detail="envelope is missing checkpoint or signature"))
            continue
        body = env["checkpoint"]
        raw = _checkpoint_bytes(body)
        try:
            blob, _fp = policysig.verify_crypto(raw, env["signature"], AUDIT_NAMESPACE)
        except (policysig.SignatureError, TypeError, ValueError) as exc:
            findings.append(_finding("forged_checkpoint", seq=body.get("seq"), detail=str(exc)))
            continue
        if trust_blob is not None and blob != trust_blob:
            findings.append(_finding("forged_checkpoint", seq=body.get("seq"), detail="unexpected audit key"))
            continue
        if signer and body.get("signer") != signer:
            findings.append(_finding("forged_checkpoint", seq=body.get("seq"), detail="signer mismatch"))
            continue
        seq = body.get("seq")
        entries = body.get("entries")
        if not isinstance(seq, int) or not isinstance(entries, int) or entries < 1:
            findings.append(_finding("forged_checkpoint", seq=seq, detail="seq or entries invalid"))
            continue
        if seq <= prev_seq:
            findings.append(_finding("reorder", seq=seq, detail="checkpoint seq is not increasing"))
        if body.get("prev_checkpoint") != prev_hash:
            findings.append(_finding("gap", seq=seq, detail="checkpoint does not link to the previous one"))
        if entries > len(lines):
            findings.append(_finding("truncation", seq=seq, entries=entries, have=len(lines),
                                     detail="checkpoint covers more entries than the log"))
        else:
            prefix = lines[:entries]
            head = line_hash(prefix[-1]) if prefix else GENESIS
            root = merkle_root([ln.encode("utf-8") for ln in prefix])
            if body.get("head") != head or body.get("merkle_root") != root or body.get("merkle") != MERKLE_ALG:
                findings.append(_finding("modified", seq=seq, detail="checkpoint head or merkle root does not match the log"))
        witness = env.get("witness")
        if isinstance(witness, dict) and witness.get("token_b64"):
            try:
                token = base64.b64decode(witness["token_b64"], validate=True)
            except (ValueError, TypeError):
                findings.append(_finding("witness_mismatch", seq=seq, detail="token is not base64"))
            else:
                ok, detail = response_ok(token, hashlib.sha256(raw).digest())
                if not ok:
                    findings.append(_finding("witness_mismatch", seq=seq, detail=detail))
        prev_hash = "sha256:" + hashlib.sha256(raw).hexdigest()
        prev_seq = seq
        checked.append(body)
    return findings, checked


def verify_worm(lines: list[str], versions: dict[str, list[tuple[bytes, str | None]]],
                delete_markers: list[str], checkpoints: list[dict]) -> list[dict]:
    """`versions` maps an object key to one or more (body, version_id) pairs."""
    findings: list[dict] = []
    expected = {f"entries/{i:020d}": line.encode("utf-8") for i, line in enumerate(lines, 1)}
    seen = set()
    for key, bodies in versions.items():
        if not key.startswith("entries/"):
            continue
        seen.add(key)
        good = [b for b, _vid in bodies if b == expected.get(key)]
        bad = [b for b, _vid in bodies if key in expected and b != expected[key]]
        if key not in expected:
            findings.append(_finding("worm_extra", key=key, detail="object is not in the local log"))
            continue
        if not good:
            findings.append(_finding("worm_mismatch", key=key, detail="no version matches the local line"))
        if bad:
            findings.append(_finding("worm_mismatch", key=key, detail="a version differs from the local line"))
    missing = [i for i in range(1, len(lines) + 1) if f"entries/{i:020d}" not in seen]
    if missing and missing == list(range(missing[0], len(lines) + 1)):
        findings.append(_finding("truncation", missing_from=missing[0],
                                 detail="WORM mirror is missing a suffix of the log"))
    else:
        for n in missing:
            findings.append(_finding("gap", key=f"entries/{n:020d}", detail="WORM object missing"))
    for key in delete_markers:
        if key.startswith("entries/") or key.startswith("checkpoints/"):
            findings.append(_finding("delete_marker", key=key, detail="delete marker hides an audit object"))
    for cp in checkpoints:
        key = f"checkpoints/{int(cp['seq']):020d}"
        # presence is checked by the caller when worm checkpoints are loaded; missing local-only is ok
        _ = key
    return findings


def verify_keyring_state(local: bytes | None, worm_bodies: list[bytes]) -> list[dict]:
    if local is None:
        return []
    digest = hashlib.sha256(local).digest()
    if any(hashlib.sha256(body).digest() == digest for body in worm_bodies):
        return []
    return [_finding("keyring_state_missing", detail="keyring-state.json digest is not in the WORM sink")]


def build_report(*, lines: list[str], envelopes: list[dict], trust_blob: bytes | None, signer: str | None,
                 worm_versions: dict[str, list[tuple[bytes, str | None]]] | None = None,
                 delete_markers: list[str] | None = None,
                 keyring_state: bytes | None = None, worm_keyring: list[bytes] | None = None,
                 worm_checked: bool = False) -> dict:
    findings = classify_chain(lines)
    cp_findings, checked = verify_checkpoints(lines, envelopes, trust_blob, signer)
    findings.extend(cp_findings)
    if worm_checked:
        findings.extend(verify_worm(lines, worm_versions or {}, delete_markers or [], checked))
        findings.extend(verify_keyring_state(keyring_state, worm_keyring or []))
        if checked:
            latest = max(checked, key=lambda c: c["seq"])
            # a checkpoint stored only locally is not enough when a WORM sink was requested
            for cp in checked:
                key = f"checkpoints/{int(cp['seq']):020d}"
                bodies = (worm_versions or {}).get(key) or []
                raw = canonical_json(cp)
                if not any(_envelope_matches(body, raw) for body, _v in bodies):
                    findings.append(_finding("worm_missing", key=key, detail="checkpoint is not in the WORM sink"))
            _ = latest
    # de-duplicate identical findings
    uniq = []
    seen = set()
    for item in findings:
        marker = json.dumps(item, sort_keys=True)
        if marker not in seen:
            seen.add(marker)
            uniq.append(item)
    return {
        "ok": not uniq,
        "entries": len(lines),
        "head": line_hash(lines[-1]) if lines else GENESIS,
        "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "checkpoints": len(checked),
        "findings": uniq,
    }


def _envelope_matches(stored: bytes, canonical_checkpoint: bytes) -> bool:
    try:
        env = json.loads(stored.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    body = env.get("checkpoint")
    if not isinstance(body, dict):
        return stored == canonical_checkpoint
    return canonical_json(body) == canonical_checkpoint
