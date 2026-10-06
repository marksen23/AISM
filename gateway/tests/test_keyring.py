"""Keyring quorum, rotation and M-of-N policy signatures.

Keys are generated in tmp_path. Nothing is written into the repository.
"""
import asyncio
import datetime as dt
import json
import pathlib
import shutil
import sys

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "gateway"))

from aism_gateway import keyring, policysig  # noqa: E402
from aism_gateway.policy import PolicyError, SignatureConfig, load_policy  # noqa: E402

SCHEMA = ROOT / "policy" / "policy.schema.json"
SRC = ROOT / "conformance" / "tests" / "testdata" / "policy.conformance.yaml"
SIGN = ROOT / "tools" / "aism-policy-sign.py"
NOW = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc)
EARLY = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
MID = dt.datetime(2026, 6, 15, tzinfo=dt.timezone.utc)
LATE = dt.datetime(2027, 6, 1, tzinfo=dt.timezone.utc)
WINDOW = (dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc), dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc))


def _priv():
    return Ed25519PrivateKey.generate()


def _pub(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()


def _member(identity, key, roles=("policy", "keyring"), start=None, end=None, revoked=False):
    start = start or WINDOW[0]
    end = end or WINDOW[1]
    return keyring.member(identity, _pub(key), set(roles), start, end, revoked)


def _ring(keys, threshold=2, now=NOW, start=None, end=None):
    """Genesis keyring signed by every key. `keys` is a list of (identity, private_key)."""
    members = [_member(i, k, start=start, end=end) for i, k in keys]
    doc = keyring.compile_keyring(1, "", threshold, threshold, members)
    bundle = keyring.seal_keyring(None, doc, [(k, i) for i, k in keys], now)
    return doc, bundle


def _write(tmp, doc, bundle) -> pathlib.Path:
    path = tmp / "keyring.yaml"
    keyring.write_pair(path, doc.body, bundle)
    return path


def _cli(*args):
    import subprocess
    return subprocess.run([sys.executable, str(SIGN), *args], capture_output=True, text=True)


def _sign_policy(tmp, doc, bundle, holders, now=NOW):
    """Write the ring and sign the conformance policy with each holder via the CLI."""
    kr = _write(tmp, doc, bundle)
    pol = tmp / "policy.yaml"
    shutil.copy(SRC, pol)
    at = keyring.format_time(now)
    for identity, key in holders:
        key_path = tmp / f"{identity}.key"
        fd = __import__("os").open(key_path, __import__("os").O_WRONLY | __import__("os").O_CREAT | __import__("os").O_TRUNC, 0o600)
        with __import__("os").fdopen(fd, "wb") as handle:
            handle.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                            serialization.NoEncryption()))
        r = _cli("sign", "--keyring", str(kr), "--key", str(key_path), "--identity", identity, "--at", at, str(pol))
        assert r.returncode == 0, r.stderr + r.stdout
    return pol, kr


def test_threshold_two_distinct_signers(tmp_path):
    a, b = ("alice@example.com", _priv()), ("bob@example.com", _priv())
    doc, bundle = _ring([a, b])
    pol, kr = _sign_policy(tmp_path, doc, bundle, [a, b])
    loaded = load_policy(pol, SCHEMA, SignatureConfig(required=True, keyring=doc, now=NOW))
    assert loaded.signature["signers"] == ["alice@example.com", "bob@example.com"]
    assert loaded.signature["threshold"] == 2
    assert loaded.info()["signers"] == ["alice@example.com", "bob@example.com"]
    # one signer is not enough
    solo = tmp_path / "solo"
    solo.mkdir()
    doc1, bundle1 = _ring([a, b])
    pol1, _kr1 = _sign_policy(solo, doc1, bundle1, [a])
    with pytest.raises(PolicyError, match="Schwellenwert nicht erreicht"):
        load_policy(pol1, SCHEMA, SignatureConfig(required=True, keyring=doc1, now=NOW))


def test_duplicate_signature_counts_once(tmp_path):
    a, b = ("alice@example.com", _priv()), ("bob@example.com", _priv())
    doc, bundle = _ring([a, b])
    pol, _kr = _sign_policy(tmp_path, doc, bundle, [a])
    raw = (pol.parent / "policy.yaml.sigs").read_text(encoding="utf-8")
    parsed = yaml.safe_load(raw)
    parsed["signatures"].append(dict(parsed["signatures"][0]))
    (pol.parent / "policy.yaml.sigs").write_text(
        keyring.dump_bundle(parsed["subject"], parsed["signatures"]), encoding="utf-8")
    with pytest.raises(PolicyError, match="duplicate") as caught:
        load_policy(pol, SCHEMA, SignatureConfig(required=True, keyring=doc, now=NOW))
    assert "1 von 2" in str(caught.value)


def test_expired_revoked_and_unknown_do_not_count(tmp_path):
    a, b = ("alice@example.com", _priv()), ("bob@example.com", _priv())
    outsider = ("carol@example.com", _priv())
    doc, bundle = _ring([a, b])
    pol, _kr = _sign_policy(tmp_path, doc, bundle, [a, b])
    data = pol.read_bytes()
    text = (pol.parent / "policy.yaml.sigs").read_text(encoding="utf-8")
    revision = yaml.safe_load(data)["metadata"]["revision"]
    # expired: same signatures, clock past not-after
    with pytest.raises(keyring.KeyringError, match="expired"):
        keyring.verify_policy(data, text, doc, revision, None, LATE)
    # unknown: replace bob's signature with an outsider who can produce a valid SSHSIG
    only_alice = tmp_path / "unknown"
    only_alice.mkdir()
    pol_u, _ = _sign_policy(only_alice, doc, bundle, [a, outsider])
    with pytest.raises(PolicyError, match="unknown"):
        load_policy(pol_u, SCHEMA, SignatureConfig(required=True, keyring=doc, now=NOW))
    # revoked: three key holders, threshold 2, revoke alice, policy signed by alice+bob no longer reaches 2
    c = ("carol@example.com", _priv())
    wide = tmp_path / "revoked"
    wide.mkdir()
    doc3, bundle3 = _ring([a, b, c])
    pol3, kr3 = _sign_policy(wide, doc3, bundle3, [a, b])
    _store_signers(wide, a, b, c)
    revoked = _cli("revoke-key", "--keyring", str(kr3), "--identity", a[0], "--at", keyring.format_time(NOW),
                   "--sign", f"{wide / 'alice@example.com.key'}={a[0]}",
                   "--sign", f"{wide / 'bob@example.com.key'}={b[0]}",
                   "--sign", f"{wide / 'carol@example.com.key'}={c[0]}")
    assert revoked.returncode == 0, revoked.stderr + revoked.stdout
    doc_r = keyring.load_tip(kr3, NOW)
    with pytest.raises(PolicyError, match="revoked"):
        load_policy(pol3, SCHEMA, SignatureConfig(required=True, keyring=doc_r, now=NOW))


def _store_signers(directory, *holders):
    """sign_policy already stored keys; this re-writes them if a caller skipped signing one of them."""
    for identity, key in holders:
        key_path = directory / f"{identity}.key"
        if key_path.exists():
            continue
        fd = __import__("os").open(key_path, __import__("os").O_WRONLY | __import__("os").O_CREAT | __import__("os").O_TRUNC, 0o600)
        with __import__("os").fdopen(fd, "wb") as handle:
            handle.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                            serialization.NoEncryption()))


def test_tampered_policy_rejected(tmp_path):
    a, b = ("alice@example.com", _priv()), ("bob@example.com", _priv())
    doc, bundle = _ring([a, b])
    pol, _kr = _sign_policy(tmp_path, doc, bundle, [a, b])
    pol.write_text(pol.read_text().replace("maxToolRounds: 5", "maxToolRounds: 50"))
    with pytest.raises(PolicyError, match="Signatur"):
        load_policy(pol, SCHEMA, SignatureConfig(required=True, keyring=doc, now=NOW))


def test_policy_cannot_lower_threshold(tmp_path):
    a, b = ("alice@example.com", _priv()), ("bob@example.com", _priv())
    doc, bundle = _ring([a, b])
    pol, _kr = _sign_policy(tmp_path, doc, bundle, [a, b])
    # the signed bytes include threshold 2; lowering it also breaks the signatures (tamper)
    # and, if the bundle is rebuilt over the weakened file by one signer, the floor still holds.
    text = pol.read_text().replace("threshold: 2", "threshold: 1")
    pol.write_text(text)
    data = pol.read_bytes()
    meta = yaml.safe_load(data)["metadata"]
    entries = []
    for identity, key in (a, b):
        armored = policysig.sign(data, key, namespace=policysig.NAMESPACE)
        _blob, fp = policysig.verify_crypto(data, armored, policysig.NAMESPACE)
        entries.append({"armored": armored, "fingerprint": fp, "identity": identity})
    rebuilt = keyring.dump_bundle({"digest": keyring.sha256_prefixed(data), "revision": meta["revision"]}, entries)
    (pol.parent / "policy.yaml.sigs").write_text(rebuilt)
    with pytest.raises(PolicyError, match="unterschreitet"):
        load_policy(pol, SCHEMA, SignatureConfig(required=True, keyring=doc, now=NOW))


def test_quorum_less_change_and_self_add_rejected(tmp_path):
    a, b = ("alice@example.com", _priv()), ("bob@example.com", _priv())
    c_id, c_key = "carol@example.com", _priv()
    doc, bundle = _ring([a, b])
    path = _write(tmp_path, doc, bundle)
    before = path.read_bytes()
    fresh = _member(c_id, c_key)
    with pytest.raises(keyring.KeyringError, match="Quorum"):
        proposed = keyring.compile_keyring(2, doc.digest, 2, 2, [*doc.keys, fresh])
        keyring.seal_keyring(doc, proposed, [(a[1], a[0])], NOW)
    assert path.read_bytes() == before
    # carol signs together with alice: carol is not in the previous ring, so only alice counts
    with pytest.raises(keyring.KeyringError, match="Quorum"):
        proposed = keyring.compile_keyring(2, doc.digest, 2, 2, [*doc.keys, fresh])
        keyring.seal_keyring(doc, proposed, [(a[1], a[0]), (c_key, c_id)], NOW)
    # one key cannot remove the other
    with pytest.raises(keyring.KeyringError, match="Quorum"):
        proposed = keyring.compile_keyring(2, doc.digest, 2, 2, [k for k in doc.keys if k.id == a[0]])
        keyring.seal_keyring(doc, proposed, [(a[1], a[0])], NOW)


def test_keyring_rollback_rejected(tmp_path):
    a, b = ("alice@example.com", _priv()), ("bob@example.com", _priv())
    c_id, c_key = "carol@example.com", _priv()
    doc, bundle = _ring([a, b])
    path = _write(tmp_path, doc, bundle)
    state = tmp_path / "keyring-state.json"
    accepted = keyring.accept_path(path, state, now=NOW)
    assert accepted.version == 1
    v1_body, v1_sigs = path.read_bytes(), (path.parent / "keyring.yaml.sigs").read_bytes()
    fresh = _member(c_id, c_key)
    proposed = keyring.compile_keyring(2, doc.digest, 2, 2, [*doc.keys, fresh])
    sealed = keyring.seal_keyring(doc, proposed, [(a[1], a[0]), (b[1], b[0])], NOW)
    keyring.write_pair(path, proposed.body, sealed)
    tip = keyring.accept_path(path, state, now=NOW)
    assert tip.version == 2 and c_id in [k.id for k in tip.keys]
    path.write_bytes(v1_body)
    (path.parent / "keyring.yaml.sigs").write_bytes(v1_sigs)
    with pytest.raises(keyring.KeyringError, match="Rollback"):
        keyring.accept_path(path, state, now=NOW)
    # the stored ring is unchanged
    assert keyring.load_state(state).version == 2


def test_rotation_overlap(tmp_path):
    a, b = ("alice@example.com", _priv()), ("bob@example.com", _priv())
    c_id, c_key = "carol@example.com", _priv()
    doc, bundle = _ring([a, b], start=EARLY, end=dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc))
    # add carol while alice and bob are still valid; her window extends past theirs
    fresh = _member(c_id, c_key, start=dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc),
                    end=dt.datetime(2028, 1, 1, tzinfo=dt.timezone.utc))
    proposed = keyring.compile_keyring(2, doc.digest, 2, 2, [*doc.keys, fresh])
    sealed = keyring.seal_keyring(doc, proposed, [(a[1], a[0]), (b[1], b[0])], MID)
    assert set(proposed.quorum_signers) == {a[0], b[0]}
    # during the overlap a policy signed by the old key and the new key verifies
    pol, _kr = _sign_policy(tmp_path, proposed, sealed, [a, (c_id, c_key)], now=MID)
    loaded = load_policy(pol, SCHEMA, SignatureConfig(required=True, keyring=proposed, now=MID))
    assert loaded.signature["signers"] == sorted([a[0], c_id])
    # after alice expires, her signature no longer counts; carol alone misses the threshold
    with pytest.raises(PolicyError, match="expired"):
        load_policy(pol, SCHEMA, SignatureConfig(required=True, keyring=proposed, now=LATE))
    # bob is also expired at LATE; carol plus a second still-valid key would pass.
    # dave is added during the overlap (signed by alice and bob) and remains valid later.
    d_id, d_key = "dave@example.com", _priv()
    dave = _member(d_id, d_key, start=dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc),
                   end=dt.datetime(2028, 1, 1, tzinfo=dt.timezone.utc))
    later = keyring.compile_keyring(3, proposed.digest, 2, 2, [*proposed.keys, dave])
    later_bundle = keyring.seal_keyring(proposed, later, [(a[1], a[0]), (b[1], b[0])], MID)
    pol2 = tmp_path / "after"
    pol2.mkdir()
    pol_d, _ = _sign_policy(pol2, later, later_bundle, [(c_id, c_key), (d_id, d_key)], now=LATE)
    loaded2 = load_policy(pol_d, SCHEMA, SignatureConfig(required=True, keyring=later, now=LATE))
    assert loaded2.signature["signers"] == sorted([c_id, d_id])


def test_cli_rotate_overlap_and_quorum_less_does_not_write(tmp_path):
    a_dir, b_dir = tmp_path / "a", tmp_path / "b"
    r = _cli("keygen", "--out", str(a_dir), "--identity", "alice@example.com")
    assert r.returncode == 0, r.stderr
    assert (a_dir / "policy-signing.key").stat().st_mode & 0o077 == 0
    assert _cli("keygen", "--out", str(b_dir), "--identity", "bob@example.com").returncode == 0
    kr = tmp_path / "keyring.yaml"
    member = ("id={id},pub={pub},roles=policy+keyring,not-before=2026-01-01T00:00:00Z,not-after=2027-06-01T00:00:00Z")
    init = _cli(
        "init-keyring", "--out", str(kr), "--keyring-threshold", "2", "--policy-threshold", "2", "--at", "2026-06-01T00:00:00Z",
        "--member", member.format(id="alice@example.com", pub=a_dir / "policy-signing.key.pub"),
        "--member", member.format(id="bob@example.com", pub=b_dir / "policy-signing.key.pub"),
        "--sign", f"{a_dir / 'policy-signing.key'}=alice@example.com",
        "--sign", f"{b_dir / 'policy-signing.key'}=bob@example.com",
    )
    assert init.returncode == 0, init.stderr + init.stdout
    c_dir = tmp_path / "c"
    assert _cli("keygen", "--out", str(c_dir), "--identity", "carol@example.com").returncode == 0
    new_member = "id=carol@example.com,pub={pub},roles=policy+keyring,not-before=2026-05-01T00:00:00Z,not-after=2028-01-01T00:00:00Z".format(
        pub=c_dir / "policy-signing.key.pub")
    solo = _cli(
        "add-key", "--keyring", str(kr), "--at", "2026-06-01T00:00:00Z", "--member", new_member,
        "--sign", f"{a_dir / 'policy-signing.key'}=alice@example.com",
    )
    assert solo.returncode != 0 and "Quorum" in (solo.stderr + solo.stdout)
    assert b'"version": 1\n' in kr.read_bytes()
    rotated = _cli(
        "rotate-key", "--keyring", str(kr), "--at", "2026-06-01T00:00:00Z",
        "--retire", "alice@example.com", "--retire-not-after", "2026-12-01T00:00:00Z",
        "--member", new_member,
        "--sign", f"{a_dir / 'policy-signing.key'}=alice@example.com",
        "--sign", f"{b_dir / 'policy-signing.key'}=bob@example.com",
    )
    assert rotated.returncode == 0, rotated.stderr + rotated.stdout
    status = _cli("status", "--keyring", str(kr), "--at", "2026-06-15T00:00:00Z")
    assert status.returncode == 0, status.stderr
    assert "version: 2" in status.stdout
    assert "carol@example.com" in status.stdout and "valid" in status.stdout
    # alice still valid on 2026-06-15 (overlap), expired after retire-not-after
    assert "alice@example.com" in status.stdout
    later = _cli("status", "--keyring", str(kr), "--at", "2026-12-15T00:00:00Z")
    assert "alice@example.com" in later.stdout and "expired" in later.stdout.split("alice@example.com", 1)[1].split("\n", 1)[0]


def test_gateway_audits_signers_and_rejects_bad_keyring(tmp_path, monkeypatch):
    a, b = ("alice@example.com", _priv()), ("bob@example.com", _priv())
    doc, bundle = _ring([a, b])
    pol, kr = _sign_policy(tmp_path, doc, bundle, [a, b])
    from aism_gateway import main as gw
    monkeypatch.setattr(gw, "POLICY_PATH", str(pol))
    monkeypatch.setattr(gw, "SCHEMA_PATH", str(SCHEMA))
    monkeypatch.setattr(gw, "KEYRING_PATH", str(kr))
    monkeypatch.setattr(gw, "KEYRING_STATE", str(tmp_path / "state.json"))
    monkeypatch.setattr(gw, "ALLOWED_SIGNERS", None)
    monkeypatch.setattr(gw, "REQUIRE_SIGNATURE", True)
    monkeypatch.setattr(gw, "SIG_CFG", SignatureConfig(required=True, now=NOW))
    monkeypatch.setattr(gw, "AUDIT_PATH_ENV", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(gw.S, "audit", None)
    monkeypatch.setattr(gw.S, "policy", None)
    monkeypatch.setattr(gw.S, "keyring_doc", None)
    gw.try_load(initial=True)
    assert gw.S.policy is not None
    assert gw.S.policy.signature["signers"] == ["alice@example.com", "bob@example.com"]
    assert gw.S.keyring_doc.version == 1
    info = asyncio.run(gw.policy_info())
    assert info["revision"] and info["digest"].startswith("sha256:")
    assert info["signature"]["signers"] == ["alice@example.com", "bob@example.com"]
    assert info["signature"]["threshold"] == 2 and info["signature"]["verified"] is True
    assert info["keyring"]["version"] == 1
    assert [s["id"] for s in info["keyring"]["signers"]] == ["alice@example.com", "bob@example.com"]
    events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    loaded = events[-1]
    assert loaded["event"] == "policy.loaded"
    assert loaded["signature"]["signers"] == ["alice@example.com", "bob@example.com"]
    assert loaded["policy"]["signers"] == ["alice@example.com", "bob@example.com"]
    blob = json.dumps(loaded)
    assert "BEGIN OPENSSH PRIVATE" not in blob and "private_key" not in blob
    good = gw.S.policy.digest
    original_policy = pol.read_bytes()
    pol.write_text(pol.read_text() + "\n# tampered\n")
    gw.try_load()
    assert gw.S.policy.digest == good and "Signatur" in gw.S.policy_error
    # quorum-less successor of the stored ring: version and policy stay
    saved_body, saved_sigs = kr.read_bytes(), (kr.parent / "keyring.yaml.sigs").read_bytes()
    outsider = _member("carol@example.com", _priv())
    proposed = keyring.compile_keyring(2, doc.digest, 2, 2, [*doc.keys, outsider])
    lone = keyring.dump_bundle({"digest": proposed.digest, "version": 2},
                               keyring.sign_entries(proposed.body, [(a[1], a[0])], keyring.NAMESPACE))
    keyring.write_pair(kr, proposed.body, lone)
    gw.try_load()
    assert gw.S.keyring_doc.version == 1 and gw.S.policy.digest == good
    assert "Quorum" in gw.S.policy_error
    kr.write_bytes(saved_body)
    (kr.parent / "keyring.yaml.sigs").write_bytes(saved_sigs)
    pol.write_bytes(original_policy)
    gw.try_load()
    assert gw.S.policy_error is None and gw.S.policy.signature["verified"] is True and gw.S.policy.digest == good
