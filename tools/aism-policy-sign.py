#!/usr/bin/env python3
"""Sign and verify AISM policies, and rotate the trust keyring (Ed25519 SSHSIG).

Single signature (threshold 1, K1/K2), interoperable with ssh-keygen -Y verify:

  keygen --out DIR --identity ID
  sign   --key KEY --identity ID POLICY [--revision REV]
  verify --allowed-signers FILE POLICY

Four-eyes keyring (K3 default: policy threshold 2). Private keys are generated at
runtime and never committed. The keyring file is changed only by a quorum of keys
that are valid in the current ring; a new key's own signature does not count.

  init-keyring --out keyring.yaml --keyring-threshold 2 --policy-threshold 2 \\
      --member id=alice@example.com,pub=alice.pub,roles=policy+keyring,\\
               not-before=2020-01-01T00:00:00Z,not-after=2035-01-01T00:00:00Z \\
      --member id=bob@example.com,pub=bob.pub,roles=policy+keyring,not-before=...,not-after=... \\
      --sign alice.key=alice@example.com --sign bob.key=bob@example.com
  add-key    --keyring keyring.yaml --member ... --sign k1=id1 --sign k2=id2
  rotate-key --keyring keyring.yaml --retire OLD --retire-not-after TS --member ... --sign ...
  revoke-key --keyring keyring.yaml --identity ID --sign ...
  sign   --keyring keyring.yaml --key KEY --identity ID POLICY
  verify --keyring keyring.yaml POLICY
  status --keyring keyring.yaml [--policy POLICY] [--state keyring-state.json]

Namespaces: aism-policy (policy bytes), aism-keyring (keyring bytes).
Passphrase-protected keys: set AISM_POLICY_KEY_PASSPHRASE.
--at ISO-8601 overrides the clock (tests). Overlapping validity windows are required
when a key is retired, so rotation does not need downtime.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import os
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "gateway"))
from aism_gateway import keyring, policysig  # noqa: E402

import yaml  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402


def keygen(a):
    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    priv = out / "policy-signing.key"
    fd = os.open(priv, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                  serialization.NoEncryption()))
    pub = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    (out / "policy-signing.key.pub").write_text(f"{pub} {a.identity}\n")
    (out / "allowed_signers").write_text(f'{a.identity} namespaces="{policysig.NAMESPACE}" {pub}\n')
    print(f"private key : {priv} (0600 – do NOT commit)\npublic key  : {out / 'policy-signing.key.pub'}\n"
          f"trust anchor: {out / 'allowed_signers'}")


def _load_priv(path: str) -> Ed25519PrivateKey:
    pw = os.environ.get("AISM_POLICY_KEY_PASSPHRASE")
    key = serialization.load_ssh_private_key(pathlib.Path(path).read_bytes(), pw.encode() if pw else None)
    if not isinstance(key, Ed25519PrivateKey):
        sys.exit("only Ed25519 keys are supported")
    return key


def _now(a) -> dt.datetime:
    if getattr(a, "at", None):
        return keyring.parse_time(a.at)
    return dt.datetime.now(dt.timezone.utc)


def _parse_member(spec: str):
    parts = {}
    for item in spec.split(","):
        if "=" not in item:
            sys.exit(f"member field without '=': {item}")
        k, v = item.split("=", 1)
        parts[k.strip()] = v.strip()
    missing = {"id", "pub", "roles", "not-before", "not-after"} - parts.keys()
    if missing:
        sys.exit(f"member is missing {sorted(missing)}")
    try:
        return keyring.member(parts["id"], pathlib.Path(parts["pub"]).read_text(encoding="utf-8"),
                              frozenset(parts["roles"].replace("+", ",").split(",")),
                              keyring.parse_time(parts["not-before"]), keyring.parse_time(parts["not-after"]))
    except (OSError, keyring.KeyringError) as exc:
        sys.exit(f"FAIL: {exc}")


def _parse_signs(specs: list[str]) -> list[tuple]:
    out = []
    for spec in specs:
        if "=" not in spec:
            sys.exit(f"--sign must be KEY=IDENTITY, got {spec!r}")
        key_path, identity = spec.split("=", 1)
        out.append((_load_priv(key_path), identity))
    if not out:
        sys.exit("at least one --sign KEY=IDENTITY is required")
    return out


def _fail(exc: Exception) -> None:
    sys.exit(f"FAIL: {exc}")


def _mutate(path: pathlib.Path, transform, signers: list[tuple], now: dt.datetime) -> None:
    try:
        current = keyring.load_tip(path, now)
        updated = keyring.compile_keyring(current.version + 1, current.digest, current.keyring_threshold,
                                          current.policy_threshold, transform(list(current.keys)))
        bundle = keyring.seal_keyring(current, updated, signers, now)
    except keyring.KeyringError as exc:
        _fail(exc)
    keyring.write_pair(path, updated.body, bundle)
    print(f"keyring {path} version {updated.version} quorum: {', '.join(updated.quorum_signers)}")


def init_keyring(a):
    path = pathlib.Path(a.out)
    if path.exists() or keyring.sigs_path(path).exists():
        sys.exit(f"FAIL: {path} already exists (refusing to overwrite a trust root)")
    try:
        doc = keyring.compile_keyring(1, "", a.keyring_threshold, a.policy_threshold,
                                      [_parse_member(m) for m in a.member])
        bundle = keyring.seal_keyring(None, doc, _parse_signs(a.sign), _now(a))
    except keyring.KeyringError as exc:
        _fail(exc)
    keyring.write_pair(path, doc.body, bundle)
    print(f"genesis keyring {path} version 1 policy_threshold {doc.policy_threshold} "
          f"keyring_threshold {doc.keyring_threshold} quorum: {', '.join(doc.quorum_signers)}")


def add_key(a):
    fresh = _parse_member(a.member)

    def transform(keys):
        if any(k.id == fresh.id for k in keys):
            sys.exit(f"FAIL: {fresh.id} is already in the keyring")
        return [*keys, fresh]

    _mutate(pathlib.Path(a.keyring), transform, _parse_signs(a.sign), _now(a))


def rotate_key(a):
    """Add a key and shorten the retired key so both are valid at --at (default: now)."""
    now = _now(a)
    fresh = _parse_member(a.member)
    try:
        retire_end = keyring.parse_time(a.retire_not_after)
    except keyring.KeyringError as exc:
        _fail(exc)

    def transform(keys):
        retired = next((k for k in keys if k.id == a.retire), None)
        if retired is None:
            sys.exit(f"FAIL: {a.retire} is not in the keyring")
        if any(k.id == fresh.id for k in keys):
            sys.exit(f"FAIL: {fresh.id} is already in the keyring")
        if not (retired.not_before < retire_end):
            sys.exit("FAIL: retire-not-after is not after the retired key's not-before")
        overlap = fresh.not_before < retire_end and fresh.not_before <= now < retire_end and fresh.not_before <= now < fresh.not_after
        if not overlap:
            sys.exit("FAIL: no overlap: the retired key and the new key must both be valid at the rotation time")
        return [keyring.TrustKey(k.id, k.public_key, k.blob, k.roles, k.not_before,
                                 retire_end if k.id == a.retire else k.not_after, k.revoked) for k in keys] + [fresh]

    _mutate(pathlib.Path(a.keyring), transform, _parse_signs(a.sign), now)


def revoke_key(a):
    def transform(keys):
        if not any(k.id == a.identity for k in keys):
            sys.exit(f"FAIL: {a.identity} is not in the keyring")
        return [keyring.TrustKey(k.id, k.public_key, k.blob, k.roles, k.not_before, k.not_after,
                                 True if k.id == a.identity else k.revoked) for k in keys]

    _mutate(pathlib.Path(a.keyring), transform, _parse_signs(a.sign), _now(a))


def _revision(path: pathlib.Path, text: str, explicit: str | None) -> tuple[str, str]:
    if explicit:
        return explicit, "explicit"
    try:
        sha = subprocess.run(["git", "-C", str(path.parent), "rev-parse", "HEAD"], capture_output=True, text=True,
                             check=True).stdout.strip()
        if re.fullmatch(r"[0-9a-f]{40,64}", sha):
            return sha, "git"
    except (OSError, subprocess.CalledProcessError):
        pass
    body = re.sub(r"(?m)^  revision:.*\n", "", text)
    return hashlib.sha256(body.encode()).hexdigest()[:40], "content-sha256"


def _rewrite_meta(text: str, extra: list[str]) -> str:
    lines = text.splitlines(keepends=True)
    try:
        start = next(i for i, l in enumerate(lines) if l.rstrip() == "metadata:")
    except StopIteration:
        sys.exit("metadata: block not found")
    end = next((i for i in range(start + 1, len(lines)) if lines[i].strip() and not lines[i].startswith((" ", "#"))),
               len(lines))
    block = [l for l in lines[start + 1:end]]
    out, skip = [], False
    for l in block:
        if re.match(r"^  #? ?(revision|signature):", l):
            skip = l.lstrip().startswith(("signature", "# signature"))
            continue
        if skip and re.match(r"^  (#\s*)?\s{2,}\S", l):
            continue
        skip = False
        out.append(l)
    while out and not out[-1].strip():
        out.pop()
    out += extra + ["\n"]
    return "".join(lines[:start + 1] + out + lines[end:])


def _set_meta(text: str, revision: str, sig_ref: str, identity: str) -> str:
    return _rewrite_meta(text, [f"  revision: \"{revision}\"\n", "  signature:\n", "    method: ssh-sig\n",
                                f"    ref: {sig_ref}\n", f"    signer: {identity}\n"])


def _set_meta_multi(text: str, revision: str, sig_ref: str, threshold: int) -> str:
    return _rewrite_meta(text, [f"  revision: \"{revision}\"\n", "  signature:\n", "    method: ssh-sig\n",
                                f"    ref: {sig_ref}\n", f"    threshold: {threshold}\n"])


def sign(a):
    if a.keyring:
        sign_multi(a)
        return
    path = pathlib.Path(a.policy)
    text = path.read_text(encoding="utf-8")
    rev, how = _revision(path, text, a.revision)
    sig_path = path.with_name(path.name + ".sig")
    new = _set_meta(text, rev, sig_path.name, a.identity)
    meta = yaml.safe_load(new)["metadata"]
    assert meta["revision"] == rev and meta["signature"]["ref"] == sig_path.name, "metadata rewrite failed"
    key = _load_priv(a.key)
    data = new.encode("utf-8")
    sig = policysig.sign(data, key)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    sig_tmp = sig_path.with_name(sig_path.name + ".tmp")
    sig_tmp.write_text(sig)
    # write the signature first, then the policy: a reloading gateway sees either old+old, new sig+old
    # policy (rejected, old policy stays active) or new+new.
    os.replace(sig_tmp, sig_path)
    os.replace(tmp, path)
    print(f"signed {path} (revision {rev} [{how}], signer {a.identity}) -> {sig_path}")


def sign_multi(a):
    """Append one signature. The policy bytes stay fixed after the first signer, so earlier signatures remain valid."""
    now = _now(a)
    try:
        doc = keyring.load_tip(a.keyring, now)
    except keyring.KeyringError as exc:
        _fail(exc)
    path = pathlib.Path(a.policy)
    text = path.read_text(encoding="utf-8")
    try:
        meta = (yaml.safe_load(text) or {}).get("metadata") or {}
    except yaml.YAMLError as exc:
        sys.exit(f"FAIL: policy is not valid YAML ({exc.__class__.__name__})")
    sig_name = path.name + ".sigs"
    sig_meta = meta.get("signature") or {}
    threshold = doc.policy_threshold if a.threshold is None else max(doc.policy_threshold, a.threshold)
    already = sig_meta.get("method") == "ssh-sig" and sig_meta.get("ref") == sig_name
    if already:
        if a.revision and a.revision != str(meta.get("revision")):
            sys.exit("FAIL: revision is already signed; refusing to rewrite the policy")
        if int(sig_meta.get("threshold") or 0) != threshold:
            sys.exit("FAIL: threshold is already signed; refusing to rewrite the policy")
        rev, how = str(meta["revision"]), "unchanged"
        new = text
    else:
        bundle_path = path.parent / sig_name
        if bundle_path.exists():
            sys.exit("FAIL: signature bundle exists but metadata.signature does not point at it")
        rev, how = _revision(path, text, a.revision)
        new = _set_meta_multi(text, rev, sig_name, threshold)
        written = yaml.safe_load(new)["metadata"]
        if written["revision"] != rev or written["signature"]["threshold"] != threshold:
            sys.exit("metadata rewrite failed")
    data = new.encode("utf-8")
    key = _load_priv(a.key)
    armored = policysig.sign(data, key, namespace=policysig.NAMESPACE)
    try:
        _blob, fp = policysig.verify_crypto(data, armored, policysig.NAMESPACE)
    except policysig.SignatureError as exc:
        _fail(exc)
    bundle_path = path.parent / sig_name
    entries: list[dict] = []
    if already and bundle_path.is_file() and data == path.read_bytes():
        try:
            _subject, old = keyring.parse_bundle(bundle_path.read_text(encoding="utf-8"))
        except keyring.KeyringError as exc:
            _fail(exc)
        entries = [e for e in old if e.get("identity") != a.identity]
    entries.append({"armored": armored, "fingerprint": fp, "identity": a.identity})
    bundle = keyring.dump_bundle({"digest": keyring.sha256_prefixed(data), "revision": str(rev)}, entries)
    keyring.atomic_write(bundle_path, bundle.encode("utf-8"))
    if data != path.read_bytes():
        keyring.atomic_write(path, data)
    try:
        result = keyring.verify_policy(data, bundle, doc, str(rev), threshold, now)
    except keyring.KeyringError as exc:
        print(f"signed {path} (revision {rev} [{how}], signer {a.identity}) -> {bundle_path}")
        print(f"threshold not yet met: {exc}")
        return
    print(f"signed {path} (revision {rev} [{how}], signer {a.identity}) -> {bundle_path}")
    print(f"threshold met: {', '.join(result.signers)} ({len(result.signers)}/{result.threshold})")


def _policy_bundle(path: pathlib.Path, meta: dict) -> tuple[bytes, str, str, int | None]:
    data = path.read_bytes()
    sig = meta.get("signature") or {}
    ref = str(sig.get("ref") or "")
    if not ref or "/" in ref or "\\" in ref or ref.startswith("."):
        sys.exit("FAIL: metadata.signature.ref must be a file name next to the policy")
    try:
        payload = (path.parent / ref).read_text(encoding="utf-8")
    except OSError as exc:
        sys.exit(f"FAIL: {exc}")
    revision = str(meta.get("revision") or "")
    raw_th = sig.get("threshold")
    meta_th = int(raw_th) if raw_th is not None else None
    if ref.endswith(".sigs"):
        return data, payload, revision, meta_th
    return data, keyring.single_sig_bundle(data, payload, str(sig.get("signer") or ""), revision), revision, meta_th


def verify(a):
    path = pathlib.Path(a.policy)
    data = path.read_bytes()
    try:
        meta = (yaml.safe_load(data) or {}).get("metadata") or {}
    except yaml.YAMLError as exc:
        sys.exit(f"FAIL: policy is not valid YAML ({exc.__class__.__name__})")
    if a.keyring:
        try:
            doc = keyring.load_tip(a.keyring, _now(a))
            body, bundle, revision, meta_th = _policy_bundle(path, meta)
            result = keyring.verify_policy(body, bundle, doc, revision, meta_th, _now(a))
        except (OSError, keyring.KeyringError, policysig.SignatureError, ValueError) as exc:
            sys.exit(f"FAIL: {exc}")
        print(f"OK: {path} revision {revision} digest {result.digest} "
              f"signers {', '.join(result.signers)} ({len(result.signers)}/{result.threshold})")
        return
    s = meta.get("signature") or {}
    if s.get("method") != "ssh-sig":
        sys.exit(f"FAIL: metadata.signature.method is {s.get('method')!r}, expected 'ssh-sig'")
    sig_path = path.parent / s["ref"]
    try:
        info = policysig.verify(data, sig_path.read_text(), pathlib.Path(a.allowed_signers).read_text(), s.get("signer"))
    except (OSError, policysig.SignatureError) as exc:
        sys.exit(f"FAIL: {exc}")
    print(f"OK: {path} revision {meta.get('revision')} signed by {info.principal} ({info.key_fingerprint})")


def status(a):
    now = _now(a)
    path = pathlib.Path(a.keyring)
    try:
        if a.state:
            doc = keyring.accept_path(path, a.state, now=now, persist=False)
            print(f"stored keyring accepts version {doc.version}")
        else:
            doc = keyring.load_tip(path, now)
    except keyring.KeyringError as exc:
        _fail(exc)
    print("\n".join(keyring.describe(doc, now)))
    if not a.policy:
        return
    policy = pathlib.Path(a.policy)
    try:
        meta = (yaml.safe_load(policy.read_bytes()) or {}).get("metadata") or {}
        body, bundle, revision, meta_th = _policy_bundle(policy, meta)
        result = keyring.verify_policy(body, bundle, doc, revision, meta_th, now)
    except (OSError, yaml.YAMLError, keyring.KeyringError, policysig.SignatureError, ValueError) as exc:
        print(f"policy: FAIL: {exc}")
        sys.exit(1)
    excluded = f" excluded: {', '.join(result.excluded)}" if result.excluded else ""
    print(f"policy: OK revision {result.revision} digest {result.digest} "
          f"signers {', '.join(result.signers)} ({len(result.signers)}/{result.threshold}){excluded}")


def _add_at(parser):
    parser.add_argument("--at", help="ISO-8601 time used for validity windows (default: current time)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--out", required=True)
    k.add_argument("--identity", required=True)
    s = sub.add_parser("sign")
    s.add_argument("--key", required=True)
    s.add_argument("--identity", required=True)
    s.add_argument("--revision")
    s.add_argument("--keyring", help="keyring.yaml; selects the multi-signature bundle (policy.yaml.sigs)")
    s.add_argument("--threshold", type=int, help="raise the policy threshold above the keyring floor")
    _add_at(s)
    s.add_argument("policy")
    v = sub.add_parser("verify")
    v.add_argument("--allowed-signers")
    v.add_argument("--keyring")
    _add_at(v)
    v.add_argument("policy")
    ik = sub.add_parser("init-keyring")
    ik.add_argument("--out", required=True, help="path of keyring.yaml to create")
    ik.add_argument("--keyring-threshold", type=int, required=True)
    ik.add_argument("--policy-threshold", type=int, required=True)
    ik.add_argument("--member", action="append", required=True)
    ik.add_argument("--sign", action="append", required=True, help="KEY=IDENTITY")
    _add_at(ik)
    for name in ("add-key", "rotate-key"):
        p = sub.add_parser(name)
        p.add_argument("--keyring", required=True)
        p.add_argument("--member", required=True)
        p.add_argument("--sign", action="append", required=True)
        _add_at(p)
        if name == "rotate-key":
            p.add_argument("--retire", required=True)
            p.add_argument("--retire-not-after", required=True)
    rv = sub.add_parser("revoke-key")
    rv.add_argument("--keyring", required=True)
    rv.add_argument("--identity", required=True)
    rv.add_argument("--sign", action="append", required=True)
    _add_at(rv)
    st = sub.add_parser("status")
    st.add_argument("--keyring", required=True)
    st.add_argument("--state", help="gateway state file; checks rollback against the stored ring")
    st.add_argument("--policy")
    _add_at(st)
    a = ap.parse_args()
    if a.cmd == "verify" and bool(a.allowed_signers) == bool(a.keyring):
        sys.exit("verify needs exactly one of --allowed-signers or --keyring")
    {"keygen": keygen, "sign": sign, "verify": verify, "init-keyring": init_keyring, "add-key": add_key,
     "rotate-key": rotate_key, "revoke-key": revoke_key, "status": status}[a.cmd](a)


if __name__ == "__main__":
    main()
