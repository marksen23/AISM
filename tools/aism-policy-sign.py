#!/usr/bin/env python3
"""Sign / verify AISM policies (detached SSHSIG, Ed25519, namespace "aism-policy").

  keygen  --out DIR --identity ID     generate an Ed25519 key pair + allowed_signers line
                                      (TEST KEYS: generate at runtime, never commit the private key)
  sign    --key KEY --identity ID POLICY [--revision REV]
                                      sets metadata.revision and metadata.signature in POLICY
                                      (text edit, comments are kept) and writes POLICY.sig
  verify  --allowed-signers FILE POLICY
                                      verifies POLICY against the signature named in metadata.signature.ref

Compatible with OpenSSH:  ssh-keygen -Y verify -f allowed_signers -I ID -n aism-policy -s policy.yaml.sig < policy.yaml
Revision: --revision, else `git rev-parse HEAD` of the policy's repository, else the sha256 of the
policy text without its revision line (first 40 hex chars; documented as content revision, not a Git SHA).
Passphrase-protected keys: set AISM_POLICY_KEY_PASSPHRASE.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "gateway"))
from aism_gateway import policysig  # noqa: E402

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


def _set_meta(text: str, revision: str, sig_ref: str, identity: str) -> str:
    lines = text.splitlines(keepends=True)
    try:
        start = next(i for i, l in enumerate(lines) if l.rstrip() == "metadata:")
    except StopIteration:
        sys.exit("metadata: block not found")
    end = next((i for i in range(start + 1, len(lines)) if lines[i].strip() and not lines[i].startswith((" ", "#"))),
               len(lines))
    block = [l for l in lines[start + 1:end]]
    # drop existing revision / signature (incl. its indented children, also commented-out examples)
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
    out += [f"  revision: \"{revision}\"\n",
            "  signature:\n",
            "    method: ssh-sig\n",
            f"    ref: {sig_ref}\n",
            f"    signer: {identity}\n", "\n"]
    return "".join(lines[:start + 1] + out + lines[end:])


def sign(a):
    path = pathlib.Path(a.policy)
    text = path.read_text(encoding="utf-8")
    rev, how = _revision(path, text, a.revision)
    sig_path = path.with_name(path.name + ".sig")
    new = _set_meta(text, rev, sig_path.name, a.identity)
    meta = yaml.safe_load(new)["metadata"]
    assert meta["revision"] == rev and meta["signature"]["ref"] == sig_path.name, "metadata rewrite failed"
    pw = os.environ.get("AISM_POLICY_KEY_PASSPHRASE")
    key = serialization.load_ssh_private_key(pathlib.Path(a.key).read_bytes(), pw.encode() if pw else None)
    if not isinstance(key, Ed25519PrivateKey):
        sys.exit("only Ed25519 keys are supported")
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


def verify(a):
    path = pathlib.Path(a.policy)
    data = path.read_bytes()
    try:
        meta = (yaml.safe_load(data) or {}).get("metadata") or {}
    except yaml.YAMLError as exc:
        sys.exit(f"FAIL: policy is not valid YAML ({exc.__class__.__name__})")
    s = meta.get("signature") or {}
    if s.get("method") != "ssh-sig":
        sys.exit(f"FAIL: metadata.signature.method is {s.get('method')!r}, expected 'ssh-sig'")
    sig_path = path.parent / s["ref"]
    try:
        info = policysig.verify(data, sig_path.read_text(), pathlib.Path(a.allowed_signers).read_text(), s.get("signer"))
    except (OSError, policysig.SignatureError) as exc:
        sys.exit(f"FAIL: {exc}")
    print(f"OK: {path} revision {meta.get('revision')} signed by {info.principal} ({info.key_fingerprint})")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen"); k.add_argument("--out", required=True); k.add_argument("--identity", required=True)
    s = sub.add_parser("sign"); s.add_argument("--key", required=True); s.add_argument("--identity", required=True)
    s.add_argument("--revision"); s.add_argument("policy")
    v = sub.add_parser("verify"); v.add_argument("--allowed-signers", required=True); v.add_argument("policy")
    a = ap.parse_args()
    {"keygen": keygen, "sign": sign, "verify": verify}[a.cmd](a)


if __name__ == "__main__":
    main()
