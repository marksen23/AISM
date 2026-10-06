"""Detached policy signatures in the OpenSSH SSHSIG format (PROTOCOL.sshsig), Ed25519 only.

Why SSHSIG: works fully offline (no transparency log / Fulcio / Rekor needed), keys can live on a
hardware token (ssh-keygen -t ed25519-sk is NOT supported by this verifier, plain ed25519 only),
the same key can sign Git commits/tags (gpg.format=ssh), and signatures are interoperable with
`ssh-keygen -Y sign` / `ssh-keygen -Y verify`. This module needs only `cryptography`.

Signature namespace: "aism-policy" (prevents reuse of e.g. Git or file signatures of the same key).
Trust anchor: an OpenSSH allowed_signers file; only lines whose namespaces= option (if present)
includes "aism-policy" are considered. cert-authority lines are not supported (ignored).
"""
from __future__ import annotations

import base64
import hashlib
import shlex
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

NAMESPACE = "aism-policy"
MAGIC = b"SSHSIG"
ARMOR_BEGIN = "-----BEGIN SSH SIGNATURE-----"
ARMOR_END = "-----END SSH SIGNATURE-----"
HASHES = {"sha512": hashlib.sha512, "sha256": hashlib.sha256}


class SignatureError(Exception):
    pass


def _s(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


class _Reader:
    def __init__(self, data: bytes):
        self.d, self.i = data, 0

    def raw(self, n: int) -> bytes:
        if self.i + n > len(self.d):
            raise SignatureError("Signatur abgeschnitten")
        out = self.d[self.i:self.i + n]
        self.i += n
        return out

    def u32(self) -> int:
        return struct.unpack(">I", self.raw(4))[0]

    def string(self) -> bytes:
        return self.raw(self.u32())


def _pub_blob(pub: Ed25519PublicKey) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return _s(b"ssh-ed25519") + _s(pub.public_bytes(Encoding.Raw, PublicFormat.Raw))


def _pub_from_blob(blob: bytes) -> Ed25519PublicKey:
    r = _Reader(blob)
    kt = r.string()
    if kt != b"ssh-ed25519":
        raise SignatureError(f"Schlüsseltyp {kt.decode(errors='replace')} nicht unterstützt (nur ssh-ed25519)")
    return Ed25519PublicKey.from_public_bytes(r.string())


def _signed_data(namespace: str, hash_alg: str, message: bytes) -> bytes:
    return MAGIC + _s(namespace.encode()) + _s(b"") + _s(hash_alg.encode()) + _s(HASHES[hash_alg](message).digest())


def sign(message: bytes, key: Ed25519PrivateKey, namespace: str = NAMESPACE) -> str:
    sig = key.sign(_signed_data(namespace, "sha512", message))
    blob = (MAGIC + struct.pack(">I", 1) + _s(_pub_blob(key.public_key())) + _s(namespace.encode()) + _s(b"")
            + _s(b"sha512") + _s(_s(b"ssh-ed25519") + _s(sig)))
    b64 = base64.b64encode(blob).decode()
    return "\n".join([ARMOR_BEGIN, *[b64[i:i + 70] for i in range(0, len(b64), 70)], ARMOR_END]) + "\n"


@dataclass
class SigInfo:
    principal: str
    key_fingerprint: str
    namespace: str


def fingerprint(blob: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def parse_allowed_signers(text: str) -> list[tuple[list[str], bytes]]:
    """Returns [(principals, pubkey_blob)] usable for NAMESPACE."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            tok = shlex.split(line)
        except ValueError:
            continue
        if len(tok) < 3:
            continue
        principals, rest = tok[0].split(","), tok[1:]
        opts: dict[str, str | bool] = {}
        if not rest[0].startswith(("ssh-", "ecdsa-", "sk-")):
            for o in rest[0].split(","):
                k, _, v = o.partition("=")
                opts[k.lower()] = v if v else True
            rest = rest[1:]
        if len(rest) < 2 or "cert-authority" in opts:
            continue
        if any(k in opts for k in ("valid-after", "valid-before")):
            continue          # not evaluated by this verifier -> ignore the line (fail closed)
        ns = opts.get("namespaces")
        if isinstance(ns, str) and NAMESPACE not in ns.split(","):
            continue
        if rest[0] != "ssh-ed25519":
            continue
        try:
            blob = base64.b64decode(rest[1], validate=True)
        except ValueError:
            continue
        out.append((principals, blob))
    return out


def parse_sshsig(armored: str, namespace: str = NAMESPACE) -> tuple[bytes, bytes, str, str]:
    """Structural parse. Returns (pubkey_blob, raw_signature, namespace, hash_alg)."""
    body = armored.strip()
    if not (body.startswith(ARMOR_BEGIN) and body.endswith(ARMOR_END)):
        raise SignatureError("keine SSH-Signatur (Armor fehlt)")
    try:
        blob = base64.b64decode("".join(body[len(ARMOR_BEGIN):-len(ARMOR_END)].split()), validate=True)
    except ValueError as exc:
        raise SignatureError("Signatur nicht base64-dekodierbar") from exc
    r = _Reader(blob)
    if r.raw(6) != MAGIC or r.u32() != 1:
        raise SignatureError("kein SSHSIG v1")
    pub_blob, ns, _reserved, hash_alg, sig_blob = (r.string(), r.string().decode(), r.string(),
                                                   r.string().decode(), r.string())
    if ns != namespace:
        raise SignatureError(f"falscher Signatur-Namespace {ns!r} (erwartet {namespace!r})")
    if hash_alg not in HASHES:
        raise SignatureError(f"Hash-Algorithmus {hash_alg} nicht unterstützt")
    sr = _Reader(sig_blob)
    if sr.string() != b"ssh-ed25519":
        raise SignatureError("nur ssh-ed25519-Signaturen werden unterstützt")
    return pub_blob, sr.string(), ns, hash_alg


def verify_crypto(message: bytes, armored: str, namespace: str = NAMESPACE) -> tuple[bytes, str]:
    """Verify an SSHSIG against the key embedded in it. Returns (pubkey_blob, fingerprint).

    Does not consult a trust anchor: callers decide whether the key is allowed to count.
    """
    pub_blob, sig, ns, hash_alg = parse_sshsig(armored, namespace)
    try:
        _pub_from_blob(pub_blob).verify(sig, _signed_data(ns, hash_alg, message))
    except InvalidSignature as exc:
        raise SignatureError("Signatur ungültig (Inhalt verändert oder falscher Schlüssel)") from exc
    return pub_blob, fingerprint(pub_blob)


def openssh_ed25519_blob(text: str) -> bytes:
    """Parse one OpenSSH public-key line (`ssh-ed25519 BASE64 [comment]`) into its wire blob."""
    parts = text.split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise SignatureError("nur ssh-ed25519-Public-Keys werden unterstützt")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except ValueError as exc:
        raise SignatureError("Public Key ist kein base64") from exc
    _pub_from_blob(blob)
    return blob


def verify(message: bytes, armored: str, allowed_signers: str, principal: str | None,
           namespace: str = NAMESPACE) -> SigInfo:
    pub_blob, sig, ns, hash_alg = parse_sshsig(armored, namespace)
    trusted = [p for p, b in parse_allowed_signers(allowed_signers) if b == pub_blob]
    if not trusted:
        raise SignatureError(f"Schlüssel {fingerprint(pub_blob)} nicht in allowed_signers (für {namespace})")
    principals = [x for ps in trusted for x in ps]
    if principal is not None and principal not in principals:
        raise SignatureError(f"Signer {principal!r} passt nicht zum Schlüssel {fingerprint(pub_blob)}")
    try:
        _pub_from_blob(pub_blob).verify(sig, _signed_data(ns, hash_alg, message))
    except InvalidSignature as exc:
        raise SignatureError("Signatur ungültig (Inhalt verändert oder falscher Schlüssel)") from exc
    return SigInfo(principal=principal or principals[0], key_fingerprint=fingerprint(pub_blob), namespace=ns)
