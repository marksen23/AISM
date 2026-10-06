"""Quorum-signed trust keyring and M-of-N policy signatures.

The keyring is a YAML document (exact bytes are signed) plus a detached bundle
`keyring.yaml.sigs`. Each signature is an SSHSIG over those bytes in the namespace
`aism-keyring`. A successor is accepted only when a quorum of keys that are valid
in the *previous* ring signs it, so one key cannot add itself or remove the others.
Version numbers are strictly monotonic and `prev` pins the predecessor digest.

Policy signatures live in `policy.yaml.sigs` (namespace `aism-policy`). Each one is
bound to the policy bytes; the bundle also records revision and digest. Distinct
identities count once. Expired, revoked and unknown keys do not count.

No HSM and no transparency log. The gateway clock decides validity windows.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import pathlib
from dataclasses import dataclass

import yaml

from . import policysig

NAMESPACE = "aism-keyring"
ROLES = frozenset({"policy", "keyring"})
BUNDLE_VERSION = "aism.trust/v1"


class KeyringError(Exception):
    pass


def sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def parse_time(value) -> dt.datetime:
    if not isinstance(value, str):
        raise KeyringError("Zeitstempel muss eine Zeichenkette mit Zeitzone sein")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise KeyringError(f"Zeitstempel nicht lesbar: {value}") from exc
    if parsed.tzinfo is None:
        raise KeyringError(f"Zeitstempel ohne Zeitzone: {value}")
    return parsed.astimezone(dt.timezone.utc)


def format_time(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now(now: dt.datetime | None) -> dt.datetime:
    if now is None:
        return dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        raise KeyringError("Prüfzeitpunkt ohne Zeitzone")
    return now.astimezone(dt.timezone.utc)


@dataclass(frozen=True)
class TrustKey:
    id: str
    public_key: str
    blob: bytes
    roles: frozenset[str]
    not_before: dt.datetime
    not_after: dt.datetime
    revoked: bool = False

    def status_at(self, now: dt.datetime) -> str:
        if self.revoked:
            return "revoked"
        if now < self.not_before:
            return "not-yet-valid"
        if now >= self.not_after:
            return "expired"
        return "valid"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "notAfter": format_time(self.not_after),
            "notBefore": format_time(self.not_before),
            "publicKey": self.public_key,
            "revoked": bool(self.revoked),
            "roles": sorted(self.roles),
        }


@dataclass
class KeyringDoc:
    version: int
    prev: str
    keyring_threshold: int
    policy_threshold: int
    keys: tuple[TrustKey, ...]
    body: bytes
    digest: str
    quorum_signers: tuple[str, ...] = ()

    def key_by_id(self, identity: str) -> TrustKey | None:
        return next((k for k in self.keys if k.id == identity), None)

    def key_by_blob(self, blob: bytes) -> TrustKey | None:
        return next((k for k in self.keys if k.blob == blob), None)


@dataclass
class BundleEntry:
    identity: str
    fingerprint: str
    armored: str
    blob: bytes


@dataclass
class PolicyVerification:
    signers: tuple[str, ...]
    fingerprints: dict[str, str]
    threshold: int
    excluded: tuple[str, ...]
    digest: str
    revision: str
    namespace: str = policysig.NAMESPACE


class _Dumper(yaml.SafeDumper):
    """Quote every string so digests, revisions and timestamps cannot change type on reload."""


def _repr_str(dumper: yaml.SafeDumper, data: str):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style='"')


_Dumper.add_representer(str, _repr_str)


def _dump(data: dict) -> bytes:
    text = yaml.dump(data, Dumper=_Dumper, sort_keys=True, allow_unicode=True, default_flow_style=False, width=10000)
    if not text.endswith("\n"):
        text += "\n"
    return text.encode("utf-8")


def member(identity: str, public_openssh: str, roles: frozenset[str] | set[str],
           not_before: dt.datetime, not_after: dt.datetime, revoked: bool = False) -> TrustKey:
    ident = str(identity).strip()
    if not ident or any(c.isspace() for c in ident) or len(ident) > 200:
        raise KeyringError(f"ungültige Signierer-Identität {identity!r}")
    role_set = frozenset(roles)
    if not role_set or not role_set <= ROLES:
        raise KeyringError(f"Rollen von {ident} müssen aus {sorted(ROLES)} sein")
    if not_before >= not_after:
        raise KeyringError(f"Gültigkeitsfenster von {ident} ist leer")
    try:
        blob = policysig.openssh_ed25519_blob(public_openssh)
    except policysig.SignatureError as exc:
        raise KeyringError(f"Public Key von {ident}: {exc}") from exc
    parts = public_openssh.split()
    return TrustKey(id=ident, public_key=f"{parts[0]} {parts[1]}", blob=blob, roles=role_set,
                    not_before=not_before, not_after=not_after, revoked=revoked)


def compile_keyring(version: int, prev: str, keyring_threshold: int, policy_threshold: int,
                    keys: list[TrustKey]) -> KeyringDoc:
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise KeyringError("Keyring-Version muss eine ganze Zahl >= 1 sein")
    if prev != "" and not (isinstance(prev, str) and len(prev) == 7 + 64 and prev.startswith("sha256:")):
        raise KeyringError("prev muss leer (Genesis) oder ein sha256-Digest sein")
    if version == 1 and prev != "":
        raise KeyringError("Genesis (version 1) muss prev leer lassen")
    if version > 1 and prev == "":
        raise KeyringError("Nachfolger müssen prev auf den Digest des Vorgängers setzen")
    for name, value in (("keyringThreshold", keyring_threshold), ("policyThreshold", policy_threshold)):
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise KeyringError(f"{name} muss eine ganze Zahl >= 1 sein")
    ordered = tuple(sorted(keys, key=lambda k: k.id))
    ids, blobs = [k.id for k in ordered], [k.blob for k in ordered]
    if len(ids) != len(set(ids)):
        raise KeyringError("doppelte Signierer-Identität im Schlüsselring")
    if len(blobs) != len(set(blobs)):
        raise KeyringError("derselbe Public Key ist mehrfach eingetragen")
    if not ordered:
        raise KeyringError("Schlüsselring ohne Signierer")
    body = _dump({
        "apiVersion": BUNDLE_VERSION,
        "keyringThreshold": keyring_threshold,
        "kind": "Keyring",
        "policyThreshold": policy_threshold,
        "prev": prev,
        "signers": [k.to_dict() for k in ordered],
        "version": version,
    })
    return KeyringDoc(version=version, prev=prev, keyring_threshold=keyring_threshold,
                      policy_threshold=policy_threshold, keys=ordered, body=body, digest=sha256_prefixed(body))


def parse_doc(body: bytes) -> KeyringDoc:
    try:
        raw = yaml.safe_load(body)
    except yaml.YAMLError as exc:
        raise KeyringError(f"Schlüsselring ist kein gültiges YAML: {exc.__class__.__name__}") from exc
    if not isinstance(raw, dict) or raw.get("kind") != "Keyring" or raw.get("apiVersion") != BUNDLE_VERSION:
        raise KeyringError("kein AISM-Schlüsselring (kind: Keyring, apiVersion aism.trust/v1)")
    try:
        keys = []
        for item in raw["signers"]:
            keys.append(member(item["id"], item["publicKey"], set(item["roles"]),
                               parse_time(item["notBefore"]), parse_time(item["notAfter"]),
                               bool(item.get("revoked", False))))
        doc = compile_keyring(int(raw["version"]), "" if raw.get("prev") in (None, "") else str(raw["prev"]),
                              int(raw["keyringThreshold"]), int(raw["policyThreshold"]), keys)
    except (KeyError, TypeError, ValueError) as exc:
        raise KeyringError(f"Schlüsselring unvollständig oder falsch typisiert ({exc})") from exc
    if doc.body != body:
        raise KeyringError("Schlüsselring weicht von der kanonischen Form ab (Signatur gilt für die exakten Bytes)")
    return doc


def dump_bundle(subject: dict, entries: list[dict]) -> str:
    body = _dump({
        "apiVersion": BUNDLE_VERSION,
        "kind": "DetachedSignatures",
        "signatures": entries,
        "subject": subject,
    })
    return body.decode("utf-8")


def parse_bundle(text: str) -> tuple[dict, list[dict]]:
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise KeyringError(f"Signaturbündel ist kein gültiges YAML: {exc.__class__.__name__}") from exc
    if not isinstance(raw, dict) or raw.get("kind") != "DetachedSignatures":
        raise KeyringError("kein AISM-Signaturbündel (kind: DetachedSignatures)")
    subject = raw.get("subject")
    sigs = raw.get("signatures")
    if not isinstance(subject, dict) or not isinstance(sigs, list) or not sigs:
        raise KeyringError("Signaturbündel ohne subject oder ohne Signaturen")
    return subject, sigs


def _crypto_entries(message: bytes, entries: list[dict], namespace: str) -> list[BundleEntry]:
    out = []
    for i, entry in enumerate(entries, 1):
        if not isinstance(entry, dict) or not isinstance(entry.get("armored"), str):
            raise KeyringError(f"Signatur {i} hat kein armored-Feld")
        identity = str(entry.get("identity") or "")
        try:
            blob, fp = policysig.verify_crypto(message, entry["armored"], namespace)
        except policysig.SignatureError as exc:
            who = identity or f"#{i}"
            raise KeyringError(f"Signatur ungültig ({who}): {exc}") from exc
        claimed = entry.get("fingerprint")
        if claimed and claimed != fp:
            raise KeyringError(f"Fingerprint von {identity or fp} stimmt nicht mit dem Schlüssel überein")
        out.append(BundleEntry(identity=identity, fingerprint=fp, armored=entry["armored"], blob=blob))
    return out


def verify_bundle(message: bytes, bundle_text: str, namespace: str, digest: str,
                  revision: str | None = None, version: int | None = None) -> list[BundleEntry]:
    subject, entries = parse_bundle(bundle_text)
    if subject.get("digest") != digest:
        raise KeyringError(
            f"Signaturbündel-Digest {subject.get('digest')!r} stimmt nicht mit dem Dokument überein ({digest})")
    if revision is not None and str(subject.get("revision")) != str(revision):
        raise KeyringError(
            f"Signaturbündel-Revision {subject.get('revision')!r} stimmt nicht mit der Policy ({revision}) überein")
    if version is not None and int(subject.get("version", -1)) != int(version):
        raise KeyringError(
            f"Signaturbündel-Version {subject.get('version')!r} stimmt nicht mit dem Schlüsselring ({version}) überein")
    return _crypto_entries(message, entries, namespace)


def _assert_workable(doc: KeyringDoc, now: dt.datetime) -> None:
    """A ring that cannot satisfy its own thresholds cannot be rotated or used. Refuse it."""
    now = _now(now)
    kr = [k for k in doc.keys if "keyring" in k.roles and k.status_at(now) == "valid"]
    pol = [k for k in doc.keys if "policy" in k.roles and k.status_at(now) == "valid"]
    if len(kr) < doc.keyring_threshold:
        raise KeyringError(
            f"Schlüsselring nicht fortsetzbar: {len(kr)} jetzt gültige keyring-Schlüssel, "
            f"Schwelle {doc.keyring_threshold} (Rotation braucht Überlappung, Widerruf unter die Schwelle ist abgelehnt)")
    if len(pol) < doc.policy_threshold:
        raise KeyringError(
            f"Schlüsselring kann Policies nicht signieren: {len(pol)} jetzt gültige policy-Schlüssel, "
            f"Schwelle {doc.policy_threshold}")


def _count(basis: KeyringDoc, found: list[BundleEntry], now: dt.datetime, role: str) -> tuple[list[str], list[str]]:
    """Distinct identities from `basis` with `role` that are valid now. Others are listed, not counted."""
    now = _now(now)
    counted: list[str] = []
    seen: set[str] = set()
    excluded: list[str] = []
    for entry in found:
        key = basis.key_by_blob(entry.blob)
        label = entry.identity or entry.fingerprint
        if key is None:
            excluded.append(f"{label}: unknown")
            continue
        if entry.identity and entry.identity != key.id:
            excluded.append(f"{entry.identity}: identity-mismatch")
            continue
        if role not in key.roles:
            excluded.append(f"{key.id}: role")
            continue
        status = key.status_at(now)
        if status != "valid":
            excluded.append(f"{key.id}: {status}")
            continue
        if key.id in seen:
            excluded.append(f"{key.id}: duplicate")
            continue
        seen.add(key.id)
        counted.append(key.id)
    return counted, excluded


def verify_genesis(doc: KeyringDoc, bundle_text: str, now: dt.datetime | None = None) -> list[str]:
    now = _now(now)
    if doc.version != 1 or doc.prev != "":
        raise KeyringError(
            "Kein gespeicherter Schlüsselring: nur eine Genesis (version 1, prev leer) wird beim ersten Start "
            f"akzeptiert (Datei ist Version {doc.version})")
    found = verify_bundle(doc.body, bundle_text, NAMESPACE, doc.digest, version=doc.version)
    counted, _excluded = _count(doc, found, now, "keyring")
    if len(counted) < doc.keyring_threshold:
        raise KeyringError(
            f"Keyring-Quorum nicht erreicht: {len(counted)} von {doc.keyring_threshold} gültigen "
            "Schlüsselring-Signierern (unbekannte, abgelaufene, widerrufene oder doppelt gesetzte "
            "Signaturen zählen nicht)")
    _assert_workable(doc, now)
    return counted


def verify_succession(previous: KeyringDoc, doc: KeyringDoc, bundle_text: str,
                      now: dt.datetime | None = None) -> list[str]:
    """Quorum is taken from keys that are valid in `previous`, never from keys that only exist in `doc`."""
    now = _now(now)
    if doc.digest == previous.digest:
        return list(previous.quorum_signers)
    if doc.version <= previous.version:
        raise KeyringError(
            f"Keyring-Rollback abgelehnt: Version {doc.version} ist nicht neuer als die gespeicherte "
            f"Version {previous.version}")
    if doc.version != previous.version + 1:
        raise KeyringError(
            f"Keyring-Versionssprung abgelehnt: {previous.version} -> {doc.version} "
            f"(erwartet {previous.version + 1})")
    if doc.prev != previous.digest:
        raise KeyringError(f"Keyring-Vorgänger stimmt nicht (prev {doc.prev}, erwartet {previous.digest})")
    found = verify_bundle(doc.body, bundle_text, NAMESPACE, doc.digest, version=doc.version)
    counted, _excluded = _count(previous, found, now, "keyring")
    if len(counted) < previous.keyring_threshold:
        raise KeyringError(
            f"Keyring-Quorum nicht erreicht: {len(counted)} von {previous.keyring_threshold} gültigen "
            "Schlüsselring-Signierern (Schlüssel, die nur im neuen Ring stehen, sowie unbekannte, "
            "abgelaufene, widerrufene oder doppelt gesetzte Signaturen zählen nicht)")
    _assert_workable(doc, now)
    return counted


def sign_entries(message: bytes, signers: list[tuple], namespace: str) -> list[dict]:
    """`signers` is a list of (Ed25519PrivateKey, identity)."""
    entries = []
    seen = set()
    for key, identity in signers:
        if identity in seen:
            continue
        seen.add(identity)
        armored = policysig.sign(message, key, namespace=namespace)
        _blob, fp = policysig.verify_crypto(message, armored, namespace)
        entries.append({"armored": armored, "fingerprint": fp, "identity": identity})
    return entries


def seal_keyring(previous: KeyringDoc | None, doc: KeyringDoc, signers: list[tuple],
                 now: dt.datetime | None = None) -> str:
    """Build the detached bundle and refuse to return it unless the quorum rule holds."""
    text = dump_bundle({"digest": doc.digest, "version": doc.version},
                       sign_entries(doc.body, signers, NAMESPACE))
    counted = verify_genesis(doc, text, now) if previous is None else verify_succession(previous, doc, text, now)
    doc.quorum_signers = tuple(counted)
    return text


def verify_policy(policy_bytes: bytes, bundle_text: str, doc: KeyringDoc, revision: str,
                  meta_threshold: int | None = None, now: dt.datetime | None = None) -> PolicyVerification:
    now = _now(now)
    digest = sha256_prefixed(policy_bytes)
    found = verify_bundle(policy_bytes, bundle_text, policysig.NAMESPACE, digest, revision=revision)
    need = doc.policy_threshold
    if meta_threshold is not None:
        if not isinstance(meta_threshold, int) or isinstance(meta_threshold, bool) or meta_threshold < 1:
            raise KeyringError("metadata.signature.threshold muss eine ganze Zahl >= 1 sein")
        if meta_threshold < need:
            raise KeyringError(
                f"metadata.signature.threshold {meta_threshold} unterschreitet die Keyring-Schwelle {need}")
        need = meta_threshold
    counted, excluded = _count(doc, found, now, "policy")
    if len(counted) < need:
        detail = f"; nicht gezählt: {', '.join(excluded)}" if excluded else ""
        raise KeyringError(
            f"Schwellenwert nicht erreicht: {len(counted)} von {need} verschiedenen gültigen Signierern{detail}")
    fps = {}
    for entry in found:
        key = doc.key_by_blob(entry.blob)
        if key is not None and key.id in counted:
            fps[key.id] = entry.fingerprint
    return PolicyVerification(signers=tuple(sorted(counted)), fingerprints=fps, threshold=need,
                              excluded=tuple(excluded), digest=digest, revision=str(revision))


def signers_still_authorized(signature: dict, doc: KeyringDoc, now: dt.datetime | None = None) -> bool:
    """Re-check a previously verified policy after a keyring update, without the original bytes.

    The fingerprint must still belong to that identity, so replacing a key under the same id
    does not keep the old signature alive.
    """
    if not signature.get("verified"):
        return False
    now = _now(now)
    fps = signature.get("fingerprints") or {}
    if not isinstance(fps, dict) or not fps:
        return False
    try:
        need = int(signature.get("threshold") or 1)
    except (TypeError, ValueError):
        return False
    ok = 0
    for ident, fp in fps.items():
        key = doc.key_by_id(str(ident))
        if key is None or policysig.fingerprint(key.blob) != fp:
            continue
        if "policy" not in key.roles or key.status_at(now) != "valid":
            continue
        ok += 1
    return ok >= need


def sigs_path(path: pathlib.Path) -> pathlib.Path:
    return path.with_name(path.name + ".sigs")


def read_pair(path: pathlib.Path) -> tuple[bytes, str]:
    try:
        body = path.read_bytes()
        sigs = sigs_path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise KeyringError(f"Schlüsselring nicht lesbar: {exc}") from exc
    return body, sigs


def atomic_write(path: pathlib.Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    os.chmod(path, mode)  # umask must not hide a rotated keyring from the gateway user


def write_pair(path: pathlib.Path, body: bytes, bundle: str) -> None:
    """Signatures first, then the document. A reader never sees a new document with the old bundle only
    after both replaces; a mixed pair fails verification and the previous ring stays in force."""
    atomic_write(sigs_path(path), bundle.encode("utf-8"))
    atomic_write(path, body)


def load_state(path: pathlib.Path) -> KeyringDoc | None:
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        doc = parse_doc(raw["body"].encode("utf-8"))
    except (OSError, json.JSONDecodeError, KeyError, KeyringError) as exc:
        raise KeyringError(f"gespeicherter Schlüsselring ist beschädigt ({exc})") from exc
    signers = raw.get("quorum_signers") or []
    doc.quorum_signers = tuple(str(s) for s in signers)
    return doc


def save_state(path: pathlib.Path, doc: KeyringDoc) -> None:
    payload = json.dumps({
        "body": doc.body.decode("utf-8"),
        "digest": doc.digest,
        "quorum_signers": list(doc.quorum_signers),
        "version": doc.version,
    }, ensure_ascii=False, sort_keys=True).encode("utf-8")
    atomic_write(path, payload + b"\n", mode=0o600)


def accept_path(path: str | pathlib.Path, state_path: str | pathlib.Path | None = None,
                previous: KeyringDoc | None = None, now: dt.datetime | None = None,
                persist: bool = True) -> KeyringDoc:
    """Accept the keyring file against the stored ring (or as genesis, when nothing is stored)."""
    now = _now(now)
    path = pathlib.Path(path)
    body, sigs = read_pair(path)
    doc = parse_doc(body)
    stored = previous
    state = pathlib.Path(state_path) if state_path else None
    if stored is None and state is not None:
        stored = load_state(state)
    if stored is not None and doc.digest == stored.digest:
        verify_bundle(doc.body, sigs, NAMESPACE, doc.digest, version=doc.version)
        doc.quorum_signers = stored.quorum_signers
        return doc
    counted = verify_genesis(doc, sigs, now) if stored is None else verify_succession(stored, doc, sigs, now)
    doc.quorum_signers = tuple(counted)
    if persist and state is not None:
        save_state(state, doc)
    return doc


def load_tip(path: str | pathlib.Path, now: dt.datetime | None = None) -> KeyringDoc:
    """Load a keyring file the operator holds. Genesis is quorum-checked; later tips are crypto-checked.

    Historical quorum of a tip older generations already accepted is enforced by `accept_path`
    (the gateway), which remembers the predecessor. This function is what the CLI uses to read
    the file it is about to mutate.
    """
    body, sigs = read_pair(pathlib.Path(path))
    doc = parse_doc(body)
    if doc.version == 1 and doc.prev == "":
        doc.quorum_signers = tuple(verify_genesis(doc, sigs, now))
        return doc
    verify_bundle(doc.body, sigs, NAMESPACE, doc.digest, version=doc.version)
    return doc


def single_sig_bundle(policy_bytes: bytes, armored: str, identity: str, revision: str) -> str:
    """Wrap one legacy SSHSIG so it goes through the same threshold check as a bundle."""
    digest = sha256_prefixed(policy_bytes)
    try:
        _blob, fp = policysig.verify_crypto(policy_bytes, armored, policysig.NAMESPACE)
    except policysig.SignatureError as exc:
        raise KeyringError(f"Signatur ungültig ({identity or 'ohne Identität'}): {exc}") from exc
    return dump_bundle({"digest": digest, "revision": str(revision)},
                       [{"armored": armored, "fingerprint": fp, "identity": identity or ""}])


def describe(doc: KeyringDoc, now: dt.datetime | None = None) -> list[str]:
    now = _now(now)
    lines = [
        f"version: {doc.version}",
        f"digest: {doc.digest}",
        f"prev: {doc.prev or '-'}",
        f"keyring_threshold: {doc.keyring_threshold}",
        f"policy_threshold: {doc.policy_threshold}",
        f"quorum_signers: {', '.join(doc.quorum_signers) or '-'}",
        "signers:",
    ]
    for key in doc.keys:
        lines.append(
            f"  - {key.id}  {policysig.fingerprint(key.blob)}  roles={','.join(sorted(key.roles))}  "
            f"{key.status_at(now)}  not_before={format_time(key.not_before)}  not_after={format_time(key.not_after)}")
    return lines
