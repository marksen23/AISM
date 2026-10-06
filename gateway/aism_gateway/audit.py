"""Append-only JSONL audit log with a hash chain (AUD, S-02).

Chain format (AISM-defined): every line carries
  prev_hash = "sha256:" + hex(SHA-256(previous raw line, UTF-8, without newline))
  seq       = 1-based index of the line.
The first line carries prev_hash = "sha256:" + 64 zeros.
Entries must never contain plaintext PII (M-05): only IDs, entity counts, hashes.

Beyond the local file the gateway can mirror each line, periodic Ed25519 checkpoints
and the keyring rollback anchor into a required S3 Object Lock sink. The local line is
fsync'd and a copy is fsync'd into a bounded queue before write() returns. Required
copies are removed from the queue only after the sink accepts them. When the queue is
full, write() raises AuditUnavailable before appending. A faulted or misconfigured
required sink still stores the line, then raises; ready() rejects requests.
Entries are never dropped.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import logging
import os
import pathlib
import socket
import threading
import time
from dataclasses import dataclass, field

from . import policysig
from .s3client import S3Client, S3Error
from .tsa import TsaError, request_timestamp

log = logging.getLogger("aism.audit")

GENESIS = "sha256:" + "0" * 64
AUDIT_NAMESPACE = "aism-audit"
MERKLE_ALG = "rfc6962-sha256-v1"


class AuditUnavailable(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def sha256_json(obj) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def line_hash(line: str) -> str:
    return "sha256:" + hashlib.sha256(line.encode("utf-8")).hexdigest()


def canonical_json(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def merkle_root(leaves: list[bytes]) -> str:
    """RFC 6962 binary Merkle tree over the raw audit lines. Empty tree hashes b''."""
    if not leaves:
        return "sha256:" + hashlib.sha256(b"").hexdigest()
    level = [hashlib.sha256(b"\x00" + leaf).digest() for leaf in leaves]
    while len(level) > 1:
        nxt = []
        i = 0
        while i < len(level):
            if i + 1 == len(level):
                nxt.append(level[i])
                break
            nxt.append(hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest())
            i += 2
        level = nxt
    return "sha256:" + level[0].hex()


def verify_chain(path: str) -> list[int]:
    """Returns 1-based line numbers where the chain is broken (empty list = intact)."""
    bad, prev = [], GENESIS
    for i, line in enumerate(pathlib.Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        if json.loads(line).get("prev_hash") != prev:
            bad.append(i)
        prev = line_hash(line)
    return bad


def _atomic_write(path: pathlib.Path, data: bytes, mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    os.chmod(path, mode)


def send_syslog(endpoint: str, line: str) -> None:
    """RFC 5424. TCP uses RFC 6587 octet-counting. UDP is one datagram."""
    if "://" not in endpoint:
        raise ValueError("syslog endpoint must be tcp:// or udp://")
    scheme, rest = endpoint.split("://", 1)
    host, _, port_s = rest.rpartition(":")
    port = int(port_s)
    pri = 13 * 8 + 6
    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    msg = f"<{pri}>1 {ts} aism-gateway aism-audit - audit - {line}".encode("utf-8")
    if scheme == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(msg, (host, port))
        finally:
            sock.close()
        return
    if scheme == "tcp":
        framed = str(len(msg)).encode("ascii") + b" " + msg
        with socket.create_connection((host, port), timeout=2) as sock:
            sock.sendall(framed)
        return
    raise ValueError(f"syslog scheme {scheme!r}")


@dataclass
class WormTarget:
    id: str
    required: bool
    client: S3Client
    bucket: str
    prefix: str
    lock_mode: str
    retention_days: int
    bucket_ready: bool = False

    def full(self, key: str) -> str:
        return f"{self.prefix}{key}"

    def ensure(self) -> None:
        if self.bucket_ready:
            return
        self.client.ensure_object_lock_bucket(self.bucket, self.lock_mode, self.retention_days)
        self.bucket_ready = True

    def put(self, key: str, body: bytes) -> str | None:
        self.ensure()
        full = self.full(key)
        try:
            existing, vid = self.client.get_bytes(self.bucket, full)
        except S3Error as exc:
            if exc.status != 404 and exc.code not in ("NoSuchKey", "NotFound"):
                raise
            existing, vid = None, None
        if existing is not None:
            if existing != body:
                raise S3Error(409, "ImmutableConflict", f"{full} already stores different bytes")
            return vid
        until = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=self.retention_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        return self.client.put_bytes(self.bucket, full, body, lock_mode=self.lock_mode, retain_until=until)

    def fault_object_present(self) -> bool:
        key = self.full("fault/block")
        try:
            if self.client.head(self.bucket, key):
                return True
        except S3Error:
            pass
        try:
            self.client.get_bytes(self.bucket, key)
        except S3Error as exc:
            if exc.status == 404 or exc.code in ("NoSuchKey", "NotFound"):
                return False
            raise
        return True


@dataclass
class AuditConfig:
    fail_closed: bool = False
    max_queued: int = 1024
    worms: list[WormTarget] = field(default_factory=list)
    syslog: list[tuple[str, bool]] = field(default_factory=list)  # (endpoint, required)
    every_entries: int | None = None
    every_seconds: float | None = None
    signer_id: str | None = None
    signing_key: object | None = None
    witness_url: str | None = None
    witness_timeout: float = 3.0
    signer_error: str | None = None
    misconfigured: str | None = None


def _prefix(value: str | None) -> str:
    prefix = (value or "").strip()
    if prefix.startswith("/") or ".." in prefix.replace("\\", "/").split("/"):
        raise ValueError(f"audit prefix {value!r}")
    if prefix and not prefix.endswith("/"):
        prefix += "/"
    return prefix


def config_from_policy(spec: dict, *, signing_key_path: str | None, keyring_doc, resolve_secret) -> AuditConfig:
    """Build runtime audit settings from spec.audit. Secrets are resolved, never stored in the policy."""
    audit = spec.get("audit") or {}
    cfg = AuditConfig(
        fail_closed=bool(audit.get("failClosed")),
        max_queued=int((audit.get("queue") or {}).get("maxEntries") or 1024),
    )
    for sink in audit.get("sinks") or []:
        required = bool(sink.get("required", True))
        if sink.get("type") == "s3-object-lock":
            access = resolve_secret(sink.get("accessKeyRef"))
            secret = resolve_secret(sink.get("secretKeyRef"))
            if not access or not secret:
                msg = f"sink {sink.get('id')}: credentials unresolved"
                if required:
                    cfg.misconfigured = msg
                log.warning(msg)
                continue
            try:
                prefix = _prefix(sink.get("prefix"))
                client = S3Client(str(sink["endpoint"]), access, secret, str(sink.get("region") or "us-east-1"))
            except (S3Error, KeyError, ValueError) as exc:
                if required:
                    cfg.misconfigured = str(exc)
                log.warning("sink %s: %s", sink.get("id"), exc)
                continue
            cfg.worms.append(WormTarget(
                id=str(sink.get("id") or "worm"), required=required, client=client, bucket=str(sink["bucket"]),
                prefix=prefix, lock_mode=str(sink.get("lockMode") or "COMPLIANCE").upper(),
                retention_days=int(sink.get("retentionDays") or 3650),
            ))
        elif sink.get("type") == "syslog":
            cfg.syslog.append((str(sink.get("endpoint") or ""), required))
    cp = (audit.get("integrity") or {}).get("checkpoint")
    if isinstance(cp, dict):
        cfg.every_entries = int(cp["everyEntries"])
        cfg.every_seconds = float(cp["everySeconds"])
        cfg.signer_id = str(cp["signer"])
        cfg.signer_error = _load_signer(cfg, signing_key_path, keyring_doc)
    witness = (audit.get("integrity") or {}).get("witness")
    if isinstance(witness, dict) and witness.get("type") == "rfc3161":
        cfg.witness_url = str(witness.get("url") or "") or None
        cfg.witness_timeout = float(witness.get("timeoutSeconds") or 3)
    if cfg.fail_closed and not any(w.required for w in cfg.worms) and not cfg.misconfigured:
        cfg.misconfigured = "failClosed requires a required s3-object-lock sink"
    return cfg


def public_blob(key) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    openssh = key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
    return policysig.openssh_ed25519_blob(openssh)


def _load_signer(cfg: AuditConfig, path: str | None, keyring_doc) -> str | None:
    if not path:
        return "AUDIT_SIGNING_KEY is not set"
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import load_ssh_private_key
        key = load_ssh_private_key(pathlib.Path(path).read_bytes(), None)
    except (OSError, ValueError, TypeError) as exc:
        return f"audit signing key unreadable: {exc}"
    if not isinstance(key, Ed25519PrivateKey):
        return "audit signing key must be Ed25519"
    try:
        blob = public_blob(key)
    except policysig.SignatureError as exc:
        return str(exc)
    if keyring_doc is None:
        return "checkpoint signer requires a keyring with an audit role"
    member = keyring_doc.key_by_id(cfg.signer_id or "")
    if member is None or "audit" not in member.roles:
        return f"{cfg.signer_id} is not an audit signer in the keyring"
    if member.blob != blob:
        return f"{cfg.signer_id} public key does not match AUDIT_SIGNING_KEY"
    cfg.signing_key = key
    return None


class AuditLog:
    def __init__(self, path: str):
        self.path = pathlib.Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.checkpoints = self.path.parent / "checkpoints"
        self.queue_path = self.path.parent / "audit-queue.json"
        self._lock = threading.Lock()
        self._lines: list[str] = []
        self._prev = GENESIS
        self._load_lines()
        self._cfg: AuditConfig | None = None
        self._pending: list[dict] = []
        self._versions: dict[str, str] = {}
        self._keyring_acked: set[str] = set()
        self._faulted = False
        self._disk_error = False
        self._checkpoint_seq = 0
        self._checkpoint_entries = 0
        self._last_checkpoint_hash = GENESIS
        self._last_checkpoint_at = time.monotonic()
        self._last_checkpoint: dict | None = None
        self._syslog_failures = 0
        self._sink_errors: dict[str, str] = {}
        self._thread: threading.Thread | None = None
        self._stop = False
        self._load_queue()

    def _load_lines(self) -> None:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return
        text = self.path.read_text(encoding="utf-8")
        self._lines = [ln for ln in text.splitlines() if ln.strip()]
        if self._lines:
            self._prev = line_hash(self._lines[-1])

    def _load_queue(self) -> None:
        if not self.queue_path.is_file():
            return
        try:
            raw = json.loads(self.queue_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log.error("audit queue unreadable: %s", exc)
            self._disk_error = True
            return
        self._versions = {str(k): str(v) for k, v in (raw.get("versions") or {}).items()}
        self._keyring_acked = set(raw.get("keyring_acked") or [])
        self._pending = list(raw.get("pending") or [])
        self._checkpoint_seq = int(raw.get("checkpoint_seq") or 0)
        self._checkpoint_entries = int(raw.get("checkpoint_entries") or 0)
        self._last_checkpoint_hash = str(raw.get("last_checkpoint_hash") or GENESIS)
        done = self.checkpoints
        if done.is_dir():
            files = sorted(done.glob("*.json"))
            if files:
                try:
                    env = json.loads(files[-1].read_text(encoding="utf-8"))
                    self._last_checkpoint = env.get("checkpoint")
                except (OSError, json.JSONDecodeError):
                    pass

    def _save_queue(self) -> None:
        payload = {
            "checkpoint_entries": self._checkpoint_entries,
            "checkpoint_seq": self._checkpoint_seq,
            "keyring_acked": sorted(self._keyring_acked),
            "last_checkpoint_hash": self._last_checkpoint_hash,
            "pending": self._pending,
            "versions": self._versions,
        }
        _atomic_write(self.queue_path, canonical_json(payload) + b"\n")

    def configure(self, cfg: AuditConfig, *, background: bool = True) -> None:
        with self._lock:
            self._cfg = cfg
            self._requeue_locked()
        if background and self._thread is None:
            self._thread = threading.Thread(target=self._loop, name="aism-audit-flush", daemon=True)
            self._thread.start()

    def _requeue_locked(self) -> None:
        cfg = self._cfg
        if cfg is None or not any(w.required for w in cfg.worms):
            return
        pending = {item["key"] for item in self._pending}
        for seq, line in enumerate(self._lines, 1):
            key = f"entries/{seq:020d}"
            if key in self._versions or key in pending:
                continue
            self._pending.append({"kind": "entry", "key": key, "body": line, "seq": seq,
                                  "digest": line_hash(line)})
        self._save_queue()

    def _required(self) -> bool:
        cfg = self._cfg
        return bool(cfg and any(w.required for w in cfg.worms))

    def _accepting_locked(self) -> bool:
        cfg = self._cfg
        if self._disk_error:
            return False
        if cfg is None or not cfg.fail_closed:
            return not self._disk_error
        if cfg.signer_error or cfg.misconfigured or self._faulted:
            return False
        if self._required() and len(self._pending) >= cfg.max_queued:
            return False
        return True

    def accepting(self) -> bool:
        with self._lock:
            return self._accepting_locked()

    def status(self) -> dict:
        with self._lock:
            cfg = self._cfg
            return {
                "fail_closed": bool(cfg and cfg.fail_closed),
                "accepting": self._accepting_locked(),
                "entries": len(self._lines),
                "head": self._prev,
                "seq": len(self._lines),
                "queue": {"depth": len(self._pending), "max": cfg.max_queued if cfg else None},
                "faulted": self._faulted,
                "signer_error": (cfg.signer_error if cfg else None),
                "misconfigured": (cfg.misconfigured if cfg else None),
                "checkpoint": self._last_checkpoint,
                "checkpoint_seq": self._checkpoint_seq,
                "syslog_failures": self._syslog_failures,
                "sink_errors": dict(self._sink_errors),
                "keyring_state_acked": sorted(self._keyring_acked),
                "worm_objects": len(self._versions),
            }

    def write(self, event: str, policy_info: dict | None, **fields) -> None:
        entry = {
            "ts": dt.datetime.now().astimezone().isoformat(timespec="milliseconds"),
            "event": event,
            "policy": policy_info,
            **{k: v for k, v in fields.items() if v is not None},
        }
        with self._lock:
            if self._disk_error:
                raise AuditUnavailable("audit log not writable")
            # A full queue cannot take another copy. Refuse before appending so the
            # line is not written and then dropped. Every other fail-closed reason
            # still persists the line (below) and then refuses the caller.
            if self._required() and self._cfg and len(self._pending) >= self._cfg.max_queued:
                raise AuditUnavailable("audit queue full")
            entry["seq"] = len(self._lines) + 1
            entry["prev_hash"] = self._prev
            line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            try:
                self._append_line(line)
                if self._required():
                    self._pending.append({
                        "kind": "entry", "key": f"entries/{entry['seq']:020d}", "body": line,
                        "seq": entry["seq"], "digest": line_hash(line),
                    })
                    self._save_queue()
                self._maybe_checkpoint_locked(force_count=True)
                self._syslog_line(line)
            except AuditUnavailable:
                raise
            except OSError as exc:
                self._disk_error = True
                raise AuditUnavailable(f"audit log not writable: {exc}") from exc
            # Queue-full was refused before the append. A line that just filled the
            # queue is stored. Misconfiguration, a missing audit key or a fault marker
            # still refuse the caller after the line is durable.
            if self._cfg and self._cfg.fail_closed and (self._cfg.misconfigured or self._cfg.signer_error or self._faulted):
                raise AuditUnavailable(self._block_reason())

    def _syslog_line(self, line: str) -> None:
        cfg = self._cfg
        if cfg is None:
            return
        for endpoint, required in cfg.syslog:
            try:
                send_syslog(endpoint, line)
            except (OSError, ValueError) as exc:
                self._syslog_failures += 1
                self._sink_errors["syslog"] = str(exc)[:300]
                if required:
                    raise AuditUnavailable(f"syslog sink failed: {exc}") from exc

    def _block_reason(self) -> str:
        cfg = self._cfg
        if cfg and cfg.misconfigured:
            return cfg.misconfigured
        if cfg and cfg.signer_error:
            return cfg.signer_error
        if self._faulted:
            return "immutable audit sink unavailable"
        if cfg and len(self._pending) >= cfg.max_queued:
            return "audit queue full"
        return "audit unavailable"

    def _append_line(self, line: str) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        self._lines.append(line)
        self._prev = line_hash(line)

    def note_keyring_state(self, body: bytes) -> None:
        digest = "sha256:" + hashlib.sha256(body).hexdigest()
        key = "keyring-state/" + digest.split(":", 1)[1]
        with self._lock:
            if not self._required():
                return
            if digest in self._keyring_acked or any(item["key"] == key for item in self._pending):
                return
            self._pending.append({
                "kind": "keyring-state", "key": key, "body": body.decode("utf-8"),
                "seq": None, "digest": digest,
            })
            self._save_queue()

    def _maybe_checkpoint_locked(self, force_count: bool) -> None:
        cfg = self._cfg
        if cfg is None or cfg.every_entries is None or cfg.signing_key is None:
            return
        n = len(self._lines)
        if n == 0 or n == self._checkpoint_entries:
            return
        due_count = force_count and cfg.every_entries and n % cfg.every_entries == 0
        due_time = cfg.every_seconds is not None and (time.monotonic() - self._last_checkpoint_at) >= cfg.every_seconds
        if not due_count and not due_time:
            return
        self._sign_checkpoint_locked()

    def _sign_checkpoint_locked(self) -> None:
        cfg = self._cfg
        if cfg is None or cfg.signing_key is None or not self._lines:
            return
        self._checkpoint_seq += 1
        body = {
            "alg": "sha256",
            "entries": len(self._lines),
            "head": self._prev,
            "merkle": MERKLE_ALG,
            "merkle_root": merkle_root([ln.encode("utf-8") for ln in self._lines]),
            "prev_checkpoint": self._last_checkpoint_hash,
            "seq": self._checkpoint_seq,
            "signer": cfg.signer_id,
            "ts": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "v": 1,
        }
        raw = canonical_json(body)
        signature = policysig.sign(raw, cfg.signing_key, namespace=AUDIT_NAMESPACE)
        envelope = {"checkpoint": body, "signature": signature, "witness": None}
        text = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        path = self.checkpoints / f"{self._checkpoint_seq:016d}.json"
        _atomic_write(path, text.encode("utf-8") + b"\n")
        self._last_checkpoint = body
        self._last_checkpoint_hash = "sha256:" + hashlib.sha256(raw).hexdigest()
        self._checkpoint_entries = len(self._lines)
        self._last_checkpoint_at = time.monotonic()
        if self._required():
            self._pending.append({
                "kind": "checkpoint", "key": f"checkpoints/{self._checkpoint_seq:020d}",
                "body": text, "seq": self._checkpoint_seq,
                "digest": self._last_checkpoint_hash,
            })
            self._save_queue()

    def checkpoint_now(self) -> dict | None:
        """Sign a checkpoint immediately (tests and shutdown)."""
        with self._lock:
            if not self._lines:
                return None
            if self._checkpoint_entries == len(self._lines) and self._last_checkpoint:
                return self._last_checkpoint
            self._sign_checkpoint_locked()
            return self._last_checkpoint

    def _loop(self) -> None:
        while not self._stop:
            time.sleep(0.4)
            try:
                with self._lock:
                    self._maybe_checkpoint_locked(force_count=False)
                self.flush()
            except Exception:  # noqa: BLE001 — background thread must not die
                log.exception("audit flush failed")

    def flush(self) -> None:
        with self._lock:
            cfg = self._cfg
            pending = list(self._pending)
            worms = list(cfg.worms) if cfg else []
        self._probe_fault(worms)
        if not pending or not worms:
            return
        still: list[dict] = []
        acked_versions: dict[str, str] = {}
        acked_keys: set[str] = set()
        for item in pending:
            body = item["body"].encode("utf-8")
            if item["kind"] == "checkpoint":
                body = self._maybe_witness(item, body)
            ok = True
            version = ""
            for worm in worms:
                try:
                    vid = worm.put(item["key"], body)
                    version = vid or version
                    self._sink_errors.pop(worm.id, None)
                except (S3Error, OSError) as exc:
                    self._sink_errors[worm.id] = str(exc)[:300]
                    if worm.required:
                        ok = False
                        log.warning("audit sink %s: %s", worm.id, exc)
            if ok and any(w.required for w in worms):
                acked_keys.add(item["key"])
                acked_versions[item["key"]] = version
            else:
                still.append(item if item["kind"] != "checkpoint" else {**item, "body": body.decode("utf-8")})
        with self._lock:
            if acked_keys:
                self._pending = [it for it in self._pending if it["key"] not in acked_keys]
                # a witness update may have changed a checkpoint body that is still pending
                by_key = {it["key"]: it for it in still}
                self._pending = [by_key.get(it["key"], it) for it in self._pending]
                for key, vid in acked_versions.items():
                    if key.startswith("keyring-state/"):
                        digest = "sha256:" + key.split("/", 1)[1]
                        self._keyring_acked.add(digest)
                    else:
                        self._versions[key] = vid
                self._save_queue()

    def _maybe_witness(self, item: dict, body: bytes) -> bytes:
        cfg = self._cfg
        if cfg is None or not cfg.witness_url:
            return body
        try:
            envelope = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            return body
        if envelope.get("witness"):
            return body
        raw = canonical_json(envelope["checkpoint"])
        digest = hashlib.sha256(raw).digest()
        try:
            token = request_timestamp(cfg.witness_url, digest, cfg.witness_timeout)
        except TsaError as exc:
            log.warning("rfc3161 witness skipped: %s", exc)
            return body
        envelope["witness"] = {"token_b64": base64.b64encode(token).decode("ascii"),
                               "imprint": "sha256:" + digest.hex()}
        text = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        path = self.checkpoints / f"{int(item['seq']):016d}.json"
        try:
            _atomic_write(path, text.encode("utf-8") + b"\n")
        except OSError as exc:
            log.warning("checkpoint witness not stored locally: %s", exc)
        item["body"] = text
        return text.encode("utf-8")

    def _probe_fault(self, worms: list[WormTarget]) -> None:
        if os.environ.get("AISM_AUDIT_FAULT_INJECTION") != "1":
            return
        required = next((w for w in worms if w.required), None)
        if required is None:
            return
        try:
            faulted = required.fault_object_present()
        except (S3Error, OSError):
            return
        with self._lock:
            self._faulted = faulted

    def close(self) -> None:
        self._stop = True
