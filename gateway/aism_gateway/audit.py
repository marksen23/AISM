"""Append-only JSONL audit log with hash chain (AUD, S-02).

Chain format (AISM-defined): every line carries
  prev_hash = "sha256:" + hex(SHA-256(previous raw line, UTF-8, without newline)).
The first line carries prev_hash = "sha256:" + 64 zeros.
Entries must never contain plaintext PII (M-05): only IDs, entity counts, hashes.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import pathlib
import threading

GENESIS = "sha256:" + "0" * 64


class AuditLog:
    def __init__(self, path: str):
        self.path = pathlib.Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._prev = self._last_hash()

    def _last_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS
        with self.path.open("rb") as f:
            f.seek(0, os.SEEK_END)
            size, block, data = f.tell(), 4096, b""
            while size > 0 and data.count(b"\n") < 2:
                step = min(block, size)
                size -= step
                f.seek(size)
                data = f.read(step) + data
        last = [l for l in data.splitlines() if l.strip()][-1]
        return "sha256:" + hashlib.sha256(last).hexdigest()

    def write(self, event: str, policy_info: dict | None, **fields) -> None:
        entry = {
            "ts": dt.datetime.now().astimezone().isoformat(timespec="milliseconds"),
            "event": event,
            "policy": policy_info,
            **{k: v for k, v in fields.items() if v is not None},
        }
        with self._lock:
            entry["prev_hash"] = self._prev
            line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._prev = "sha256:" + hashlib.sha256(line.encode("utf-8")).hexdigest()


def sha256_json(obj) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def verify_chain(path: str) -> list[int]:
    """Returns 1-based line numbers where the chain is broken (empty list = intact)."""
    bad, prev = [], GENESIS
    for i, line in enumerate(pathlib.Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        if json.loads(line).get("prev_hash") != prev:
            bad.append(i)
        prev = "sha256:" + hashlib.sha256(line.encode("utf-8")).hexdigest()
    return bad
