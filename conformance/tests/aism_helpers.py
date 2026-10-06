"""Helpers for AISM conformance tests (no pytest dependency)."""
from __future__ import annotations

import json
from typing import Iterable

SSE_FIELD_PREFIXES = ("data:", "event:", "id:", "retry:", ":")


def chat_body(model: str, content: str, stream: bool = False, **extra) -> dict:
    body = {"model": model, "stream": stream, "messages": [{"role": "user", "content": content}]}
    body.update(extra)
    return body


def parse_sse(lines: Iterable[str]) -> tuple[list[dict], bool, list[str]]:
    """Parse an OpenAI-style SSE stream.

    Returns (chunks, saw_done, problems). Each `data:` line must hold either a JSON
    chat.completion.chunk or the literal [DONE]; nothing may follow [DONE].
    """
    chunks: list[dict] = []
    problems: list[str] = []
    saw_done = False
    for raw in lines:
        line = raw.rstrip("\r")
        if not line:
            continue
        if not line.startswith(SSE_FIELD_PREFIXES):
            problems.append(f"Ungültige SSE-Zeile: {line[:80]!r}")
            continue
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if saw_done:
            problems.append("Daten nach [DONE]")
            continue
        if payload == "[DONE]":
            saw_done = True
            continue
        try:
            obj = json.loads(payload)
        except json.JSONDecodeError:
            problems.append(f"data-Zeile ist kein JSON: {payload[:80]!r}")
            continue
        if "error" in obj and "choices" not in obj:
            problems.append(f"Fehlerereignis im Stream: {obj['error']}")
            continue
        if obj.get("object") != "chat.completion.chunk":
            problems.append(f"object != chat.completion.chunk: {obj.get('object')!r}")
        if not isinstance(obj.get("choices"), list):
            problems.append("choices fehlt oder ist keine Liste")
        chunks.append(obj)
    return chunks, saw_done, problems


def find_plaintext(text: str, values: Iterable[str]) -> list[str]:
    return [v for v in values if v in text]


def tool_messages(chat_request: dict) -> list[dict]:
    return [m for m in chat_request.get("messages", []) if m.get("role") == "tool"]


def compose_env(svc: dict) -> dict:
    """Normalize a compose service `environment` (mapping or list) to a str->str dict."""
    env = svc.get("environment") or {}
    if isinstance(env, list):
        env = dict(e.split("=", 1) if "=" in e else (e, "") for e in env)
    return {k: str(v) for k, v in env.items()}
