#!/usr/bin/env python3
"""AISM capture mock upstream (stdlib only).

Stands in for the *upstreams of the orchestrator (S3)* during conformance runs:
  - S6 inference   POST /v1/chat/completions (stream and non-stream), GET /v1/models
  - S4 embeddings  POST /v1/embeddings
  - tool gateway   POST /webhook/<path>   (n8n stand-in)
  - S5 web search  GET  /search?q=...&format=json   (SearXNG stand-in; one result contains a synthetic e-mail)
Every request is recorded and can be read back by the test suite:
  GET  /_captured   -> JSON list of {ts, method, path, headers, body}
  POST /_reset      -> clear the capture buffer

Scenarios are triggered by markers in the last user message:
  AISM-TEST:DISALLOWED_TOOL  -> first answer is a tool call to `delete_ticket` (not allowlisted)
  AISM-TEST:INVALID_ARGS     -> first answer calls `ticket_status_lookup` with schema-invalid arguments
  AISM-TEST:ALLOWED_TOOL     -> first answer calls `ticket_status_lookup` with valid arguments (positive control)
  AISM-TEST:WEB_SEARCH       -> first answer calls the built-in tool `web_search`; the query deliberately
                                contains a plaintext e-mail and a placeholder (S3 must mask/strip both)
  AISM-TEST:WRITE_TOOL       -> first answer calls `ticket_add_comment` (write tool, needs confirmation)
  AISM-TEST:ECHO             -> answers with the received (masked) user text; when streaming, in
                                3-character chunks so that placeholders are split across chunks
Once a role=tool message is present, the mock answers normally.

Usage:
  python3 mock_upstream.py --port 18080
      single port: API and /_captured, /_reset on the same port
  python3 mock_upstream.py --host 127.0.0.1 --port 18081 --capture-host 0.0.0.0 --capture-port 18080
      split mode: the API (S6/S4/webhook stand-in) only on --port, /_captured and /_reset only on
      --capture-port. Use this when the API must stay unreachable from the client network (K1-05).
This mock is a test double. It has no authentication and must never be used in production.
"""
from __future__ import annotations

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODEL_ID = "aism-mock-model"
EMBED_DIM = 8
_lock = threading.Lock()
_captured: list[dict] = []
KEEP_HEADERS = {"traceparent", "tracestate", "x-aism-request-id", "x-aism-route", "content-type", "authorization-present"}


def _record(handler, body):
    hdrs = {k.lower(): v for k, v in handler.headers.items() if k.lower() in KEEP_HEADERS}
    if handler.headers.get("Authorization"):
        hdrs["authorization-present"] = "true"
    with _lock:
        _captured.append({"ts": time.time(), "method": handler.command, "path": handler.path, "headers": hdrs, "body": body})


def _last_user(messages):
    for m in reversed(messages or []):
        if m.get("role") == "user" and isinstance(m.get("content"), str):
            return m["content"]
    return ""


def _decide(body):
    msgs = body.get("messages") or []
    has_tool_result = any(m.get("role") == "tool" for m in msgs)
    text = _last_user(msgs)
    if not has_tool_result and "AISM-TEST:DISALLOWED_TOOL" in text:
        return {"tool": ("delete_ticket", {"ticket_id": "INC-2026-0042"})}
    if not has_tool_result and "AISM-TEST:ALLOWED_TOOL" in text:
        return {"tool": ("ticket_status_lookup", {"ticket_id": "INC-2026-0042"})}
    if not has_tool_result and "AISM-TEST:INVALID_ARGS" in text:
        return {"tool": ("ticket_status_lookup", {"ticket_id": "1; DROP TABLE tickets"})}
    if not has_tool_result and "AISM-TEST:WEB_SEARCH" in text:
        return {"tool": ("web_search", {"query": "Status INC-2026-0042 <PERSON_1> erika.mustermann@example.com"})}
    if not has_tool_result and "AISM-TEST:WRITE_TOOL" in text:
        return {"tool": ("ticket_add_comment", {"ticket_id": "INC-2026-0042", "comment": "Rueckruf erfolgt"})}
    if "AISM-TEST:ECHO" in text:
        return {"text": text, "chunk": 3}
    return {"text": "AISM mock answer."}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    serve_api = True       # S6/S4/webhook stand-in
    serve_capture = True   # /_captured, /_reset

    def log_message(self, fmt, *args):  # quiet
        pass

    def _json(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            return json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return {"_raw": raw.decode(errors="replace")}

    def _not_found(self):
        return self._json(404, {"error": {"message": "not found", "type": "invalid_request_error", "code": "not_found"}})

    def do_GET(self):
        if self.path == "/_captured":
            if not self.serve_capture:
                return self._not_found()
            with _lock:
                return self._json(200, list(_captured))
        if not self.serve_api:
            return self._not_found()
        _record(self, None)
        if self.path in ("/health", "/v1/health"):
            return self._json(200, {"status": "ok"})
        if self.path == "/v1/models":
            return self._json(200, {"object": "list", "data": [{"id": MODEL_ID, "object": "model", "owned_by": "aism-mock"}]})
        if self.path.startswith("/search?"):
            from urllib.parse import parse_qs, urlsplit  # noqa: PLC0415
            q = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
            return self._json(200, {"query": q, "results": [
                {"title": "INC-2026-0042 – Statusseite", "url": "https://status.example.org/INC-2026-0042",
                 "content": "Ansprechpartner: max.mustermann@example.org"},
                {"title": "Wartungsfenster", "url": "https://status.example.org/maintenance", "content": "Kein Eintrag."}]})
        return self._json(404, {"error": {"message": "not found", "type": "invalid_request_error", "code": "not_found"}})

    def do_POST(self):
        if self.path == "/_reset":
            if not self.serve_capture:
                return self._not_found()
            with _lock:
                _captured.clear()
            return self._json(200, {"ok": True})
        if not self.serve_api:
            return self._not_found()
        body = self._body()
        _record(self, body)
        if self.path == "/v1/embeddings":
            inputs = body.get("input")
            inputs = [inputs] if isinstance(inputs, str) else (inputs or [])
            data = [{"object": "embedding", "index": i, "embedding": [0.0] * EMBED_DIM} for i in range(len(inputs))]
            return self._json(200, {"object": "list", "data": data, "model": body.get("model", "mock-embed")})
        if self.path.startswith("/webhook/"):
            return self._json(200, {"ok": True, "mock": True})
        if self.path == "/v1/chat/completions":
            if not isinstance(body.get("messages"), list):
                return self._json(400, {"error": {"message": "messages required", "type": "invalid_request_error", "code": "invalid_request"}})
            return self._chat(body)
        return self._json(404, {"error": {"message": "not found", "type": "invalid_request_error", "code": "not_found"}})

    def _chat(self, body):
        d = _decide(body)
        cid = f"chatcmpl-mock{int(time.time()*1000)}"
        model = body.get("model", MODEL_ID)
        if "tool" in d:
            name, args = d["tool"]
            tc = {"id": "call_mock01", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}
        if not body.get("stream"):
            if "tool" in d:
                msg, fr = {"role": "assistant", "content": None, "tool_calls": [tc]}, "tool_calls"
            else:
                msg, fr = {"role": "assistant", "content": d["text"]}, "stop"
            return self._json(200, {"id": cid, "object": "chat.completion", "created": int(time.time()), "model": model,
                                    "choices": [{"index": 0, "message": msg, "finish_reason": fr}],
                                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        def emit(delta, fr=None):
            chunk = {"id": cid, "object": "chat.completion.chunk", "created": int(time.time()), "model": model,
                     "choices": [{"index": 0, "delta": delta, "finish_reason": fr}]}
            self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
            self.wfile.flush()

        if "tool" in d:
            emit({"role": "assistant", "content": None, "tool_calls": [{"index": 0, **{k: tc[k] for k in ("id", "type")}, "function": {"name": tc["function"]["name"], "arguments": ""}}]})
            emit({"tool_calls": [{"index": 0, "function": {"arguments": tc["function"]["arguments"]}}]})
            emit({}, "tool_calls")
        else:
            emit({"role": "assistant", "content": ""})
            if d.get("chunk"):
                n = d["chunk"]
                for i in range(0, len(d["text"]), n):
                    emit({"content": d["text"][i:i + n]})
            else:
                for part in d["text"].split(" "):
                    emit({"content": part + " "})
            emit({}, "stop")
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()
        self.close_connection = True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=18080)
    ap.add_argument("--capture-host", default="0.0.0.0")
    ap.add_argument("--capture-port", type=int, default=None)
    ap.add_argument("--tls-cert", default=None, help="serve the API via HTTPS (e.g. as mock cloud provider, K3-04)")
    ap.add_argument("--tls-key", default=None)
    a = ap.parse_args()

    def tls(srv):
        if a.tls_cert:
            import ssl  # noqa: PLC0415
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(a.tls_cert, a.tls_key)
            srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        return srv

    if a.capture_port is None:
        srv = tls(ThreadingHTTPServer((a.host, a.port), Handler))
        print(f"AISM capture mock listening on {a.host}:{a.port}", flush=True)
        srv.serve_forever()
        return
    api_h = type("ApiHandler", (Handler,), {"serve_capture": False})
    cap_h = type("CaptureHandler", (Handler,), {"serve_api": False})
    cap = ThreadingHTTPServer((a.capture_host, a.capture_port), cap_h)
    threading.Thread(target=cap.serve_forever, daemon=True).start()
    srv = tls(ThreadingHTTPServer((a.host, a.port), api_h))
    print(f"AISM capture mock: API on {a.host}:{a.port}, capture on {a.capture_host}:{a.capture_port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
