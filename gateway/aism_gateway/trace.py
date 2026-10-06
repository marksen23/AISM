"""W3C Trace Context (traceparent) handling (S-10)."""
from __future__ import annotations

import re
import secrets

TP_RE = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")


def continue_or_start(header: str | None) -> tuple[str, str]:
    """Returns (trace_id, outgoing traceparent) with a fresh span id."""
    m = TP_RE.match((header or "").strip().lower())
    if m and m.group(1) != "0" * 32 and m.group(2) != "0" * 16:
        trace_id, flags = m.group(1), m.group(3)
    else:
        trace_id, flags = secrets.token_hex(16), "01"
    return trace_id, f"00-{trace_id}-{secrets.token_hex(8)}-{flags}"
