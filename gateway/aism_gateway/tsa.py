"""Optional RFC 3161 Time-Stamp Protocol client (offline-safe).

Builds a TimeStampReq (SHA-256 imprint) and checks that a TimeStampResp grants the
request and carries that imprint as an OCTET STRING. This does not validate a TSA
certificate chain: pinning a trust anchor and verifying CMS SignedData is a documented
limitation. A missing or unreachable TSA never blocks the audit path; the caller records
the failure next to the checkpoint.
"""
from __future__ import annotations

import os
import secrets
import urllib.error
import urllib.request

SHA256_OID = (2, 16, 840, 1, 101, 3, 4, 2, 1)


class TsaError(Exception):
    pass


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _len(len(content)) + content


def _seq(*parts: bytes) -> bytes:
    return _tlv(0x30, b"".join(parts))


def _integer(n: int) -> bytes:
    if n < 0:
        raise TsaError("negative INTEGER is not used")
    if n == 0:
        body = b"\x00"
    else:
        body = n.to_bytes((n.bit_length() + 7) // 8, "big")
        if body[0] & 0x80:
            body = b"\x00" + body
    return _tlv(0x02, body)


def _oid(parts: tuple[int, ...]) -> bytes:
    body = bytes([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append(0x80 | (part & 0x7F))
            part >>= 7
        body += bytes(reversed(chunk))
    return _tlv(0x06, body)


def _octet(data: bytes) -> bytes:
    return _tlv(0x04, data)


def timestamp_request(digest: bytes, nonce: int | None = None) -> bytes:
    if len(digest) != 32:
        raise TsaError("SHA-256 imprint must be 32 bytes")
    if nonce is None:
        nonce = int.from_bytes(secrets.token_bytes(8), "big")
    alg = _seq(_oid(SHA256_OID), _tlv(0x05, b""))
    imprint = _seq(alg, _octet(digest))
    # version, messageImprint, nonce, certReq = TRUE
    return _seq(_integer(1), imprint, _integer(nonce), _tlv(0x01, b"\xff"))


def _walk(data: bytes):
    i, n = 0, len(data)
    while i < n:
        if i >= n:
            break
        tag = data[i]
        i += 1
        if i >= n:
            raise TsaError("truncated DER")
        ln = data[i]
        i += 1
        if ln & 0x80:
            nbytes = ln & 0x7F
            if nbytes == 0 or i + nbytes > n:
                raise TsaError("truncated DER length")
            ln = int.from_bytes(data[i:i + nbytes], "big")
            i += nbytes
        if i + ln > n:
            raise TsaError("truncated DER value")
        content = data[i:i + ln]
        yield tag, content
        i += ln


def response_ok(token: bytes, digest: bytes) -> tuple[bool, str]:
    """Granted status (0 or 1) and the imprint present as an OCTET STRING."""
    try:
        top = list(_walk(token))
    except TsaError as exc:
        return False, str(exc)
    if not top or top[0][0] != 0x30:
        return False, "not a SEQUENCE"
    inner = list(_walk(top[0][1]))
    status = None
    for tag, content in inner:
        if tag == 0x30:
            for itag, icontent in _walk(content):
                if itag == 0x02 and icontent:
                    status = icontent[-1]
                    break
            break
    if status not in (0, 1):
        return False, f"PKIStatus {status}"
    found = False

    def scan(buf: bytes) -> None:
        nonlocal found
        for tag, content in _walk(buf):
            if tag == 0x04 and content == digest:
                found = True
            elif tag == 0x30:
                scan(content)

    try:
        scan(top[0][1])
    except TsaError as exc:
        return False, str(exc)
    if not found:
        return False, "imprint missing"
    return True, "granted"


def request_timestamp(url: str, digest: bytes, timeout: float = 3.0) -> bytes:
    body = timestamp_request(digest)
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/timestamp-query", "Accept": "application/timestamp-reply"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            token = resp.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise TsaError(str(exc)) from exc
    ok, detail = response_ok(token, digest)
    if not ok:
        raise TsaError(detail)
    return token


def witness_enabled(url: str | None) -> bool:
    return bool(url) and os.environ.get("AISM_AUDIT_WITNESS", "1") != "0"
