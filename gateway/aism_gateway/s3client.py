"""Minimal path-style S3 client (SigV4) for the audit WORM sink.

Stdlib only. Covers the calls the gateway and the verifier need: create a bucket with
Object Lock, put/get/head/delete objects, list versions.
No AWS SDK. Credentials are passed in; this module never reads them from disk itself.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

EMPTY_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class S3Error(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(f"s3 {status} {code}: {message}"[:500])
        self.status, self.code, self.message = status, code, message


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac(key: bytes, data: str) -> bytes:
    return hmac.new(key, data.encode("utf-8"), hashlib.sha256).digest()


def signing_key(secret: str, day: str, region: str, service: str = "s3") -> bytes:
    k = _hmac(("AWS4" + secret).encode("utf-8"), day)
    k = _hmac(k, region)
    k = _hmac(k, service)
    return _hmac(k, "aws4_request")


def canonical_request(method: str, uri: str, query: list[tuple[str, str]], headers: dict[str, str],
                      payload_hash: str) -> tuple[str, str]:
    """Returns (canonical_request, signed_headers). Headers are lower-cased names."""
    canon_q = "&".join(
        f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}"
        for k, v in sorted(query)
    )
    items = sorted((k.lower().strip(), " ".join(v.split())) for k, v in headers.items())
    canon_h = "".join(f"{k}:{v}\n" for k, v in items)
    signed = ";".join(k for k, _ in items)
    parts = "/".join(urllib.parse.quote(p, safe="") for p in uri.split("/"))
    if not parts.startswith("/"):
        parts = "/" + parts
    req = "\n".join([method, parts, canon_q, canon_h, signed, payload_hash])
    return req, signed


def authorization(method: str, uri: str, query: list[tuple[str, str]], headers: dict[str, str],
                  payload_hash: str, *, access_key: str, secret_key: str, region: str,
                  amz_date: str, service: str = "s3") -> tuple[str, str]:
    """Returns (Authorization header value, canonical request) for tests."""
    canon, signed = canonical_request(method, uri, query, headers, payload_hash)
    day = amz_date[:8]
    scope = f"{day}/{region}/{service}/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, _sha256(canon.encode("utf-8"))])
    sig = hmac.new(signing_key(secret_key, day, region, service), sts.encode("utf-8"), hashlib.sha256).hexdigest()
    auth = f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={sig}"
    return auth, canon


def _xml_text(data: bytes, name: str) -> str:
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return ""
    for el in root.iter():
        if el.tag == name or el.tag.endswith("}" + name):
            return (el.text or "").strip()
    return ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ARG002
        raise S3Error(code, "Redirect", f"refusing redirect to {newurl}")


class S3Client:
    def __init__(self, endpoint: str, access_key: str, secret_key: str, region: str = "us-east-1",
                 timeout: float = 5.0):
        self.endpoint = endpoint.rstrip("/")
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.timeout = timeout
        parts = urllib.parse.urlsplit(self.endpoint)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise S3Error(0, "Config", f"endpoint {endpoint!r} is not http(s)")
        host = parts.hostname
        if parts.port:
            host = f"{host}:{parts.port}"
        self._host = host
        self._opener = urllib.request.build_opener(_NoRedirect)

    def _request(self, method: str, bucket: str, key: str = "", query: list[tuple[str, str]] | None = None,
                 body: bytes = b"", extra: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
        query = list(query or [])
        uri = "/" + bucket.strip("/")
        if key:
            uri += "/" + key.lstrip("/")
        payload_hash = _sha256(body) if body or method in ("PUT", "POST") else EMPTY_SHA
        if method in ("GET", "HEAD", "DELETE") and not body:
            payload_hash = EMPTY_SHA
        now = dt.datetime.now(dt.timezone.utc)
        amz = now.strftime("%Y%m%dT%H%M%SZ")
        headers = {
            "host": self._host,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz,
        }
        if extra:
            headers.update({k.lower(): v for k, v in extra.items()})
        if body or method == "PUT":
            headers.setdefault("content-type", "application/octet-stream")
        auth, _ = authorization(method, uri, query, headers, payload_hash, access_key=self.access_key,
                                secret_key=self.secret_key, region=self.region, amz_date=amz)
        headers["authorization"] = auth
        q = ("?" + urllib.parse.urlencode(query)) if query else ""
        url = self.endpoint + uri + q
        data = body if method in ("PUT", "POST") else None
        req = urllib.request.Request(url, data=data, method=method)
        for k, v in headers.items():
            if k == "host":
                continue
            req.add_header(k, v)
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                raw = b"" if method == "HEAD" else resp.read()
                return resp.status, {k.lower(): v for k, v in resp.headers.items()}, raw
        except urllib.error.HTTPError as exc:
            raw = exc.read() if exc.fp is not None else b""
            code = _xml_text(raw, "Code") or str(exc.code)
            msg = _xml_text(raw, "Message") or (raw.decode("utf-8", "replace")[:300])
            raise S3Error(exc.code, code, msg) from exc
        except urllib.error.URLError as exc:
            raise S3Error(0, "Transport", str(exc.reason)) from exc
        except TimeoutError as exc:
            raise S3Error(0, "Timeout", str(exc)) from exc

    def ensure_object_lock_bucket(self, bucket: str, mode: str, days: int) -> None:
        """Create the bucket with Object Lock, or confirm an existing bucket already has it.

        The create header turns versioning and object lock on together. There is no
        bucket-wide default retention: only objects that set COMPLIANCE headers are
        locked, so a fault-injection marker and an overwrite attempt stay deletable.
        A second PUT of versioning or of the lock configuration is not sent; some
        S3 implementations reject that call once the header has already enabled the lock.
        """
        del mode, days
        try:
            self._request("PUT", bucket, extra={"x-amz-bucket-object-lock-enabled": "true"}, body=b"")
            return
        except S3Error as exc:
            if exc.code not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists") and exc.status != 409:
                raise
        try:
            _status, _headers, raw = self._request("GET", bucket, query=[("object-lock", "")])
        except S3Error as exc:
            raise S3Error(exc.status, exc.code, f"object lock not confirmed: {exc.message}") from exc
        if b"Enabled" not in raw:
            raise S3Error(409, "ObjectLockNotEnabled", "bucket exists without object lock")

    def put_plain(self, bucket: str, key: str, body: bytes) -> tuple[int, str | None]:
        """PUT without Object Lock headers. Returns (status, version id). Never raises for HTTP errors."""
        try:
            status, headers, _raw = self._request("PUT", bucket, key, body=body)
        except S3Error as exc:
            return exc.status, None
        return status, headers.get("x-amz-version-id") or None

    def put_bytes(self, bucket: str, key: str, body: bytes, *, lock_mode: str, retain_until: str) -> str | None:
        status, headers, _ = self._request(
            "PUT", bucket, key, body=body,
            extra={
                "content-type": "application/octet-stream",
                "x-amz-object-lock-mode": lock_mode,
                "x-amz-object-lock-retain-until-date": retain_until,
            },
        )
        if status not in (200, 201):
            raise S3Error(status, "PutFailed", key)
        return headers.get("x-amz-version-id") or None

    def get_bytes(self, bucket: str, key: str, version_id: str | None = None) -> tuple[bytes, str | None]:
        query = [("versionId", version_id)] if version_id else []
        status, headers, raw = self._request("GET", bucket, key, query=query)
        if status != 200:
            raise S3Error(status, "GetFailed", key)
        return raw, headers.get("x-amz-version-id") or version_id

    def head(self, bucket: str, key: str) -> bool:
        try:
            status, _, _ = self._request("HEAD", bucket, key)
        except S3Error as exc:
            if exc.status == 404 or exc.code in ("NoSuchKey", "NotFound"):
                return False
            raise
        return status == 200

    def delete(self, bucket: str, key: str, version_id: str | None = None) -> int:
        query = [("versionId", version_id)] if version_id else []
        try:
            status, _, _ = self._request("DELETE", bucket, key, query=query)
        except S3Error as exc:
            return exc.status
        return status

    def list_versions(self, bucket: str, prefix: str) -> tuple[list[dict], list[dict]]:
        """Returns (versions, delete_markers). Each item has key, version_id, is_latest."""
        versions: list[dict] = []
        markers: list[dict] = []
        token = None
        while True:
            query = [("versions", ""), ("prefix", prefix), ("max-keys", "1000")]
            if token:
                query.append(("key-marker", token[0]))
                query.append(("version-id-marker", token[1]))
            try:
                _status, _headers, raw = self._request("GET", bucket, query=query)
            except S3Error:
                return self._list_v2(bucket, prefix), []
            root = ET.fromstring(raw)
            def local(tag: str) -> str:
                return tag.rsplit("}", 1)[-1]
            for el in root:
                name = local(el.tag)
                if name not in ("Version", "DeleteMarker"):
                    continue
                item = {}
                for child in el:
                    item[local(child.tag)] = (child.text or "").strip()
                rec = {
                    "key": item.get("Key", ""),
                    "version_id": item.get("VersionId") or None,
                    "is_latest": item.get("IsLatest") == "true",
                }
                (markers if name == "DeleteMarker" else versions).append(rec)
            truncated = False
            key_marker = ver_marker = ""
            for el in root:
                if local(el.tag) == "IsTruncated" and (el.text or "").strip() == "true":
                    truncated = True
                if local(el.tag) == "NextKeyMarker":
                    key_marker = (el.text or "").strip()
                if local(el.tag) == "NextVersionIdMarker":
                    ver_marker = (el.text or "").strip()
            if not truncated:
                break
            token = (key_marker, ver_marker)
        return versions, markers

    def _list_v2(self, bucket: str, prefix: str) -> list[dict]:
        out: list[dict] = []
        token = None
        while True:
            query = [("list-type", "2"), ("prefix", prefix), ("max-keys", "1000")]
            if token:
                query.append(("continuation-token", token))
            _status, _headers, raw = self._request("GET", bucket, query=query)
            root = ET.fromstring(raw)
            def local(tag: str) -> str:
                return tag.rsplit("}", 1)[-1]
            for el in root:
                if local(el.tag) != "Contents":
                    continue
                item = {local(c.tag): (c.text or "").strip() for c in el}
                out.append({"key": item.get("Key", ""), "version_id": None, "is_latest": True})
            truncated = False
            next_token = ""
            for el in root:
                if local(el.tag) == "IsTruncated" and (el.text or "").strip() == "true":
                    truncated = True
                if local(el.tag) == "NextContinuationToken":
                    next_token = (el.text or "").strip()
            if not truncated:
                break
            token = next_token
        return out
