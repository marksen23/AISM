"""Client and user authentication (PEP-1) for the prototype.

Supported identity sources (policy spec.subjects.identitySources):
  api-key              Bearer token of a calling client (Open WebUI, n8n, conformance runner)
  forwarded-jwt-hs256  user identity forwarded by a trusted client, e.g. Open WebUI >= v0.9.6
                       (ENABLE_FORWARD_USER_INFO_HEADERS + FORWARD_USER_INFO_HEADER_JWT_SECRET).
                       Open WebUI's JWT carries sub, email, name, role, iss, iat, exp – no groups.
  oidc-bearer          Bearer access token (JWT) of an OIDC IdP, validated against the IdP's JWKS
                       (jwksUri): signature (RS*/PS*/ES*/EdDSA only – never HS*/none), iss, aud, exp, nbf
                       (leeway 30 s), sub. Roles come from the claims (e.g. groups) via subjects.roles[].match.
                       JWKS are cached for 5 min; unknown kid triggers one refetch (PyJWKClient). If the JWKS
                       cannot be fetched the request is rejected with 503 (fail-closed).
"""
from __future__ import annotations

import hmac
import os
import pathlib
import ssl
from dataclasses import dataclass, field

import jwt

OIDC_ALGORITHMS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"]
OIDC_LEEWAY = 30
_jwks_clients: dict[str, jwt.PyJWKClient] = {}

from .policy import Policy, roles_for_claims


class AuthError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def resolve_secret(ref: str | None) -> str | None:
    if not ref:
        return None
    kind, _, val = ref.partition(":")
    if kind == "env":
        return os.environ.get(val) or None
    if kind == "file":
        try:
            return pathlib.Path(val).read_text(encoding="utf-8").strip() or None
        except OSError:
            return None
    return None


@dataclass
class Subject:
    id: str
    client: str
    roles: list[str] = field(default_factory=list)
    agent: str | None = None


def _jwks_client(uri: str) -> jwt.PyJWKClient:
    c = _jwks_clients.get(uri)
    if c is None:
        ca = os.environ.get("AISM_CA_BUNDLE")
        c = jwt.PyJWKClient(uri, cache_jwk_set=True, lifespan=300, timeout=5,
                            ssl_context=ssl.create_default_context(cafile=ca) if ca else None)
        _jwks_clients[uri] = c
    return c


def _oidc(policy: Policy, token: str, sources: list[dict]) -> Subject | None:
    oidc = [s for s in sources if s["type"] == "oidc-bearer"]
    if not oidc:
        return None
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
        hdr = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise AuthError(401, "invalid_token", "Token ist kein gültiges JWT") from exc
    src = next((s for s in oidc if s.get("issuer") and s["issuer"] == unverified.get("iss")), None)
    if src is None:
        raise AuthError(401, "invalid_token", "Unbekannter Token-Aussteller")
    if hdr.get("alg") not in OIDC_ALGORITHMS:
        raise AuthError(401, "invalid_token", f"Signaturalgorithmus {hdr.get('alg')!r} nicht zulässig")
    if not src.get("jwksUri") or not src.get("audience"):
        raise AuthError(503, "auth_unavailable", f"Identitätsquelle {src['id']}: jwksUri/audience fehlt")
    try:
        key = _jwks_client(src["jwksUri"]).get_signing_key_from_jwt(token)
    except jwt.PyJWKClientConnectionError as exc:
        raise AuthError(503, "auth_unavailable", "JWKS des IdP nicht abrufbar (fail-closed)") from exc
    except jwt.PyJWKClientError as exc:
        raise AuthError(401, "invalid_token", "Kein passender Schlüssel (kid) in den JWKS") from exc
    try:
        claims = jwt.decode(token, key.key, algorithms=[hdr["alg"]], audience=src["audience"], issuer=src["issuer"],
                            leeway=OIDC_LEEWAY, options={"require": ["exp", "iss", "aud", "sub"]})
    except jwt.PyJWTError as exc:
        raise AuthError(401, "invalid_token", f"OIDC-Token ungültig: {exc.__class__.__name__}") from exc
    return Subject(id=f"oidc:{src['id']}:{claims['sub']}", client=src.get("client") or src["id"],
                   roles=roles_for_claims(policy, claims))


def authenticate(policy: Policy, headers) -> Subject:
    sources = policy.spec["subjects"].get("identitySources", [])
    authz = headers.get("authorization", "")
    if not authz.lower().startswith("bearer "):
        raise AuthError(401, "invalid_token", "Bearer-Token fehlt")
    token = authz[7:].strip()

    client = None
    for s in sources:
        if s["type"] != "api-key":
            continue
        secret = resolve_secret(s.get("secretRef"))
        if secret and hmac.compare_digest(secret.encode(), token.encode()):
            client = s.get("client") or s["id"]
            break
    if client is None:
        subj = _oidc(policy, token, sources) if token.count(".") == 2 else None
        if subj is None:
            raise AuthError(401, "invalid_token", "Unbekannter Client-Schlüssel")
        agent = headers.get("x-aism-agent") or None
        if agent not in {a["id"] for a in policy.spec["subjects"].get("agents", [])}:
            agent = None
        subj.agent = agent
        return subj

    claims: dict = {}
    subject_id = f"client:{client}"
    for s in sources:
        if s["type"] != "forwarded-jwt-hs256" or s.get("client") not in (None, client):
            continue
        hdr = s.get("header", "X-OpenWebUI-User-Jwt")
        raw = headers.get(hdr.lower()) or headers.get(hdr)
        if not raw:
            continue
        secret = resolve_secret(s.get("secretRef"))
        if not secret:
            raise AuthError(503, "auth_unavailable", "JWT-Secret nicht konfiguriert")
        try:
            claims = jwt.decode(raw, secret, algorithms=["HS256"], options={"require": ["sub", "exp"]},
                                issuer=s["issuer"] if s.get("issuer") else None)
        except jwt.PyJWTError as exc:
            raise AuthError(401, "invalid_token", f"Benutzer-JWT ungültig: {exc.__class__.__name__}") from exc
        subject_id = f"user:{claims['sub']}"
        break

    agent = headers.get("x-aism-agent") or None
    known_agents = {a["id"] for a in policy.spec["subjects"].get("agents", [])}
    if agent and agent not in known_agents:
        agent = None
    return Subject(id=subject_id, client=client, roles=roles_for_claims(policy, claims), agent=agent)
