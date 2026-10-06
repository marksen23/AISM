#!/usr/bin/env python3
"""Minimal OIDC test IdP (TEST DOUBLE – mints tokens for anyone, never use outside tests).

Keys are generated at start (RSA-2048 "test-rs256" + ES256 "test-es256"), nothing is written to disk.
  GET /.well-known/openid-configuration      issuer, jwks_uri
  GET /jwks                                  public keys (JWKS)
  GET /token?sub=u1&groups=it-ops,staff&aud=aism-gateway&ttl=300&alg=RS256&rogue=0
                                             -> {"access_token": "..."}; rogue=1 signs with a key NOT in the
                                                JWKS; ttl<0 gives an expired token
Usage: python3 mock_idp.py --port 18090 [--issuer http://127.0.0.1:18090/realms/aism]
"""
from __future__ import annotations

import argparse
import json
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa

KEYS = {"RS256": ("test-rs256", rsa.generate_private_key(public_exponent=65537, key_size=2048)),
        "ES256": ("test-es256", ec.generate_private_key(ec.SECP256R1()))}
ROGUE = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwks() -> dict:
    out = []
    for alg, (kid, key) in KEYS.items():
        jwk = json.loads(jwt.algorithms.get_default_algorithms()[alg].to_jwk(key.public_key()))
        out.append({**jwk, "kid": kid, "alg": alg, "use": "sig"})
    return {"keys": out}


class H(BaseHTTPRequestHandler):
    issuer = ""

    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path.endswith("/.well-known/openid-configuration"):
            return self._json(200, {"issuer": self.issuer, "jwks_uri": self.issuer + "/jwks"})
        if u.path.endswith("/jwks"):
            return self._json(200, jwks())
        if u.path.endswith("/token"):
            alg = q.get("alg", "RS256")
            kid, key = KEYS[alg]
            if q.get("rogue") == "1":
                kid, key, alg = "test-rs256", ROGUE, "RS256"   # same kid, different key -> must fail
            now = int(time.time())
            ttl = int(q.get("ttl", "300"))
            claims = {"iss": q.get("iss", self.issuer), "sub": q.get("sub", "test-user"), "aud": q.get("aud", "aism-gateway"),
                      "iat": now, "nbf": now - 5, "exp": now + ttl, "jti": uuid.uuid4().hex,
                      "groups": [g for g in q.get("groups", "").split(",") if g],
                      "preferred_username": q.get("sub", "test-user")}
            return self._json(200, {"access_token": jwt.encode(claims, key, algorithm=alg, headers={"kid": kid})})
        return self._json(404, {"error": "not_found"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18090)
    ap.add_argument("--issuer", default=None)
    a = ap.parse_args()
    H.issuer = (a.issuer or f"http://{a.host}:{a.port}/realms/aism").rstrip("/")
    print(f"mock IdP issuer {H.issuer}", flush=True)
    ThreadingHTTPServer((a.host, a.port), H).serve_forever()


if __name__ == "__main__":
    main()
