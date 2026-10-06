"""Unit tests: policy signatures (K3-01/K3-08) and OIDC/JWKS validation (S-01).
All keys are generated at test runtime (tmp_path); nothing is persisted."""
import json
import pathlib
import shutil
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "gateway"))

from aism_gateway import policysig  # noqa: E402
from aism_gateway.auth import AuthError, authenticate  # noqa: E402
from aism_gateway.policy import PolicyError, SignatureConfig, load_policy  # noqa: E402

SCHEMA = ROOT / "policy" / "policy.schema.json"
SRC = ROOT / "conformance" / "tests" / "testdata" / "policy.conformance.yaml"
EXAMPLE = ROOT / "policy" / "policy.example.yaml"
SIGN = ROOT / "tools" / "aism-policy-sign.py"
ID = "unit-test@localhost"


def run(*args):
    return subprocess.run([sys.executable, str(SIGN), *args], capture_output=True, text=True)


@pytest.fixture()
def signed(tmp_path):
    keys, pol = tmp_path / "keys", tmp_path / "policy"
    pol.mkdir()
    assert run("keygen", "--out", str(keys), "--identity", ID).returncode == 0
    assert (keys / "policy-signing.key").stat().st_mode & 0o077 == 0, "private key must be 0600"
    shutil.copy(SRC, pol / "policy.yaml")
    r = run("sign", "--key", str(keys / "policy-signing.key"), "--identity", ID, str(pol / "policy.yaml"))
    assert r.returncode == 0, r.stderr
    return pol / "policy.yaml", SignatureConfig(required=True, allowed_signers=str(keys / "allowed_signers")), keys


def test_signed_policy_loads(signed):
    path, sc, _ = signed
    p = load_policy(path, SCHEMA, sc)
    assert p.signature["verified"] and p.signature["signer"] == ID
    assert p.info()["signature_verified"] and len(p.meta["revision"]) == 40


def test_unsigned_policy_rejected(tmp_path):
    shutil.copy(SRC, tmp_path / "policy.yaml")
    (tmp_path / "as").write_text("")
    with pytest.raises(PolicyError, match="unsignierte"):
        load_policy(tmp_path / "policy.yaml", SCHEMA, SignatureConfig(required=True, allowed_signers=str(tmp_path / "as")))


def test_tampered_policy_rejected(signed):
    path, sc, _ = signed
    path.write_text(path.read_text().replace("maxToolRounds: 5", "maxToolRounds: 50"))
    with pytest.raises(PolicyError, match="Signatur ungültig"):
        load_policy(path, SCHEMA, sc)


def test_untrusted_key_rejected(signed, tmp_path):
    path, sc, _ = signed
    other = tmp_path / "other"
    run("keygen", "--out", str(other), "--identity", ID)
    with pytest.raises(PolicyError, match="nicht in allowed_signers"):
        load_policy(path, SCHEMA, SignatureConfig(required=True, allowed_signers=str(other / "allowed_signers")))


def test_wrong_namespace_rejected(signed):
    path, sc, keys = signed
    from cryptography.hazmat.primitives import serialization
    key = serialization.load_ssh_private_key((keys / "policy-signing.key").read_bytes(), None)
    (path.parent / "policy.yaml.sig").write_text(policysig.sign(path.read_bytes(), key, namespace="git"))
    with pytest.raises(PolicyError, match="Namespace"):
        load_policy(path, SCHEMA, sc)


def test_anchor_namespace_restriction(signed):
    path, sc, keys = signed
    line = (keys / "allowed_signers").read_text().replace('namespaces="aism-policy"', 'namespaces="git"')
    (keys / "allowed_signers").write_text(line)
    with pytest.raises(PolicyError, match="nicht in allowed_signers"):
        load_policy(path, SCHEMA, sc)


def test_signer_mismatch_rejected(signed):
    path, sc, _ = signed
    path_text = path.read_text().replace(f"signer: {ID}", "signer: someone-else@localhost")
    path.write_text(path_text)   # also invalidates the signature; signer check runs first
    with pytest.raises(PolicyError):
        load_policy(path, SCHEMA, sc)


def test_rollback_rejected(signed):
    path, sc, keys = signed
    cur = load_policy(path, SCHEMA, sc)
    old = path.read_text().replace('effectiveFrom: "2026-10-05T00:00:00+02:00"', 'effectiveFrom: "2026-01-01T00:00:00+01:00"')
    path.write_text(old)
    assert run("sign", "--key", str(keys / "policy-signing.key"), "--identity", ID, str(path)).returncode == 0
    with pytest.raises(PolicyError, match="Rollback"):
        load_policy(path, SCHEMA, sc, current=cur)


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="OpenSSH not installed")
def test_interop_with_openssh(signed):
    path, sc, keys = signed
    r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", sc.allowed_signers, "-I", ID, "-n", "aism-policy",
                        "-s", str(path) + ".sig"], stdin=open(path, "rb"), capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    p2 = path.parent / "p2.yaml"
    shutil.copy(path, p2)
    subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(keys / "policy-signing.key"), "-n", "aism-policy", str(p2)],
                   check=True, capture_output=True)
    policysig.verify(p2.read_bytes(), (path.parent / "p2.yaml.sig").read_text(), pathlib.Path(sc.allowed_signers).read_text(), ID)


def test_gateway_keeps_old_policy_on_bad_signature(signed, monkeypatch, tmp_path):
    path, sc, _ = signed
    from aism_gateway import main as gw
    monkeypatch.setattr(gw, "POLICY_PATH", str(path))
    monkeypatch.setattr(gw, "SCHEMA_PATH", str(SCHEMA))
    monkeypatch.setattr(gw, "SIG_CFG", sc)
    monkeypatch.setattr(gw, "AUDIT_PATH_ENV", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(gw.S, "audit", None)
    monkeypatch.setattr(gw.S, "policy", None)
    gw.try_load(initial=True)
    assert gw.S.policy is not None
    good = gw.S.policy.digest
    path.write_text(path.read_text() + "\n# tampered\n")
    gw.try_load()
    assert gw.S.policy.digest == good and "Signatur" in gw.S.policy_error
    events = [json.loads(l)["event"] for l in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert events[-1] == "policy.load_failed"


# ── OIDC ─────────────────────────────────────────────────────────────

ISS = "http://127.0.0.1:{port}/realms/aism"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ROGUE = rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def idp():
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key()))
    body = json.dumps({"keys": [{**jwk, "kid": "k1", "alg": "RS256", "use": "sig"}]}).encode()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


@pytest.fixture()
def oidc_policy(idp, tmp_path):
    t = EXAMPLE.read_text()
    t = t.replace("issuer: https://idp.example.com/realms/aism", f"issuer: {ISS.format(port=idp)}")
    t = t.replace("jwksUri: https://idp.example.com/realms/aism/protocol/openid-connect/certs",
                  f"jwksUri: http://127.0.0.1:{idp}/jwks")
    (tmp_path / "policy.yaml").write_text(t)
    return load_policy(tmp_path / "policy.yaml", SCHEMA), ISS.format(port=idp)


def tok(iss, key=KEY, kid="k1", alg="RS256", **over):
    now = int(time.time())
    c = {"iss": iss, "sub": "u1", "aud": "aism-gateway", "iat": now, "exp": now + 300, "groups": ["it-ops"], **over}
    c = {k: v for k, v in c.items() if v is not None}
    return jwt.encode(c, key, algorithm=alg, headers={"kid": kid})


def hdr(t):
    return {"authorization": f"Bearer {t}"}


def test_oidc_valid_token_maps_groups(oidc_policy):
    pol, iss = oidc_policy
    s = authenticate(pol, hdr(tok(iss)))
    assert s.roles == ["it-ops"] and s.id == "oidc:corporate-idp:u1"


@pytest.mark.parametrize("case", ["expired", "wrong_aud", "rogue_key", "unknown_kid", "hs256", "no_sub", "wrong_iss"])
def test_oidc_invalid_tokens_rejected(oidc_policy, case):
    pol, iss = oidc_policy
    t = {"expired": lambda: tok(iss, exp=int(time.time()) - 120),
         "wrong_aud": lambda: tok(iss, aud="other"),
         "rogue_key": lambda: tok(iss, key=ROGUE),
         "unknown_kid": lambda: tok(iss, key=ROGUE, kid="nope"),
         "hs256": lambda: jwt.encode({"iss": iss, "sub": "u1", "aud": "aism-gateway", "exp": int(time.time()) + 60},
                                     "x" * 32, algorithm="HS256"),
         "no_sub": lambda: tok(iss, sub=None),
         "wrong_iss": lambda: tok("https://evil.example/realms/aism")}[case]()
    with pytest.raises(AuthError) as e:
        authenticate(pol, hdr(t))
    assert e.value.status == 401, e.value.message


def test_oidc_jwks_unreachable_fails_closed(tmp_path):
    t = EXAMPLE.read_text().replace("jwksUri: https://idp.example.com/realms/aism/protocol/openid-connect/certs",
                                "jwksUri: http://127.0.0.1:9/jwks")
    (tmp_path / "policy.yaml").write_text(t)
    pol = load_policy(tmp_path / "policy.yaml", SCHEMA)
    with pytest.raises(AuthError) as e:
        authenticate(pol, hdr(tok("https://idp.example.com/realms/aism")))
    assert e.value.status == 503
