"""
Tests with a local JWKS: generates an RSA key pair, serves the key set over HTTP and signs JWTs
with the claims Cloudflare Access issues.
"""

import asyncio
import base64
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

TEAM = "teste.cloudflareaccess.com"
AUD = "a" * 64
KID = "kid-teste"

_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_other = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _b64(n: int, length: int) -> str:
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()


def _jwks() -> bytes:
    pub = _priv.public_key().public_numbers()
    return json.dumps({"keys": [{"kty": "RSA", "kid": KID, "use": "sig", "alg": "RS256", "n": _b64(pub.n, 256), "e": _b64(pub.e, 3)}]}).encode()


class _H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = _jwks()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # quiet
        pass


@pytest.fixture(scope="session")
def guard():
    srv = HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    os.environ["CF_ACCESS_TEAM_DOMAIN"] = TEAM
    os.environ["CF_ACCESS_AUD"] = AUD
    os.environ["CF_ACCESS_CERTS_URL"] = f"http://127.0.0.1:{srv.server_port}/certs"
    import app as mod

    yield mod
    srv.shutdown()


def _pem(k):
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _token(key=_priv, kid=KID, **over):
    now = int(time.time())
    claims = {"aud": [AUD], "iss": f"https://{TEAM}", "sub": "uuid", "email": "Daniel@example.com", "iat": now, "nbf": now, "exp": now + 600, "type": "app"}
    claims.update(over)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, _pem(key), algorithm="RS256", headers={"kid": kid})


def _call(mod, headers: dict[str, str], path="/verify"):
    scope = {"type": "http", "path": path, "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()]}
    out = {}

    async def send(msg):
        if msg["type"] == "http.response.start":
            out["status"] = msg["status"]
            out["headers"] = {k.decode(): v.decode() for k, v in msg["headers"]}

    asyncio.run(mod.app(scope, None, send))
    return out


def test_healthz(guard):
    assert _call(guard, {}, "/healthz")["status"] == 200


def test_missing_token_401(guard):
    assert _call(guard, {})["status"] == 401


def test_valid_token_header(guard):
    r = _call(guard, {"Cf-Access-Jwt-Assertion": _token()})
    assert r["status"] == 200
    assert r["headers"]["x-remote-user"] == "daniel@example.com"
    assert r["headers"]["x-remote-user-email"] == "daniel@example.com"


def test_valid_token_cookie(guard):
    r = _call(guard, {"Cookie": f"foo=bar; CF_Authorization={_token()}"})
    assert r["status"] == 200


def test_client_header_does_not_leak(guard):
    # a forged X-Remote-User from the client never leaks: the response carries the JWT e-mail
    r = _call(guard, {"Cf-Access-Jwt-Assertion": _token(), "X-Remote-User": "admin"})
    assert r["headers"]["x-remote-user"] == "daniel@example.com"


@pytest.mark.parametrize(
    "tok",
    [
        _token(exp=int(time.time()) - 120),            # expired
        _token(aud=["b" * 64]),                        # audience of another app
        _token(iss="https://outra.cloudflareaccess.com"),
        _token(key=_other),                            # signed by another key (same kid)
        _token(kid="kid-inexistente"),
        _token(email=None, sub="", common_name="abcdef.access"),   # service token: rejected by default
        _token()[:-5] + "AAAAA",                       # tampered signature
        "nao.e.jwt",
    ],
)
def test_invalid_tokens_401(guard, tok):
    assert _call(guard, {"Cf-Access-Jwt-Assertion": tok})["status"] == 401


# --- Access service tokens (CF-Access-Client-Id/Secret): JWT with common_name and no e-mail ---

def _svc(**over):
    return _token(email=None, sub="", common_name="abcdef.access", **over)


def test_service_token_rejected_by_default(guard):
    assert guard.SERVICE_TOKENS == "reject"
    assert _call(guard, {"Cf-Access-Jwt-Assertion": _svc()})["status"] == 401


def test_service_token_pass(guard, monkeypatch):
    monkeypatch.setattr(guard, "SERVICE_TOKENS", "pass")
    r = _call(guard, {"Cf-Access-Jwt-Assertion": _svc(), "X-Remote-User": "admin"})
    assert r["status"] == 200
    # identity headers are present but EMPTY, so the proxy overwrites whatever the client sent
    assert r["headers"]["x-remote-user"] == ""
    assert r["headers"]["x-remote-user-email"] == ""
    # humans are unaffected
    assert _call(guard, {"Cf-Access-Jwt-Assertion": _token()})["headers"]["x-remote-user"] == "daniel@example.com"


def test_service_token_identity(guard, monkeypatch):
    monkeypatch.setattr(guard, "SERVICE_TOKENS", "identity")
    r = _call(guard, {"Cf-Access-Jwt-Assertion": _svc()})
    assert r["status"] == 200
    assert r["headers"]["x-remote-user"] == "abcdef.access"
    assert r["headers"]["x-remote-user-email"] == ""


def test_service_token_without_name_401(guard, monkeypatch):
    monkeypatch.setattr(guard, "SERVICE_TOKENS", "pass")
    assert _call(guard, {"Cf-Access-Jwt-Assertion": _token(email=None, sub="")})["status"] == 401


def test_service_token_still_validated(guard, monkeypatch):
    monkeypatch.setattr(guard, "SERVICE_TOKENS", "pass")
    assert _call(guard, {"Cf-Access-Jwt-Assertion": _svc(aud=["b" * 64])})["status"] == 401
    assert _call(guard, {"Cf-Access-Jwt-Assertion": _svc(key=_other)})["status"] == 401
