"""
cloudflare-access-forwardauth — a tiny ForwardAuth / auth_request service that validates
Cloudflare Access JWTs at your origin.

Why: Cloudflare Access only protects the Cloudflare edge. If your origin is reachable directly
(by IP, with a forged Host header, or from inside your network), nothing stops a request from
skipping the login page. Cloudflare's answer is to validate the `Cf-Access-Jwt-Assertion` JWT on
every request at the origin: https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/

This service does exactly that, as a sidecar for reverse proxies that support an external auth
call (Traefik ForwardAuth, nginx auth_request, Caddy forward_auth, HAProxy, ...):

  - GET /healthz      -> 200 (liveness/readiness)
  - GET /verify, /*   -> 200 + identity headers when the JWT is valid, else 401

The JWT is read from the `Cf-Access-Jwt-Assertion` header or the `CF_Authorization` cookie and
checked for signature (RS256, JWKS of your team), issuer, audience (the AUD tag of the Access
application), expiry and the presence of an `email` claim. On success the response carries
`X-Remote-User` and `X-Remote-User-Email` (names configurable) for the proxy to copy onto the
upstream request, which lets apps that support header-based auth (NetBox REMOTE_AUTH, Grafana
auth.proxy, Django RemoteUserMiddleware, ...) log the user in automatically.

Access *service tokens* (machine clients sending CF-Access-Client-Id/Secret) get a JWT without
`email`, only `common_name`. SERVICE_TOKENS decides what to do with them:
  - reject   (default) 401: only humans get through.
  - pass     200 with EMPTY identity headers: the request reaches the app, which must authenticate
             it on its own (API token, basic auth...). The empty headers make the proxy overwrite
             anything the client sent, so a service token can never impersonate a user.
  - identity 200 with X-Remote-User = common_name (e-mail empty): the app logs the token in as a
             user named after it.

Deliberately framework-free: a raw ASGI app on uvicorn, one real dependency (PyJWT + cryptography).
Less surface in an authentication component is a feature.
"""

import logging
import os
import time
from http.cookies import SimpleCookie

import jwt
from jwt import PyJWKClient

log = logging.getLogger("cloudflare-access-forwardauth")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")

TEAM_DOMAIN = os.environ["CF_ACCESS_TEAM_DOMAIN"]  # e.g. example.cloudflareaccess.com
AUD = os.environ["CF_ACCESS_AUD"]  # Application Audience (AUD) tag of the Access application
ISSUER = f"https://{TEAM_DOMAIN}"
JWKS_URL = os.environ.get("CF_ACCESS_CERTS_URL", f"{ISSUER}/cdn-cgi/access/certs")
USER_HEADER = os.environ.get("USER_HEADER", "X-Remote-User").lower().encode("latin-1")   # ASGI: header names are lowercase
EMAIL_HEADER = os.environ.get("EMAIL_HEADER", "X-Remote-User-Email").lower().encode("latin-1")
SERVICE_TOKENS = os.environ.get("SERVICE_TOKENS", "").strip().lower()
if not SERVICE_TOKENS:
    # REQUIRE_EMAIL=false (0.1.x) meant "accept service tokens, identity = common_name".
    SERVICE_TOKENS = "reject" if os.environ.get("REQUIRE_EMAIL", "true").lower() not in ("0", "false", "no") else "identity"
if SERVICE_TOKENS not in ("reject", "pass", "identity"):
    raise SystemExit(f"SERVICE_TOKENS must be reject, pass or identity (got {SERVICE_TOKENS!r})")
LEEWAY = int(os.environ.get("CLOCK_SKEW_SECONDS", "30"))

# Cloudflare rotates signing keys. The JWK set is cached for an hour; an unknown `kid` triggers a
# refetch before the token is rejected.
_jwks = PyJWKClient(JWKS_URL, cache_jwk_set=True, lifespan=3600, timeout=10)

HEADER_JWT = b"cf-access-jwt-assertion"
COOKIE_JWT = "CF_Authorization"


def _token_from(headers: list[tuple[bytes, bytes]]) -> str | None:
    cookie_raw = None
    for name, value in headers:
        if name == HEADER_JWT and value:
            return value.decode("latin-1")
        if name == b"cookie":
            cookie_raw = value.decode("latin-1")
    if cookie_raw:
        jar = SimpleCookie()
        try:
            jar.load(cookie_raw)
        except Exception:  # malformed cookie: treat as absent
            return None
        if COOKIE_JWT in jar:
            return jar[COOKIE_JWT].value or None
    return None


def verify(token: str) -> tuple[str, str]:
    """Return (user, email) from a valid JWT or raise jwt.PyJWTError."""
    key = _jwks.get_signing_key_from_jwt(token)
    claims = jwt.decode(
        token,
        key.key,
        algorithms=["RS256"],
        audience=AUD,
        issuer=ISSUER,
        options={"require": ["exp", "iat", "aud", "iss", "sub"]},
        leeway=LEEWAY,
    )
    email = (claims.get("email") or "").strip().lower()
    if email and "@" in email:
        return email, email
    # No e-mail: an Access service token (or a malformed JWT).
    if SERVICE_TOKENS == "reject":
        raise jwt.InvalidTokenError("JWT has no 'email' claim (service tokens are rejected: SERVICE_TOKENS=reject)")
    name = (claims.get("common_name") or claims.get("sub") or "").strip()
    if not name:
        raise jwt.InvalidTokenError("JWT has neither 'email' nor 'common_name'/'sub'")
    if SERVICE_TOKENS == "pass":
        log.info("service token %s: passing without identity", name)
        return "", ""
    return name, ""


async def _send(send, status: int, body: bytes, extra_headers: list[tuple[bytes, bytes]] = ()):
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"text/plain; charset=utf-8"), (b"cache-control", b"no-store"), *extra_headers],
        }
    )
    await send({"type": "http.response.body", "body": body})


async def app(scope, receive, send):
    if scope["type"] == "lifespan":
        while True:
            msg = await receive()
            if msg["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif msg["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
    if scope["type"] != "http":
        return

    if scope["path"] == "/healthz":
        await _send(send, 200, b"ok")
        return

    token = _token_from(scope["headers"])
    if not token:
        await _send(send, 401, b"unauthorized: Cloudflare Access required")
        return
    t0 = time.monotonic()
    try:
        user, email = verify(token)
    except jwt.PyJWTError as e:
        log.warning("jwt rejected: %s", e)
        await _send(send, 401, b"unauthorized: invalid Cloudflare Access token")
        return
    except Exception as e:  # JWKS unreachable etc.: fail CLOSED
        log.error("jwt validation failed: %s", e)
        await _send(send, 503, b"auth unavailable")
        return
    log.debug("ok %s in %.0fms", user, (time.monotonic() - t0) * 1000)
    await _send(send, 200, b"ok", [(USER_HEADER, user.encode("latin-1")), (EMAIL_HEADER, email.encode("latin-1"))])
