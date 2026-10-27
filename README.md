# cloudflare-access-forwardauth

A tiny (~100 lines, one real dependency) ForwardAuth / `auth_request` service that validates
[Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/) JWTs at your origin.

**Why.** Cloudflare Access only protects the Cloudflare edge. If your origin is reachable directly
(by IP with a forged `Host`, from inside your network, through a misrouted tunnel) nothing stops a request
from skipping the login page. Cloudflare's recommendation is to
[validate the `Cf-Access-Jwt-Assertion` JWT on every request](https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/).
This service does that for any reverse proxy with an external-auth hook, and hands the authenticated
identity to your app as headers so it can log the user in automatically.

```
client ──Cloudflare Access──▶ proxy ──(ForwardAuth)──▶ cloudflare-access-forwardauth
                                │                              │ 200 + X-Remote-User
                                └────── upstream app ◀─────────┘   (or 401)
```

## Endpoints

| Path       | Result |
|------------|--------|
| `/healthz` | `200 ok` (liveness/readiness) |
| anything else (`/verify` by convention) | `200` with `X-Remote-User` and `X-Remote-User-Email` when the JWT is valid; `401` when missing or invalid; `503` when the JWKS cannot be fetched (fails closed) |

The JWT is read from the `Cf-Access-Jwt-Assertion` header or the `CF_Authorization` cookie, exactly as
Cloudflare sends them. Checks: RS256 signature against your team's JWKS (cached 1h, refreshed on unknown `kid`),
issuer `https://<team>.cloudflareaccess.com`, audience = your application's AUD tag, `exp`/`iat`
(30 s leeway) and an `email` claim.

## Configuration (environment)

| Variable | Required | Default | Meaning |
|----------|----------|---------|---------|
| `CF_ACCESS_TEAM_DOMAIN` | yes | | e.g. `example.cloudflareaccess.com` |
| `CF_ACCESS_AUD` | yes | | Application Audience (AUD) tag of the Access application (Zero Trust → Access → Applications → Overview) |
| `CF_ACCESS_CERTS_URL` | no | `https://$TEAM/cdn-cgi/access/certs` | JWKS URL (override for tests) |
| `USER_HEADER` | no | `X-Remote-User` | response header carrying the identity |
| `EMAIL_HEADER` | no | `X-Remote-User-Email` | response header carrying the e-mail |
| `REQUIRE_EMAIL` | no | `true` | reject tokens without `email` (Access **service tokens** have none). Set `false` to accept them: identity becomes `common_name`/`sub` |
| `CLOCK_SKEW_SECONDS` | no | `30` | leeway for `exp`/`iat`/`nbf` |
| `LOG_LEVEL` | no | `INFO` | `DEBUG` logs each accepted identity |

## Run

```sh
docker run --rm -p 8080:8080 \
  -e CF_ACCESS_TEAM_DOMAIN=example.cloudflareaccess.com \
  -e CF_ACCESS_AUD=0123…abcd \
  ghcr.io/estabilis/cloudflare-access-forwardauth:latest
```

Image: `ghcr.io/estabilis/cloudflare-access-forwardauth` (linux/amd64 + arm64), tags `latest`, `X.Y.Z` (from git tag `vX.Y.Z`), `X.Y`, `main`,
`sha-<commit>`. Runs as uid 10001, works with a read-only root filesystem (mount a writable `/tmp`).

## Proxy examples

- **Traefik on Kubernetes** (ForwardAuth `Middleware` + Ingress annotation): [`examples/traefik-kubernetes.yaml`](examples/traefik-kubernetes.yaml)
- **nginx** (`auth_request`): [`examples/nginx.conf`](examples/nginx.conf)
- **Caddy**: `forward_auth cloudflare-access-forwardauth:8080 { uri /verify; copy_headers X-Remote-User X-Remote-User-Email }`

Make sure the proxy **replaces** `X-Remote-User`/`X-Remote-User-Email` on the upstream request with the values from
this service (Traefik's `authResponseHeaders` and nginx's `proxy_set_header` do). Never let the client's own
copy of those headers through, and make sure the upstream is reachable **only** through the proxy
(NetworkPolicy, firewall, localhost binding).

## Apps that log in from the headers

- **NetBox**: `REMOTE_AUTH_ENABLED=True`, `REMOTE_AUTH_HEADER='HTTP_X_REMOTE_USER'`,
  `REMOTE_AUTH_USER_EMAIL='HTTP_X_REMOTE_USER_EMAIL'`, `REMOTE_AUTH_AUTO_CREATE_USER=True`
  (`REMOTE_AUTH_GROUP_SYNC_ENABLED=True` if you use `REMOTE_AUTH_SUPERUSERS`).
- **Grafana**: `[auth.proxy] enabled = true, header_name = X-Remote-User, header_property = username`.
- **Django**: `RemoteUserMiddleware` + `RemoteUserBackend` with `header = 'HTTP_X_REMOTE_USER'`.

Logging out of such an app should also end the Access session: redirect to
`https://<your host>/cdn-cgi/access/logout`.

## Development

```sh
pip install --require-hashes -r requirements.txt -r requirements-dev.txt
pytest -q
```

Tests sign JWTs with a local RSA key served from an in-process JWKS endpoint and cover: valid token via header and
via cookie, forged client header, expired, wrong audience, wrong issuer, wrong key, unknown `kid`, missing
e-mail, tampered signature, garbage. Dependencies are pinned with hashes; regenerate with

```sh
docker run --rm -v "$PWD":/w -w /w python:3.13-slim sh -c 'pip install -q pip-tools && pip-compile --generate-hashes --strip-extras requirements.in && pip-compile --generate-hashes --strip-extras -o requirements-dev.txt requirements-dev.in'
```

## License

MIT.
