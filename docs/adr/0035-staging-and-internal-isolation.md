# ADR 0035: Staging deployment and isolation of the internal API

Status: accepted (T-047). Recommended option taken under the owner's standing permission.

## Context
T-044 added service-authenticated endpoints under `/api/v1/internal/*` for the import worker (ADR 0034).
They take the institution id from the body, so they must never be reachable from the public internet
(T-044 review M1). The web app proxies `/api/v1/*` to the API (ADR 0025), which would expose them.

## Decision
1. **Web rewrite excludes `/api/v1/internal/*`** (`apps/web/next.config.mjs`, regex `(?!internal(?:/|$))`).
   The public origin returns 404 for those paths. Tested in `apps/web/src/next-config.test.ts`.
2. **Network guard in the API** (`INTERNAL_ALLOWED_CIDRS`, default loopback only). The peer is the TCP socket
   address, never `X-Forwarded-*`. Requests carrying `X-Forwarded-For`, `X-Forwarded-Host` or `Forwarded`
   (that is, ones that came through a proxy) get 404, as do peers outside the list. The check runs before the
   bearer token. `0/0` is refused. In production, setting `INTERNAL_API_TOKEN` without
   `INTERNAL_ALLOWED_CIDRS` is a startup error. A separate private listener was rejected for the MVP: a
   second Fastify instance adds a port and a deployment surface for no extra protection over allowlist plus
   proxy exclusion plus token. The deployment guide still says to keep the API on a private network.
3. **Worker requires https for `INTERNAL_API_URL` in production** (config error otherwise).
4. **Staging** runs with `NODE_ENV=production` semantics: `TRUST_PROXY` set to the real hop count (ADR 0003),
   `IP_HASH_KEY` set, secure cookies, HSTS. See `docs/deploy/staging.md`.

## Consequences
- Single-host setups where the worker calls the API over loopback keep working with no extra setting, but
  production must use https, so a TLS-terminating private hop (or mesh) is needed between worker and API.
- The API speaks plain HTTP, so the https hop must be a TLS sidecar on the worker's own host (loopback to the
  API's private address is not enough: terminate TLS next to the API, in front of it on the private network).
  That terminator must not add `X-Forwarded-*`/`Forwarded` headers (the guard would 404 the worker), and
  `INTERNAL_ALLOWED_CIDRS` must be only that terminator's narrow address, not the whole subnet. Reviewer M1
  (a dedicated TLS-terminating internal port in the API) is left as a follow-up before the first production import.
- Defence is layered: proxy exclusion, peer allowlist, shared secret, tenant checks and RLS.
