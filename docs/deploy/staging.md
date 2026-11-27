# Staging deployment and production hardening (T-047, ADR 0035)

No real secrets belong in this repo. Generate every value per environment and keep it in the platform's secret store.

## Topology
```
internet -> TLS ingress -> web (Next.js, public) -> api (private network) <- worker (private network)
                                                     |-> Postgres (private)   |-> S3/MinIO (private bucket)
```
- Only `web` is public. The API listens on a private address (`API_HOST`), never on a public interface.
- `/api/v1/internal/*` is not proxied by web (rewrite exclusion) and the API answers it only to peers in
  `INTERNAL_ALLOWED_CIDRS`, only without `X-Forwarded-*`, and only with `INTERNAL_API_TOKEN`.
- Keep the ingress from forwarding `/api/v1/internal/*` too (defence in depth); the app does not rely on it.

## Required API environment (NODE_ENV=production)
| Variable | Notes |
|---|---|
| `TRUST_PROXY` | Hop count of proxies in front of the API (ADR 0003), e.g. `2` for ingress + web. Never `true`. |
| `IP_HASH_KEY` | `openssl rand -base64 32`. Keys the hashed-IP logs and rate limits (also the account keys in `rate_limit_counters`). Must be identical on every API instance, or limits stop being shared (ADR 0040). |
| `MASTER_KEY` | 32 bytes base64, held outside the DB. Different from every other secret. |
| `AUDIT_HEAD_PUBLIC_KEYS` | Public keys for the daily signed head. |
| `COOKIE_SECURE` | `true` (default in production). |
| `INTERNAL_API_TOKEN` | `openssl rand -base64 48`. Same value in worker. |
| `INTERNAL_ALLOWED_CIDRS` | Worker subnet, e.g. `10.20.0.0/24`. Required when the token is set. |
| `DELIVERY_PAYLOAD_KEY` | Shared with worker, not `MASTER_KEY`. |

Worker: `INTERNAL_API_URL` must be `https://...` in production, plus `INTERNAL_API_TOKEN`, `S3_*`,
`DELIVERY_PAYLOAD_KEY`, `WORKER_DATABASE_URL` (worker only; the API refuses it, ADR 0039).

Release step, after `pnpm db:migrate` and after each pg-boss upgrade, run as the owner (`DATABASE_URL`): `pnpm db:pgboss`.
It fails if the pgboss schema or a relation is owned by a runtime role. Keep `PGBOSS_SCHEMA_MODE=external`
(the production default; the API warns on `auto`).
Web: `API_URL` points at the private API address; `WEB_TRUST_PROXY_HOPS` per ADR 0026.

See `.env.example` for the full list and `.env.staging.example` for placeholders.

## Hardening checklist
- [ ] Postgres reachable only from api and worker; api uses `igaro_app` (RLS on), worker uses its own grants role.
- [ ] S3 bucket private; scoped keys per service (open follow-up from ADR 0028 M2).
- [ ] TLS everywhere including the worker to API hop; HSTS is set by web in production.
- [ ] Run migrations with the owner role in the release step, never from the app.
- [ ] Rotate `INTERNAL_API_TOKEN` by deploying API and worker together.
- [ ] Logs: confirm no tokens or keys (the no-secrets-in-logs test is part of T-048).
- [ ] Back up Postgres; the audit log is append-only and its signed head must be backed up with it.
