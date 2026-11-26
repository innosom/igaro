# iGARO end-to-end demo script (Playwright)

Drives the white paper v1.0 section 15 demo through the real UI against a running stack. It is deliberately **not** part
of `pnpm test` (the package has no `test` script): it needs the whole stack, a browser and a few minutes.

Covered (one ordered story, `tests/demo.spec.ts`):

1. platform admin creates an institution and invites its admin
2. admin accepts the invite from the Mailpit email (link works once), logs in
3. branding (logo, card title, colours)
4. credential type, holder, photo
5. issue; the QR URL (`/v/:token`) shows VERIFIED, signed by the institution, with the institution branding
6. holder email in Mailpit with a private `/h/:token` link; holder page; card PNG download; a guessed link reveals nothing
7. suspend (reason mandatory) -> SUSPENDED; reinstate -> VERIFIED
8. revoke (final, confirmation mandatory) -> REVOKED; no reinstate button; a forged API reinstate is refused
9. reissue -> old credential SUPERSEDED with a link to the new VERIFIED one
10. CSV + photo ZIP import (preview, run, one email per holder; `E2E_IMPORT_ROWS`, default 25, up to 500)
11. audit chain verifies in the dashboard
12. (needs `E2E_DATABASE_URL`) editing a signed field in the database -> VERIFICATION FAILED, restored -> VERIFIED
13. (needs `E2E_DATABASE_URL`) `UPDATE credentials SET status='ACTIVE'` on a revoked row is refused; `/v` still REVOKED

Not here (covered by vitest suites): cross-tenant (404 + RLS), audit tamper with recomputed hashes, CLI verify with the
network off, p95 latency, log hygiene (`apps/api/src/no-secrets-in-logs.test.ts`), the 500-holder import
(`apps/api/src/import-internal.test.ts`).

## Prerequisites

The stack must already be running and reachable, with a platform admin seeded:

- Postgres migrated and seeded (`pnpm db:seed`), MinIO, **Mailpit** (`docker compose up -d`)
- API (`apps/api`) with `MASTER_KEY`, `INTERNAL_API_TOKEN`, `ACCOUNT_MAIL_QUEUE=pgboss`, `DELIVERY_PAYLOAD_KEY`, S3 settings
- **Worker** (`apps/worker`) with the same queue, SMTP to Mailpit, `INTERNAL_API_URL`, `INTERNAL_API_TOKEN`, `DELIVERY_PAYLOAD_KEY`, S3 settings
  (emails, card rendering and the import all depend on it)
- Web (`apps/web`) built and started, proxying `/api/v1` to the API; `WEB_BASE_URL` for mail links should be the same origin
- `.env.example` documents each variable. Use test-only values; never point this at production.

## Run

```
pnpm install
pnpm --filter @igaro/e2e e2e:install        # downloads Chromium once (add `--with-deps` on a bare Linux host)

E2E_PLATFORM_EMAIL=platform-admin@igaro.test \
E2E_PLATFORM_PASSWORD='<the seeded platform admin password>' \
pnpm e2e
```

| Variable | Default | Purpose |
|---|---|---|
| `E2E_PLATFORM_EMAIL` / `E2E_PLATFORM_PASSWORD` | required | seeded platform admin |
| `E2E_BASE_URL` | `http://127.0.0.1:3000` | web origin |
| `E2E_MAILPIT_URL` | `http://127.0.0.1:8025` | Mailpit REST API |
| `E2E_DATABASE_URL` | unset | **superuser** connection; enables steps 12 and 13. Local throwaway compose database only, never staging. Traces may contain typed passwords; do not upload test-results/. |
| `E2E_IMPORT_ROWS` | `25` | holders in the import step (500 for the full criterion) |

Every run creates a fresh institution (`e2e-<random>`) and unique emails, so it can be repeated. It leaves that
institution behind; suspend it from the platform screen if you need to tidy up. Steps 12 and 13 modify and then restore
a row of that institution only.

## Security notes

- `trace: retain-on-failure` and failure screenshots can contain one-time tokens in URLs. They stay in `test-results/`
  (git-ignored). Do not upload them as CI artefacts from a shared runner.
- The script never prints message bodies or tokens.
- The admin password is random per run and only held in memory.

## Status

Type-checks and lists (`pnpm --filter @igaro/e2e typecheck`, `pnpm exec playwright test --list`). See the T-048 report for whether it
has been executed against a live stack; the selectors were written from the web source and may need small adjustments
on the first live run.
