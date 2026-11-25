# ADR 0006: Worker scaffold and account mail jobs (T-011)

Status: accepted. Every choice below is the recommended option, taken under the owner's standing permission.

## Context
ADR 0005 point 10 left invite and password-reset mail to the worker. The job payload holds a raw one-time token and the
recipient address, so the queue must not leak either into logs or linger in job tables.

## Decisions
1. **Contract lives in `@igaro/worker`, not the API.** `AccountMailJob`, `AccountMailQueue` and the validator are in
   `apps/worker/src/account-mail-job.ts`. The worker never imports the API; the API imports the contract from
   `@igaro/worker/producer` and re-exports the types from `apps/api/src/notifications.ts`, so there is no cycle and no
   duplicated type. `NoopAccountMailQueue` and `MemoryAccountMailQueue` stay in the API.
2. **Producer.** `PgBossAccountMailQueue` (queue `account.mail`) wraps `pg-boss` `send`. `connectAccountMailQueue()` opens a
   producer-only connection (`supervise:false`, `schedule:false`; maintenance belongs to the worker) and ensures the queue.
3. **API wiring is config-driven.** `ACCOUNT_MAIL_QUEUE=noop|pgboss` (default `noop`, so nothing changes unless asked).
   `server.ts` loads the producer with a dynamic import only for `pgboss`, so tests and the default path never load pg-boss.
   Package `exports` use a `types` condition pointing at `src` and a `default` pointing at `dist`, so the worker must be built
   (`pnpm -r build` orders it) before the API runs with `pgboss`.
4. **Database role.** Worker uses `WORKER_DATABASE_URL`, else `APP_DATABASE_URL`; the owner `DATABASE_URL` is refused. pg-boss
   keeps its tables in its own schema (`PGBOSS_SCHEMA`, default `pgboss`), separate from RLS-protected tenant tables. It creates
   that schema on first start, so the role needs CREATE on the database or the schema must be pre-created. **Follow-up for
   `igaro-platform`:** add an `igaro_worker` role and grants in `packages/db`; the restricted `igaro_app` role may lack CREATE.
5. **Secrets in job tables: short life.** Queue options: `deleteAfterSeconds: 60` (applies to completed and failed jobs; `0`
   would mean keep forever), `expireInSeconds: 120`, `retryLimit: 5` with exponential backoff from 30 s. Per job,
   `retentionSeconds` = seconds until token expiry + 60 (floor 60 s), so a queued job never outlives its token. Residual risk:
   raw token sits in the job row from enqueue until about a minute after completion; accepted, and noted for the threat model.
6. **Expired jobs are skipped, not sent.** If `expiresAt <= now` the handler sends nothing and the job completes (logged as
   `skipped_expired`, with job id only).
7. **Malformed payloads are dropped, not retried.** Validation requires a plain address (no CR/LF, comma, angle brackets) and a
   base64url token. The error carries no payload. The job completes and is logged as `invalid job dropped`.
8. **No payload in logs or stored errors.** Call sites log job id, queue, outcome and retry count only. The pino logger also
   redacts `token`, `to`, `data`, `link`, `text`, `html` and uses an error serializer without message or stack. SMTP failures
   are rethrown as a generic `MailSendError` because pg-boss stores the thrown error as job output and SMTP replies often
   echo the recipient.
9. **Link format.** `${WEB_BASE_URL}/invite/accept#token=...` and `${WEB_BASE_URL}/password-reset#token=...`. The token is in
   the URL fragment so it is not sent to the web server or in Referer headers; the web app (not yet built) must read it
   client-side and POST it as JSON to the existing endpoints. `WEB_BASE_URL` falls back to `PUBLIC_WEB_URL`; `https` is
   required in production; no credentials, query or fragment allowed in the base.
10. **Mail transport.** nodemailer over SMTP (`SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM`; optional `SMTP_SECURE`, `SMTP_USER`,
    `SMTP_PASS`). Mailpit locally. A Resend/SES API transport can replace the transport later without changing the handler.
11. **Idempotency.** Each invite/reset token is unique, so a duplicate job would mail a different link; no singleton key is
    used (a key would copy token data into another column). Retries after a send that succeeded but was not acknowledged can
    mail twice; the token is single-use, so this is harmless.
12. **Tests.** Unit tests for contract, rendering, handler, producer, config and logger. Integration test runs real pg-boss on
    `$DATABASE_URL` in a throwaway schema with an in-process fake SMTP server, and checks that no token, recipient or link
    appears in worker logs. It is skipped when `DATABASE_URL` is unset.

## Not in this task
`email.deliver` (holder cards), `card.render`, `import.csv`, `audit.dailyHead`, and the `anchor.credential` slot (Phase 1, a
comment marker only in `apps/worker/src/index.ts`). Purging expired invite/reset/session rows (ADR 0005 point 14) is still open.
