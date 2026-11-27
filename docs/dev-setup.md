# Dev setup

Requires Node 20+, pnpm 9, Docker with Compose v2.

```
cp .env.example .env        # test-only values; set your own MASTER_KEY
openssl rand -base64 32     # paste into MASTER_KEY in .env
docker compose up -d        # Postgres 16, Mailpit, MinIO (+ bucket bootstrap)
docker compose ps           # wait until services are healthy
pnpm install
```

Services (all bound to 127.0.0.1):

| Service  | Address                                |
| -------- | -------------------------------------- |
| Postgres | 127.0.0.1:5432                         |
| Mailpit  | SMTP 1025, UI http://127.0.0.1:8025    |
| MinIO    | S3 9000, console http://127.0.0.1:9001 |

The `minio-init` one-shot container creates the private bucket `S3_BUCKET`.
Data persists in the named volumes `pgdata` and `miniodata`. To reset, stop the
stack and remove its volumes with `docker compose down -v`.

All credentials in `docker-compose.yml` and `.env.example` are test-only.
Seed: `pnpm db:seed` (owner `DATABASE_URL`; idempotent; SEED_* in `.env.example`; see
`packages/db/src/seed.ts`). It creates the platform admin, the `eau` institution and its admin,
the STUDENT_ID and CERTIFICATE types and three demo holders, but no signing keys. With
`NODE_ENV=production` only the platform admin is created (add `SEED_DEMO=1` for the demo data), and
the test-only default password is refused everywhere except `NODE_ENV=development|test` or
`SEED_ALLOW_TEST_PASSWORD=1`. The seed sets both the platform and the tenant scope, since the
platform scope can only read credential types and holders. Tests run it as a NOSUPERUSER
NOBYPASSRLS table-owner role.

## Database roles and RLS

The init migration (`packages/db/prisma/migrations/*_init`) creates the role `igaro_app`
(NOLOGIN, no superuser, no BYPASSRLS, no password in the repo). Run migrations as the owner role
(the compose `POSTGRES_USER`). To let the API/worker connect as the restricted role, set a password
once per environment, outside version control:

```
ALTER ROLE igaro_app WITH LOGIN PASSWORD '<from your secret store>';
```

and use an `igaro_app` connection string for the API/worker. Until you run that `ALTER ROLE` step
(also in local dev) the role cannot log in. RLS is ENABLE + FORCE on every table, so even a
non-superuser owner sees nothing unless the transaction sets a scope with `SET LOCAL` /
`set_config(name, value, true)`: `app.institution_id` (tenant), `app.is_platform_admin = 'true'`
(platform), or one narrow lookup setting for unauthenticated paths (`app.institution_slug`,
`app.verification_token`, `app.holder_token_hash`, `app.login_email`, `app.session_token_hash`,
`app.invite_token_hash`, `app.reset_token_hash`). Seeds must set a scope too. Superusers and
BYPASSRLS roles skip RLS entirely, so the app must never connect as one (the compose `igaro`
user is typically a superuser, so use `igaro_app` to exercise RLS). Anyone who can run arbitrary SQL as
`igaro_app` can set the scope settings (threat model row 9, M2).
UPDATE is granted per column; key and institution status changes are platform scope only.
`packages/db/src/migration.test.ts` runs when `DATABASE_URL` is set (scratch schema).

## Job queue schema (pg-boss), enqueue-only API role (ADR 0038)

pg-boss keeps jobs in its own schema (`pgboss`, or `PGBOSS_SCHEMA`), outside RLS. In production the schema is created by
the owner and the runtime roles get least privilege: `igaro_worker` full rights in that schema; `igaro_app` (the API) may
only enqueue (INSERT on `job`, SELECT of the `id` and `start_after` columns, SELECT on `queue` and `version`, EXECUTE on
`job_now()`), so it cannot read the content of any pending job.

```
pnpm db:migrate     # owner: creates the schema skeleton and default privileges (migration 20261128000000)
pnpm db:pgboss      # owner (DATABASE_URL): installs pg-boss, creates the queues, applies the grants. Idempotent.
```

Re-run `pnpm db:pgboss` after every pg-boss upgrade (the owner applies pg-boss's own migrations). The API and worker run
with `PGBOSS_SCHEMA_MODE=external` (the production default): they create and migrate nothing and fail at start if the schema
is missing. Outside production the default is `auto` (pg-boss installs itself), so local dev needs no extra step. Invite,
reset and holder-delivery jobs are sealed with `DELIVERY_PAYLOAD_KEY`; set it on both the API and the worker.
