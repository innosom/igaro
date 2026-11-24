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
Migrations and seeds (`pnpm db:migrate`, `pnpm db:seed`) arrive with `packages/db`.

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
