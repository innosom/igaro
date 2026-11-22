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
