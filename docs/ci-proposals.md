# CI proposals

## P-004 (T-047, ADR 0035): deny /api/v1/internal at the ingress
Defence in depth only (the app already refuses it). In the staging/production ingress config return 404 for
`/api/v1/internal/`. No `.github/` change is needed for T-047.

Agents cannot edit `.github/`. Proposed changes are described here for the owner to apply.

## P-001: Quality gate workflow (T-003)

Check the existing `.github/workflows/ci.yml` against this proposal. If it already runs the
same steps, no action is needed. Otherwise add or merge:

```yaml
name: ci
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

jobs:
  check:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    services:
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_USER: postgres
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: igaro_test
        ports: ["5432:5432"]
        options: >-
          --health-cmd "pg_isready -U postgres"
          --health-interval 5s --health-timeout 5s --health-retries 10
    env:
      # Test-only values. Never put real secrets here.
      DATABASE_URL: postgresql://postgres:postgres@localhost:5432/igaro_test
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4   # version comes from packageManager in package.json
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: pnpm
      - run: pnpm install --frozen-lockfile
      - run: pnpm lint
      - run: pnpm typecheck
      - run: pnpm build
      - run: pnpm test
      - run: pnpm audit --prod --audit-level=high
```

Notes:
- DB-backed tests (T-012) will need a migrate step before `pnpm test`; add it when T-005 lands.
- Pin third-party actions to commit SHAs once the owner chooses a policy.
- Follow-up for `docker-compose.yml` (not under `.github/`): pin the `mailpit`, `minio` and `mc` image tags instead of `latest`.

## T-048: Playwright demo script (proposal, not applied)

`tools/e2e` (`@igaro/e2e`) holds the Playwright demo script. It is not run by `pnpm test` (the package has no `test`
script). Suggested separate workflow, nightly and on demand against a local compose stack (never staging: steps 12-13 need a Postgres superuser) with Postgres, MinIO,
Mailpit, API, worker and web started, never on every PR:

```yaml
name: igaro-e2e
on:
  workflow_dispatch:
  schedule: [{ cron: "30 3 * * *" }]
jobs:
  e2e:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22, cache: pnpm }
      - run: pnpm install --frozen-lockfile
      - run: pnpm --filter @igaro/e2e exec playwright install --with-deps chromium
      # bring up the stack here (docker compose up -d; migrate; seed; start api, worker, web) and wait for /api/v1/health
      - run: pnpm e2e
        env:
          E2E_BASE_URL: http://127.0.0.1:3000
          E2E_PLATFORM_EMAIL: ${{ secrets.E2E_PLATFORM_EMAIL }}
          E2E_PLATFORM_PASSWORD: ${{ secrets.E2E_PLATFORM_PASSWORD }}
          E2E_IMPORT_ROWS: "500"
          E2E_DATABASE_URL: postgresql://postgres:postgres@127.0.0.1:5432/igaro   # throwaway compose Postgres only (test value); NEVER a staging secret
```

Do not upload `tools/e2e/test-results/`: traces and screenshots can contain one-time tokens in URLs.
The existing `pnpm install --frozen-lockfile` step needs the updated `pnpm-lock.yaml` (adds `@playwright/test`).
