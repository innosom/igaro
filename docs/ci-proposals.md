# CI proposals

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
