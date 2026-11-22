# iGARO build plan

Source of truth: `docs/spec/whitepaper-v1.0.txt`. One task per run, in order, respecting deps.
Format: `- [ ] T-NNN [owner: agent] [deps: ids|none] description`. Tick the box when merged.
Acceptance criteria per milestone: `docs/acceptance/`.

## W1 Platform, auth, threat model
- [x] T-001 [owner: igaro-platform] [deps: none] Monorepo scaffold (pnpm workspaces, TS config, lint, type-check, test scripts, empty app/package skeletons)
  - Done: pnpm workspace scaffold with 6 skeleton packages; build, typecheck, lint, test pass. Web is a TS placeholder (Next.js comes with T-035). Follow-ups: pnpm onlyBuiltDependencies allowlist, exclude tests from build tsconfig.
- [x] T-002 [owner: igaro-platform] [deps: T-001] Docker Compose (Postgres, Mailpit, MinIO) and .env.example
  - Done: docker-compose.yml (Postgres 16, Mailpit, MinIO + private bucket init), .env.example, docs/dev-setup.md. Not run (no Docker in CI runner). Follow-ups: pin image versions; apps must use APP_DATABASE_URL and fail on superuser/placeholder MASTER_KEY.
- [ ] T-003 [owner: igaro-platform] [deps: T-001] Draft CI workflow proposal in docs/ci-proposals.md (lint, type-check, tests)
- [ ] T-004 [owner: igaro-platform] [deps: T-002] Prisma schema for all v1.0 tables (incl. credential_events, audit_logs, anchor_status)
- [ ] T-005 [owner: igaro-platform] [deps: T-004] Initial migration with RLS policies per tenant table and restricted app DB role
- [ ] T-006 [owner: igaro-platform] [deps: T-005] DB triggers (REVOKED is final, status change only via credential_events) and append-only audit_logs grants
- [ ] T-007 [owner: igaro-platform] [deps: T-005] Seed data (platform admin, demo institution, two credential type templates)
- [ ] T-008 [owner: igaro-api] [deps: T-005] Fastify scaffold under /api/v1, config, log redaction, tenant-scoped data-access layer (institution_id from session)
- [ ] T-009 [owner: igaro-api] [deps: T-008, T-007] Auth: login, logout, me with Argon2id and hashed httpOnly cookie sessions
- [ ] T-010 [owner: igaro-api] [deps: T-009] Invite accept, password reset, login rate limiting
- [ ] T-011 [owner: igaro-worker] [deps: T-005, T-002] Worker scaffold (pg-boss) and invite/reset email jobs to Mailpit
- [ ] T-012 [owner: igaro-qa] [deps: T-006, T-009] Cross-tenant test harness and RLS/trigger/append-only DB tests
- [ ] T-013 [owner: igaro-security-reviewer] [deps: T-010, T-012] W1 security review against invariants and docs/threat-model.md

## W2 Institutions, keys, holders, types
- [ ] T-014 [owner: igaro-crypto-core] [deps: T-001] AES-256-GCM key wrapping and Ed25519 key pair generation with kid
- [ ] T-015 [owner: igaro-api] [deps: T-010, T-011, T-014] Platform admin: create/list institutions, suspend/unsuspend, invite first admin; per-institution key generation
- [ ] T-016 [owner: igaro-api] [deps: T-015] Own institution GET/PATCH (branding, public-field settings) and logo upload to private storage
- [ ] T-017 [owner: igaro-api] [deps: T-015] Signing key rotation (old key RETIRED) and mark-compromised
- [ ] T-018 [owner: igaro-api] [deps: T-015] Holders CRUD, photo upload with EXIF strip and SHA-256 photoSha256
- [ ] T-019 [owner: igaro-api] [deps: T-015] Credential types CRUD with attribute lists; STUDENT_ID and CERTIFICATE templates
- [ ] T-020 [owner: igaro-qa] [deps: T-016, T-017, T-018, T-019] Cross-tenant 404 tests for institutions, keys, holders, types
- [ ] T-021 [owner: igaro-security-reviewer] [deps: T-020] W2 review (key custody, photo handling, tenancy)

## W3 Trust core, issuance, lifecycle, audit
- [ ] T-022 [owner: igaro-crypto-core] [deps: T-014] JCS canonicalize, SHA-256 dataHash, Ed25519 sign/verify with domain prefix, payload schema igaro.credential.v1, golden tests
- [ ] T-023 [owner: igaro-crypto-core] [deps: T-022] Lifecycle state machine, audit hash-chain helpers, AnchorService and NoopAnchorService
- [ ] T-024 [owner: igaro-api] [deps: T-023, T-006, T-008] Audit log service: per-institution DB lock, hash chain, append-only writes
- [ ] T-025 [owner: igaro-api] [deps: T-022, T-024, T-018, T-019, T-017] Single issuance in one transaction (payload, salt, sign, ACTIVE, event, audit, tokens, credential number)
- [ ] T-026 [owner: igaro-api] [deps: T-025] Suspend, reinstate, revoke (reasons required), reissue (SUPERSEDED link) via credential_events
- [ ] T-027 [owner: igaro-api] [deps: T-025] Credentials list/get with search and filter, dashboard stats, audit-logs, verify-chain endpoints
- [ ] T-028 [owner: igaro-worker] [deps: T-024, T-011] Daily audit head hash job: sign and timestamp with OpenTimestamps, store proof
- [ ] T-029 [owner: igaro-qa] [deps: T-026, T-027, T-028] Tamper, lifecycle, REVOKED-final, audit-chain-vs-signed-head and cross-tenant tests for credentials
- [ ] T-030 [owner: igaro-security-reviewer] [deps: T-029] W3 review (signing, canonicalization, audit chain, no secrets in logs)

## W4 Verification, keys.json, CLI
- [ ] T-031 [owner: igaro-crypto-core] [deps: T-022, T-023] Verification algorithm in packages/core following invariant 7 order
- [ ] T-032 [owner: igaro-api] [deps: T-031, T-026] Public GET /verify/:token and credential.json, hashed-IP verification log, per-IP and per-token rate limits, ops alert on failure
- [ ] T-033 [owner: igaro-api] [deps: T-017] Public /i/:slug/keys.json and GET /holder/:holderToken
- [ ] T-034 [owner: igaro-crypto-core] [deps: T-031] tools/verify-cli independent verifier (no iGARO API calls) with tests
- [ ] T-035 [owner: igaro-web] [deps: T-010] apps/web scaffold, Tailwind, login, invite accept and password reset pages
- [ ] T-036 [owner: igaro-web] [deps: T-032, T-033, T-035] Public /v/:token page with all result states and data-driven proof panel (Not anchored)
- [ ] T-037 [owner: igaro-qa] [deps: T-032, T-033, T-034] Verify p95 under 300 ms, URL enumeration/rate-limit tests, CLI-vs-API agreement, DB tamper returns FAILED
- [ ] T-038 [owner: igaro-security-reviewer] [deps: T-036, T-037] W4 review (verification order, rate limits, CSP, enumeration)

## W5 Cards, email, import, dashboard, staging, demo
- [ ] T-039 [owner: igaro-worker] [deps: T-025, T-016] Card render job: HTML template to PNG and PDF via headless Chrome with QR
- [ ] T-040 [owner: igaro-api] [deps: T-039] card.png and card.pdf endpoints, enqueue render and delivery jobs after issuance
- [ ] T-041 [owner: igaro-worker] [deps: T-039, T-033] Holder delivery email with private /h/:token link
- [ ] T-042 [owner: igaro-web] [deps: T-033, T-040, T-035] Private holder page /h/:token (card and credential file download)
- [ ] T-043 [owner: igaro-api] [deps: T-025, T-011] POST /credentials/import: CSV + photo ZIP validate/preview and batch job creation
- [ ] T-044 [owner: igaro-worker] [deps: T-043, T-041] CSV + ZIP import batch job (500 holders with photos, issue, email each)
- [ ] T-045 [owner: igaro-web] [deps: T-027, T-035, T-016, T-017] Dashboard: branding, keys, holders, types, issue form, lifecycle actions, credential list, status counts, audit view
- [ ] T-046 [owner: igaro-web] [deps: T-043, T-015, T-045] CSV import preview UI and platform-admin screens
- [ ] T-047 [owner: igaro-platform] [deps: T-044, T-003] Staging deployment config, production hardening notes, CI proposals update
- [ ] T-048 [owner: igaro-qa] [deps: T-044, T-046, T-042, T-036] Playwright E2E demo script, 500-holder import test, no-secrets-in-logs test
- [ ] T-049 [owner: igaro-security-reviewer] [deps: T-047, T-048] Final review against all invariants and section 15 success criteria
