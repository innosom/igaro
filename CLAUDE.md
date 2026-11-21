# iGARO — shared project context

Source of truth: `iGARO MVP Technical White Paper v1.0.pdf` (Nov 21, 2026). It replaces the v0 paper.
`iGARO-Architecture-Review.md` explains why. If the two disagree, **v1.0 wins**.
Plain-text copy for agents: `docs/spec/whitepaper-v1.0.txt`.

## What we are building
A multi-tenant SaaS platform for institutions to issue, manage, suspend, revoke and publicly verify
digital credentials. Every credential is Ed25519-signed by its institution. **No blockchain in the MVP**,
but the hooks for Phase 1 anchoring are built now.

## Repo layout (monorepo, TypeScript everywhere)
```
igaro/
  apps/web/          Next.js + React + Tailwind: dashboard, public /v/:token, holder /h/:token
  apps/api/          Fastify REST API under /api/v1 — the ONLY component that signs
  apps/worker/       pg-boss jobs: email, card render (headless Chrome), CSV+ZIP import, daily head hash
  packages/core/     RFC 8785 canonicalize, SHA-256, Ed25519 sign/verify, lifecycle rules, AnchorService
  packages/db/       Prisma schema, migrations, RLS policies, triggers
  tools/verify-cli/  open-source independent verifier (no iGARO API calls)
  docs/              architecture.md, threat-model.md, api.md, adr/, acceptance/
```
Stack: PostgreSQL + Prisma + RLS, pg-boss, Node built-in `crypto` (Ed25519, SHA-256, AES-256-GCM),
MinIO/S3, Resend/SES (Mailpit locally), Docker Compose (Postgres, Mailpit, MinIO).

## Non-negotiable invariants (every agent)
1. **Signing:** `dataHash = SHA-256(JCS(payload))`; `signature = Ed25519(key, "igaro.credential.sig.v1:" + dataHash)`.
   Payload schema `igaro.credential.v1` includes `credentialNumber`, `issuerKeyId`, `holder.photoSha256`, and a 256-bit `salt`.
   Status, tokens and branding stay OUTSIDE the payload. Changing canonical output requires a new `schemaVersion`.
2. **One shared crypto package** (`packages/core`) used by API, worker and CLI. Golden tests must stay byte-identical forever.
3. **Identifiers:** internal UUID `id`; human `credential_number` (never used for lookup); 128-bit `verification_token`
   (only thing in QR/URL); separate `holder_token`. Session/invite/reset tokens are stored only as hashes.
4. **Lifecycle:** DRAFT → ACTIVE; ACTIVE ↔ SUSPENDED; ACTIVE → REVOKED (terminal); ACTIVE → SUPERSEDED via reissue (terminal,
   links to new). EXPIRED is computed at read time. A DB trigger refuses any change out of REVOKED. Status changes only
   through `credential_events`. Credentials are never deleted. Signed data is never edited in place — corrections are reissues.
   Revoke and suspend require a reason (stored in the audit log).
5. **Tenancy, two layers:** the data-access layer takes `institution_id` from the session, never the request; Postgres RLS
   backs it up. Cross-tenant reads/writes return 404 — and tests prove it.
6. **Audit log:** append-only at DB level (no UPDATE/DELETE grants), hash-chained (`entry_hash = SHA-256(prev_hash ‖ entry)`),
   written one at a time per institution under a DB lock. Daily head hash is signed and timestamped with OpenTimestamps.
7. **Verification order:** NOT FOUND → integrity/signature (VERIFICATION FAILED + ops alert) → key compromised (FAILED) →
   REVOKED/SUSPENDED/SUPERSEDED → EXPIRED → institution suspended (VALID WITH WARNING) → VERIFIED.
   Integrity is always checked before status. Every check logged with a hashed IP.
8. **Keys:** one Ed25519 key pair per institution with a `kid`; private key AES-256-GCM-encrypted under a master key held
   outside the DB; public keys at `/i/:slug/keys.json` with ACTIVE/RETIRED/COMPROMISED.
9. **Never log** a private key, salt, or any token.
10. **Blockchain hooks:** `AnchorService` interface with `NoopAnchorService`; `credential_events` outbox; `anchor_status`
    column (`NOT_ANCHORED`); data-driven proof panel. Nothing in the MVP may depend on a chain.

## Out of scope for the MVP
Blockchain anchoring, mobile app, holder accounts/wallets, DIDs/W3C VC, Apple/Google Wallet, MFA, SSO, extra roles,
custom domains, offline QR, AI/biometrics, advanced analytics, any token/NFT/DAO. Roles: Platform Admin, Institution Admin only.

## Agent team (`.claude/agents/`)
| Agent | Owns |
|---|---|
| `igaro-architect` | plan, ADRs, threat model, acceptance criteria, API contract; coordinates the others |
| `igaro-platform` | monorepo, CI, Docker Compose, `packages/db` (Prisma, RLS, triggers, grants), seeds |
| `igaro-crypto-core` | `packages/core` + `tools/verify-cli` + golden tests |
| `igaro-api` | `apps/api`: auth, tenancy, institutions, keys, holders, types, issuance, lifecycle, audit, verify |
| `igaro-worker` | `apps/worker`: email, card PNG/PDF, CSV+ZIP import, daily head-hash signing + OpenTimestamps |
| `igaro-web` | `apps/web`: dashboard, verification page + proof panel, holder page |
| `igaro-qa` | cross-tenant, tamper, lifecycle, E2E demo-script and p95 performance tests |
| `igaro-security-reviewer` | read-only review against the invariants above before anything is called done |

## Running on GitHub
The team runs unattended in GitHub Actions (`.github/workflows/igaro-build.yml`): each run does one task from
`docs/plan.md` and opens a PR labelled `igaro-build`, and the reviewer agent reviews and merges it. Agents never push to `main`,
never edit `.github/` (put CI changes in `docs/ci-proposals.md`), and never commit secrets.
The reviewer agent (`igaro-review.yml`, every 30 min) reviews and tests each build PR, fixes small issues, and merges only
when it approves and tests pass; otherwise it labels the PR `needs-human` for the owner.
`@claude` in an issue or PR comment reaches the team interactively (`claude.yml`).

Build order (5 weeks): W1 platform+auth+threat model → W2 institutions/keys/holders/types → W3 crypto core, issuance,
lifecycle, events, audit chain → W4 verification, keys.json, CLI, rate limits → W5 cards, email, CSV import, dashboard, staging, demo test.
