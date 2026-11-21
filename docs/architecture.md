# iGARO architecture (MVP, v1.0)

## Components
- `apps/web` Next.js: dashboard, public `/v/:token`, holder `/h/:token`.
- `apps/api` Fastify under `/api/v1`: the only component that signs. Decrypts an institution's private key with the master key only at signing time.
- `apps/worker` pg-boss (queue in Postgres): emails, card render (headless Chrome), CSV+ZIP import, daily head hash + OpenTimestamps.
- `packages/core`: JCS, SHA-256, Ed25519, AES-256-GCM wrap, lifecycle rules, verification algorithm, audit-chain helpers, AnchorService.
- `packages/db`: Prisma schema, migrations, RLS, triggers, grants.
- `tools/verify-cli`: independent verifier, no iGARO API calls.
- Infra: PostgreSQL, MinIO/S3 (private; short-lived signed links), Resend/SES (Mailpit locally).

## Data flow: issuance (one DB transaction)
validate against type attributes -> generate id, credential_number, 128-bit verification_token, holder_token -> build payload with fresh salt and photo hash -> canonicalize/hash/sign with ACTIVE key -> insert ACTIVE credential + `credential_events(ISSUED)` + audit entry (per-institution advisory lock). After commit: enqueue card render, holder email, (Phase 1) anchor.

## Tenancy
Every tenant table has `institution_id`. Layer 1: data-access layer takes it from the session. Layer 2: RLS using a per-transaction setting. Cross-tenant access returns 404. Only platform-admin users/sessions have null institution.

## Lifecycle
DRAFT -> ACTIVE; ACTIVE <-> SUSPENDED; ACTIVE -> REVOKED (terminal); ACTIVE -> SUPERSEDED (terminal, `superseded_by`). EXPIRED computed at read time from signed `expiresAt`. Status changes only by inserting `credential_events`; a trigger refuses any change out of REVOKED. Credentials are never deleted.

## Audit log
`entry_hash = SHA-256(prev_hash || canonical(entry))`, written serially per institution under a lock; app DB role has INSERT/SELECT only. Daily job signs the head hash with the platform key and obtains an OpenTimestamps proof; `verify-chain` recomputes the chain and compares to signed heads, catching recomputed-chain insiders.

## Verification (invariant 7)
NOT FOUND -> integrity/signature (FAILED + ops alert) -> key COMPROMISED (FAILED) -> REVOKED/SUSPENDED/SUPERSEDED -> EXPIRED -> institution suspended (VALID WITH WARNING) -> VERIFIED. Every check logged with salted-hash IP. Rate limited per IP and per token.

## Phase 1 hooks
`AnchorService` (noop), `credential_events` outbox with `anchored_at`, `anchor_status`, proof panel driven by data. Phase 1 adds `chain_operations` and `anchors` tables only.

## Logging
Redact private keys, salts, session/invite/reset/verification/holder tokens everywhere.
