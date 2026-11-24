# ADR 0002: Holder token stored only as a hash; enum values for status, events and verification

Status: Accepted (owner decision on PR #5, 2026-11-24)

## Context
The white paper (§7) generates a separate holder token for the private holder page `/h/:token`, but does not
say how it is stored. It also does not list the enum values for credential status, lifecycle events or
verification results. T-004 (Prisma schema) needed both.

## Decision
1. **Holder token is stored only as a SHA-256 hash** (`credentials.holder_token_hash`), like session, invite and
   reset tokens. The issuance transaction generates a 128-bit token and stores its hash. The clear token is passed only to
   the holder-email job and must be removed from the job's stored data once the email is sent. It is never logged.
   `GET /holder/:holderToken` looks up by `SHA-256(token)`. "Resend link" generates a new token, which replaces the hash
   and invalidates the old link. The verification token stays in clear, because the QR code and card render need it.
2. **Enum values** (accepted as proposed):
   - Credential status: `DRAFT`, `ACTIVE`, `SUSPENDED`, `REVOKED`, `SUPERSEDED`. `EXPIRED` is not stored; it is computed at read time.
   - Lifecycle events: `ISSUED`, `SUSPENDED`, `REINSTATED`, `REVOKED`, `REISSUED`.
   - Verification results: `NOT_FOUND`, `VERIFICATION_FAILED`, `KEY_COMPROMISED`, `REVOKED`, `SUSPENDED`,
     `SUPERSEDED`, `EXPIRED`, `VALID_WITH_WARNING`, `VERIFIED`. `KEY_COMPROMISED` is shown to verifiers as
     VERIFICATION FAILED, and is kept separate only in logs.

## Consequences
- A database read cannot open any holder's page.
- An admin cannot see or copy an existing holder link. Re-sending a link always issues a new one.
