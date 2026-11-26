# ADR 0021: Verification algorithm is a pure function in packages/core

Status: Accepted (recommended option taken under the owner's standing permission)

## Decision
`verifyCredential` (packages/core/src/verify.ts) takes the loaded record and key and returns `{ result, reason, alertOps }`,
following invariant 7 exactly. Security-review hardening, all fail-closed:
1. The signed payload is bound to its row: `payload.credentialId === record.id`, `payload.institutionId === record.institutionId`,
   and the key's `kid` and `institutionId` must equal the payload's. Otherwise VERIFICATION_FAILED with an ops alert, so a
   genuine signed payload cannot be copied into another row or tenant.
2. Any record status other than ACTIVE/SUSPENDED/REVOKED/SUPERSEDED, or key status other than ACTIVE/RETIRED/COMPROMISED,
   is VERIFICATION_FAILED.
3. A compromised key fails without an ops alert (known condition); integrity failures alert.

## Consequences for T-032
The API must pass `id`/`institutionId`, never return `reason` publicly (it separates DRAFT from unknown), build the
SUPERSEDED link from the new credential's verification token (not its UUID), and write the hashed-IP verification log.
