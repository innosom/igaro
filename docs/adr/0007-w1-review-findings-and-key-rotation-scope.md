# ADR 0007: W1 review findings and key-rotation scope

Status: accepted (recommended option taken under the owner's standing permission)

## Context
The T-013 W1 security review found no Critical or High issues (verdict: ship). It raised four Mediums.
White paper v1.0 (spec lines 342-345) lets Institution Admins rotate their own signing keys, but the
init migration allows tenants only SELECT on `institution_keys`.

## Decision
- **M4 (key rotation scope):** follow the white paper. T-017 adds tenant-scoped policies on `institution_keys`:
  INSERT for the own institution, and UPDATE limited to `status` and `retired_at` (no change to key material,
  `kid`, or the wrapped private key). The API must never set platform and tenant scope together to do this.
  A DB test must prove the narrow UPDATE and cross-tenant denial.
- **M1 (role check):** API and worker refuse to start if `current_user` is superuser, has BYPASSRLS, or owns
  any application table. Required before `ACCOUNT_MAIL_QUEUE=pgboss` is enabled outside dev (with T-015).
- **M2 (pg-boss tokens readable by igaro_app):** create an `igaro_worker` role and a pre-created pg-boss schema;
  `igaro_app` gets only enqueue rights, no SELECT on job tables. Required before T-015 enables real mail.
- **M3 (queue retention):** call `updateQueue` after `createQueue`, with a test starting from a default queue.

## Consequences
Lows are tracked in docs/plan.md under T-013. Nothing here weakens an invariant.
