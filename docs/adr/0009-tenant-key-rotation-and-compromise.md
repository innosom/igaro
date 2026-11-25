# ADR 0009: Institution Admin key rotation and compromise (T-017)

Status: accepted. Every choice below is the recommended option, taken under the owner's standing permission.

## Context
`POST /institution/keys/rotate` is an Institution Admin endpoint, but the init migration made `institution_keys`
read-only for tenants (writes were platform scope only), so the API could not do it under RLS. The white paper does not say
what happens when the ACTIVE key is reported compromised.

## Decisions
1. **Tenant INSERT/UPDATE policies on own keys only** (migration `20261125010000_tenant_key_rotation`). The second layer
   (RLS) still pins every row to `app_institution_id()`; inserts must be `ACTIVE`. Column grants are unchanged: only
   `status` and `retired_at` can be updated, so `kid`, `public_key` and `encrypted_private_key` stay immutable. The alternative
   (routing through a platform-scope session) would have let the API act across tenants for a tenant action.
2. **Status trigger.** Status only moves forward (ACTIVE -> RETIRED | COMPROMISED, RETIRED -> COMPROMISED). COMPROMISED is
   final and no key can become ACTIVE again by UPDATE. This holds for every role, including the owner.
3. **One ACTIVE key.** Every key change locks the institution row (`FOR UPDATE`), so concurrent rotations serialise and leave
   exactly one ACTIVE key (a unique constraint refuses a second one; retire runs before insert).
4. **Compromising the ACTIVE key creates a replacement in the same transaction**, so the institution is never left without a
   signing key. Compromising a RETIRED key creates none. Repeating the call is a no-op (200, `replacement: null`).
5. **Reason required** to mark a key compromised (400 `REASON_REQUIRED`); for now it is recorded in a structured log line,
   moved to the audit log by T-024 (`TODO(T-024)`). Rotation needs no reason.
6. **No master key configured -> 503** `KEY_CUSTODY_UNAVAILABLE` for both writes. Responses carry the public key only.

## Consequences
- Signatures made with a COMPROMISED key must verify as FAILED (invariant 7) and RETIRED keys still verify; T-031/T-033 consume
  the status. Credentials signed by a compromised key need reissue (out of scope here).
- Old RETIRED keys are kept forever: credentials reference them by `(institution_id, kid)`.
