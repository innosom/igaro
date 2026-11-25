# ADR 0014: Audit entry hash encoding, lifecycle rules in core

Status: accepted (recommended option taken under the owner's standing permission)

## Decisions
1. `entry_hash = hex(SHA-256( ascii(prev_hash) || utf8(JCS(content)) ))`. `prev_hash` is 64 lowercase hex chars; the first entry of a chain uses 64 zeros. `content` = `{institutionId, seq (decimal string), actorId, action, targetType, targetId, metadata, ip (already hashed), createdAt}`. `createdAt` is the exact ISO-8601 UTC millisecond string the API hashed and must be stored and returned unchanged (T-024: write it explicitly, do not rely on the DB default; reviewer M3). A golden test pins the format; changing it needs a new chain version.
2. The lifecycle table in `packages/core` mirrors the DB trigger: SUSPENDED -> REVOKED is NOT allowed (reinstate first), matching CLAUDE.md invariant 4. Reviewer M4 (revoke straight from SUSPENDED) is left to the owner as a post-MVP question, since it needs an invariant and trigger change.
3. `isExpired` fails closed: a non-strict-ISO `expiresAt` counts as expired.
4. `AnchorService` + `NoopAnchorService` (always NOT_ANCHORED); nothing depends on a chain.

## Follow-ups
T-024 must write `createdAt` explicitly and normalise metadata round-trips. Reissue `reason` (docs/api.md) is optional in core.
