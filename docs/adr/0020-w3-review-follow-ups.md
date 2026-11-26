# ADR 0020: W3 review outcome and follow-ups

Status: accepted (recommended option taken under the owner's standing permission)

## Decisions
- Key rotation and mark-compromised require password re-entry, are limited to 10/hour per institution, and write key.rotated / key.compromised audit entries in the same transaction (ADR 0012 decision 3). The compromise reason is kept out of application logs.
- Suspended institutions cannot rotate keys or upload photos/logos (ADR 0012 decision 4). Marking a key compromised stays allowed while suspended: it is an emergency safety action.
- Holder, credential type and branding changes are audited in the same transaction (field names only, no PII values; photo changes carry SHA-256).

## Open follow-ups (Medium/Low)
- M: the limiter counts wrong passwords per institution, so a stolen session could lock out a real admin's compromise call for an hour. Count failures per (institution, user).
- M: log a warn (actor, institution, hashed IP) on failed password re-entry.
- L1 worker should verify the last signed head is still in the chain before signing, and alert. L2 trigger pinning anchor_status to NOT_ANCHORED. L4 rate limit verify-chain. L5 worker startup should refuse superuser/bypassrls/owner roles. L6 strip bidi override characters from holder names. Logo audit entry should include SHA-256. Limiter is per-process (ADR 0005).
