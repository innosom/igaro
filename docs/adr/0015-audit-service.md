# ADR 0015: Audit service design (T-024)

Status: accepted (recommended option taken under the owner's standing permission)

## Decisions
1. `appendAudit(client, input)` in `apps/api/src/audit.ts` runs inside the caller's transaction, so the audited change and its entry commit or roll back together. Writers to one chain are serialised with `pg_advisory_xact_lock(hashtextextended('igaro.audit:<institutionId|platform>', 0))`; the DB's `UNIQUE NULLS NOT DISTINCT (institution_id, seq)` and `(institution_id, prev_hash)` are the backstop.
2. Institution create, suspend and reinstate (platform admin actions) are written to the affected institution's own chain, with the suspension `reason` in `metadata`. The reason is no longer put in structured logs. Choice taken: the institution's admins can read it (audit of all actions); making it platform-only would need a separate chain and is left open.
3. Audit metadata is JSON round-tripped before hashing, and keys matching `token|secret|password|salt|private|key|cookie|authorization` are refused (invariant 9). Key-lifecycle audits (T-017 follow-up) must use names such as `kid`, not `keyId`.
4. IP is stored only as the keyed hash (ADR 0003); `createdAt` is written explicitly (ADR 0014).
5. Free-text `reason` input rejects control characters and lone surrogates (400) because JSONB cannot store them.
6. Gotcha recorded: when selecting `seq::text AS seq`, `ORDER BY` must be `audit_logs.seq`, otherwise it sorts the text alias lexically.

## Follow-ups
Future tenant-scoped callers must pass the session's institution id. `verifyAuditChain` compares only the chain; the signed-head comparison arrives with T-027/T-028.
