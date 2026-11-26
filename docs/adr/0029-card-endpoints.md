# ADR 0029: card enqueue and card endpoints (T-040)

Status: accepted. Every choice below is the recommended option, taken under the owner's standing permission.

## Review fixes (security review of T-040)
- M1: expiry is read from the signed payload (`payload.expiresAt`), never the unsigned `expires_at` column; test added.
- L1: integrity is checked before status and expiry (invariant 7), so tampered non-ACTIVE rows also raise `card.integrity_failure`.
- Open Low: L2 compare payload `issuerKeyId` with row `issuer_kid` (same pattern as verify.ts); L3 AWS S3 may answer 403 for a missing key without ListBucket (shows as 503); L4 cards of revoked credentials stay in storage (scoped S3 keys, T-039 M2).

## Context
T-039 (ADR 0028) renders cards in the worker and stores them under `institutions/<inst>/credentials/<id>/card.{png,pdf}`.
T-040 queues the render after issuance and lets an institution admin download the stored card.

## Decisions
1. **Enqueue after commit, never failing issuance.** `POST /credentials` and `POST /credentials/:id/reissue` call
   `enqueueCardAfterCommit` once the tenant transaction has committed. Reissue queues the NEW credential only. A queue error is
   logged as `card.enqueue_failed` with ids and the error class name (no message, no payload) and the request still returns 201.
   The card is regenerable, so a lost job is a degraded state, not data loss. The job carries ids only (ADR 0028).
2. **Interface and wiring.** `CardRenderQueue` (`enqueue({institutionId, credentialId})`) lives in `apps/api/src/notifications.ts`
   with `NoopCardRenderQueue` (default) and `MemoryCardRenderQueue` (tests, with a `fail` switch). `buildApp({cardRender})`. The
   pg-boss implementation is `PgBossCardRenderQueue` in `apps/worker/src/card-render-producer.ts`, which uses
   `enqueueCardRender` and creates the queue with `CARD_RENDER_QUEUE_OPTIONS`. `connectProducerQueues` opens ONE producer-only
   pg-boss connection and creates both the account-mail and card-render queues; `server.ts` uses it when `ACCOUNT_MAIL_QUEUE=pgboss`
   (otherwise both queues are no-ops). `connectAccountMailQueue` stays exported for compatibility.
3. **Serve only what verifies.** `GET /credentials/:id/card.png|card.pdf` (INSTITUTION_ADMIN; tenant from the session; RLS plus an
   `institution_id = app_institution_id()` filter). Before any storage access the row is re-checked with `@igaro/core`
   `verifyCredentialIntegrity`: SHA-256(JCS(payload)) must equal the stored `data_hash` and the signature must verify under the
   issuer key's public key, plus `payload.credentialId` equals the row id and `payload.institutionId` equals the session tenant, and the
   key is not COMPROMISED (RETIRED still verifies). A failure logs the ops alert `card.integrity_failure` (ids only) and answers the
   same 404 as an unknown id, so a tampered row is neither served nor distinguishable. This closes ADR 0028 follow-up L3.
4. **Status policy: 404, not 409.** Only a stored ACTIVE credential that has not expired has a card endpoint. SUSPENDED, REVOKED,
   SUPERSEDED, DRAFT and EXPIRED answer the same `404 NOT_FOUND` as unknown, foreign and malformed ids. It is the safest option
   (one uniform answer, no status oracle, no stale card of a revoked credential handed out from a link or bookmark). The dashboard
   already shows the status from `GET /credentials/:id`. The card of a reinstated credential works again, since the files are kept.
5. **Redirect, not stream.** If the object exists (`ObjectStorage.exists`, a signed HEAD on S3, a map lookup in memory), the
   answer is `302` with `Location` = a signed GET URL valid 60 s, `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.
   The URL is a bearer credential: it is never logged (only ids and format are).
6. **Not ready is not a dead link.** If the card is missing the answer is `404 CARD_NOT_READY` with `Retry-After: 15`. A storage
   error on the HEAD or signing is `503 STORAGE_UNAVAILABLE` (logged with ids only). Storage not configured is `503`; this is checked after
   the integrity check, so unknown ids still return 404 and nothing is revealed about a deployment without storage.
7. **`ObjectStorage.exists`** is added to the interface, `S3ObjectStorage` (SigV4 HEAD; 404 is false, anything else not OK throws
   `StorageError` without echoing detail) and `MemoryObjectStorage` (`failExists` for tests).
8. **Holder view unchanged.** `links.card` in `GET /holder/:holderToken` stays `null`. T-042 owns the holder card route, which must
   apply the same checks (status, integrity) with the holder token as the credential instead of an admin session.
9. **Tests.** The API's vitest config aliases `@igaro/worker/producer` to the worker source so tests need no prior build
   (the package export points at `dist`). `card-endpoints.test.ts`: enqueue (ids only, after reissue the new id, nothing on a failed
   issue, failure swallowed and logged without the message), 302 for both formats, `no-store`, URL not logged, not ready,
   cross-tenant/unknown/malformed identical 404, non-ACTIVE and expired 404, tampered payload/hash/signature never served with an
   ops alert, COMPROMISED key refused, 503 without storage and on storage failure, 401 without a session, 403 for platform admin;
   S3 HEAD behaviour; worker producer unit tests.

## Not done here
Delivery email with the holder link (T-041), the holder card route (T-042), deleting stored cards of revoked credentials
(they are unreachable through the API; a lifecycle cleanup is optional hardening), a re-render endpoint for a card that never
arrives (an admin can reissue; a "re-render" action is a possible follow-up).
