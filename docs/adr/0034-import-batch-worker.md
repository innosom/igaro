# ADR 0034: import batch worker, `import.batch` (T-044)

Status: accepted. Every choice below is the recommended option, taken under the owner's standing permission.

## Context
T-043 (ADR 0033) validates a CSV plus an optional photo ZIP, stores the sources and queues an ids-only `import.batch` job.
T-044 consumes it: per row create or reuse the holder with its photo, issue the credential, queue the card render and the
holder email, record per-row results, survive row failures and retries, and handle 500 holders. ADR 0033 pointed at "the
API's internal service-authenticated batch-issue path (not part of T-043)". It did not exist, and it cannot live in the
worker: the API is the only component that unwraps institution keys and signs (v1.0 section 5, ADR 0019), and the worker cannot
import the API (the API imports the worker's producer entry).

## Decisions
1. **Split by trust.** The worker orchestrates and handles untrusted files; the API does every database write and all
   signing. Worker: read the job, re-validate and sanitise photos, call the API once per row, finish the batch, delete the
   stored sources. API: create or reuse the holder, store the photo, call `issueInTransaction` (the same function as
   `POST /credentials`: signing, `credential_events` outbox row, audit entry identical to single issuance), mark the row,
   queue card render and holder delivery after commit. The worker gets no new database grant and no migration; it still
   never holds a key, salt or master key.
2. **Internal endpoints** (`apps/api/src/import-internal.ts`, under `/api/v1/internal/import/batches/:id/`):
   `start` (batch to PROCESSING, returns row list as `{row, status, externalId, photo}`, plus the SHA-256 of the stored CSV and ZIP
   recorded in the `import.created` audit entry), `rows/:n` (process one row), `finish` (`{outcome: complete|failed}`: totals from
   the rows, COMPLETED or FAILED, `import.completed`/`import.failed` audit entry; `complete` is refused with 409 while rows are
   PENDING). All idempotent: a finished batch or row answers from its state and does nothing twice.
3. **Service authentication, not a session.** `Authorization: Bearer <INTERNAL_API_TOKEN>` (32-512 chars, constant-time compare of
   SHA-256 digests, checked in `onRequest` before the body is parsed). The endpoints are not registered when the token is
   unset; the API refuses a value equal to `MASTER_KEY`. Because there is no session, the institution id is in the body. This
   is the one place where tenancy input comes from a request, so it is only honoured together with the secret, every query
   still runs in `Db.withTenant` (RLS) with the `app_institution_id()` filter, and a batch that does not belong to that
   institution is 404 (tests prove it for all three calls). The row's values (name, external id, email, type, attributes,
   expiry) are read from `import_rows.data`, validated at intake; the body can only carry a photo or a fixed failure code.
4. **Photos: the worker re-checks, the API re-checks the worker.** ADR 0033 stores the original ZIP. The worker verifies the ZIP
   against the intake hash, reads it with the same defensive reader (flat names, declared-size caps, CRC, no ZIP64/encryption;
   a copy in `apps/worker/src/import-zip.ts`), requires `.jpg|.jpeg`, walks the JPEG structure, strips EXIF/XMP/comments/
   thumbnails/trailing data (copy of the JPEG half of `image.ts`, `import-photo.ts`) and hashes the exact bytes to store
   (`photoSha256`). It sends `{sha256, data}` base64. The API does not trust it: it sniffs JPEG, re-runs the strip and refuses
   the photo unless stripping is a no-op, and recomputes the hash. The object is stored content-addressed under
   `institutions/<inst>/holders/<holderId>/photo/<sha>.jpg`, the same key scheme as `POST /holders/:id/photo`. A previous photo
   no signed credential commits to is deleted after commit. Duplicated code is deliberate for now (see "Not done").
5. **Holder rules.** Matched by `externalId`. An existing holder is reused; a name that no longer matches is a row error
   `HOLDER_NAME_MISMATCH` (never overwritten). An email is set only when the holder has none. A `zip` photo replaces the holder's
   photo; a `holder` row uses the existing one (`HOLDER_PHOTO_REQUIRED` if it vanished).
6. **One transaction per row.** Holder, photo, credential, event, audit entries and the row update commit together. Any failure
   rolls the whole row back (no half-created holder); a photo object written for a holder that was rolled back is deleted.
7. **Failure classes.** A 4xx `AppError` raised while processing (name mismatch, unknown type, invalid expiry, suspended
   institution, no active key, missing photo, bad attribute) is a **row error**: the row becomes `ERROR` with the fixed code as
   text (no PII), the batch continues, `error_rows` is updated. Worker-found photo problems use the whitelisted codes
   `PHOTO_REQUIRED|PHOTO_INVALID|PHOTO_ARCHIVE_INVALID|PHOTO_SOURCE_MISSING|PHOTO_SOURCE_MISMATCH` through `rows/:n {fail}`.
   Anything else (database, storage, signing outage `KEY_CUSTODY_UNAVAILABLE` 503, network) is **transient**: nothing is
   written, the row stays PENDING, the worker counts it, stops the pass after 5 consecutive transient failures, and throws so
   pg-boss retries the job (3 retries, 60 s exponential backoff, ADR 0033 queue options). A retry skips IMPORTED and ERROR rows.
   On the last attempt (`job.retryCount >= job.retryLimit`, handler uses `includeMetadata`) the worker marks the batch FAILED
   (unprocessed rows remain PENDING and are visible in the status endpoint) and deletes the sources.
8. **Progress.** Every row transaction refreshes `imported_rows` and `error_rows` from the rows, so `GET /credentials/import/:id`
   shows live progress (`pendingRows`). `finish` recomputes the final totals.
9. **Email and card.** After each row commits the API calls the same `enqueueCardAfterCommit` and `enqueueDeliveryAfterCommit` as
   single issuance, so the sealed holder token (ADR 0030) never reaches the worker's import path. Holders without an email get
   no mail. Enqueue failures are logged by id and class only and never fail the row. The `email.deliver` singleton key per
   credential keeps delivery to one mail per credential. If the response to a row call is lost after the API committed, the
   retry sees IMPORTED and does not enqueue again: the raw holder token cannot be rebuilt (ADR 0002), so that one email can be
   missed. A resend-link action is the fix and is out of scope here.
10. **Sources are deleted.** After `finish` (complete or failed) the worker deletes `source.csv` and `photos.zip` (they hold personal
    data and the rows already hold what is needed). `WorkerObjectStorage` gained `delete`.
11. **Configuration.** Worker: `INTERNAL_API_URL` (API `/api/v1` base) + `INTERNAL_API_TOKEN` + `S3_*`; any missing means
    `import.batch` is not registered (startup warning); half-set URL/token is a `ConfigError` (messages never carry values). API:
    `INTERNAL_API_TOKEN`. `.env.example` documents both. The worker uses concurrency 1 (one batch at a time, serial rows): about
    10 ms of signing and database work per row, so 500 holders took under 5 s locally.
12. **Logging.** Ids, row numbers, counts and fixed codes only. `HttpImportApi` errors are generic (`ImportApiError(status)`):
    no URL, body or token. Tests assert that names, addresses, tokens, the bearer secret and photo metadata are absent from API
    and worker logs.
13. **Tests.** Worker unit (fake API): sanitising and hashing, bad photos, tampered/missing/hostile archives, transient and retry
    behaviour, consecutive-failure stop, finished batch, malformed job, 500 rows, HTTP client. Worker integration (real pg-boss):
    queued run, last-attempt FAILED, singleton enqueue, malformed payload dropped. API end to end (Postgres, RLS, the real worker
    consumer driving the real endpoints): auth, validation and hostile photos, tenancy 404s, row tolerance and rollback,
    idempotency, signing outage and retry, FAILED path, 500 holders with photos and an email each (credentials verify, photo hashes
    match, audit chain intact, one distinct holder link per holder).

## Not done / follow-ups
- `import-zip.ts` and the JPEG walk exist twice (API and worker). Move them to a shared package (core is crypto-core's) and delete the copies.
- No retention job for finished `import_rows` (PII under RLS) or for orphaned photo objects after a crash between storage and commit.
- No per-row audit entry beyond the issuance, holder and batch entries; no resend-link for a missed email (see 9).
- The internal secret is a single shared value without rotation overlap; rotate by deploying API and worker together after the queue drains.
- Internal endpoints have no rate limit (they are callable only with the secret); put the API's internal path behind the private network in staging (T-047).
