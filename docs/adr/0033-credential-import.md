# ADR 0033: credential import intake (T-043)

Status: accepted. Every choice below is the recommended option, taken under the owner's standing permission.

## Context
W5 needs a CSV (plus optional ZIP of photos named by holder external ID) import of up to 1000 holders. T-043 is the API side:
validate, preview, record, enqueue. The worker (T-044) consumes the job and issues through the existing single-issue code path;
the API remains the only component that unwraps keys and signs. Intake never signs and never creates holders or credentials.

## Decisions
1. **Endpoints.** `POST /credentials/import` (multipart, file fields `csv` required and `photos` optional, Institution Admin only,
   `?dryRun=true|false`) and `GET /credentials/import/:id` (batch status; foreign, unknown and malformed ids are 404). Tenant from
   the session only; every query runs in `Db.withTenant` (RLS) and filters on `app_institution_id()`. A suspended institution
   gets 409 `INSTITUTION_SUSPENDED` (also for previews, `assertInstitutionActive`).
2. **Dry run writes nothing.** No DB write, no storage write, no audit entry, no job. It answers 200
   `{dryRun, totalRows, validRows, errorRows, photos:{provided, matched, unmatched}, rows:[{row, ok, holderExists, errors:[{column?, code, message}]}]}`.
   Row numbers are 1-based data rows (header excluded, blank lines skipped). Messages are fixed strings; cell contents, file
   names and ZIP entry names are never echoed or logged.
3. **All or nothing.** A real run with any invalid row answers 422 `IMPORT_VALIDATION_FAILED` with the same preview and writes
   nothing. Accepting partial batches would let a half-imported file be mistaken for a complete one; the preview exists so the
   admin fixes the file first. `import_rows.status = ERROR` is therefore only for failures at issuance time (written by T-044).
4. **Accepted run.** Stores `source.csv` and (if given) `photos.zip` privately under
   `institutions/<inst>/imports/<batch>/` (`importStorageKeys` in `@igaro/worker/producer`); `import_batches.source_key` is the CSV
   key and the ZIP key is derived. Then one tenant transaction (advisory lock per institution) inserts `import_batches`,
   all `import_rows` (status PENDING, `data` = normalised, validated values) and one audit entry `import.created` (counts and
   SHA-256 of the sources only, no PII). Storage objects are removed again if the transaction fails. After commit the job is
   enqueued; if that fails the batch is marked FAILED and the call answers 503 `QUEUE_UNAVAILABLE`. 202 returns
   `{batchId, status:'PENDING', totalRows, photos}`. No migration is needed: the init grants already cover these writes
   (INSERT on both tables, UPDATE of status/total/imported/error/completed on batches).
5. **Job contract** (`apps/worker/src/import-batch-job.ts`, exported from `@igaro/worker/producer`): queue `import.batch`,
   payload `{institutionId, batchId}` only (UUIDs; no tokens, no CSV content, no PII), singleton key per batch, retry 3 with
   backoff, 1 h expiry. `PgBossImportBatchQueue` and `createQueue` are wired into `connectProducerQueues`; the API has
   `ImportBatchQueue` with Noop (default, the batch stays PENDING) and Memory (tests) implementations. The consumer must be
   idempotent: skip rows already IMPORTED.
6. **Row semantics.** Columns: `fullName`, `externalId`, `credentialType` (code or type UUID) required; `email`, `expiresAt`
   (UTC `...Z`, future) optional; any other column must be an attribute key of one of the institution's types (else 400
   `UNKNOWN_COLUMN`; strict case-sensitive header, duplicates refused). Attributes are validated by `buildAttributes`, the very
   function single issuance uses, so a row that passes preview satisfies the same schema at issuance. A cell for an attribute that
   does not belong to the row's type is an error. Holders are matched by `externalId`: an existing holder is reused; a different
   full name is refused (`HOLDER_NAME_MISMATCH`) instead of silently overwriting identity data. Duplicate external IDs in one file
   are an error. A photo is required: a ZIP entry `<externalId>.jpg|.jpeg` (extension case-insensitive) or an existing holder
   photo; otherwise `PHOTO_REQUIRED`.
7. **Limits (defaults, overridable in tests via `buildApp`).** CSV 2 MiB, 1000 data rows, 40 columns, 1000 chars per cell; ZIP
   50 MiB, 1000 entries, 2 MiB per photo (the holder photo limit), 200 MiB total uncompressed; at most 3 active
   (PENDING/PROCESSING, last 24 h) batches per institution (409 `TOO_MANY_ACTIVE_IMPORTS`); 30 requests per hour per institution
   (previews included; `RateLimiter`, 429 with Retry-After). Limits apply to previews too.
8. **CSV injection safety.** Own RFC 4180 parser: comma delimiter, quotes, CRLF/LF, strict UTF-8 (BOM stripped, NUL refused),
   malformed quoting refused. Nothing is evaluated. Because the values are later rendered in cards, emails and possibly
   re-exported, free-text cells (`fullName`, `externalId`, string attributes) that begin with `= + - @` or TAB/CR are refused
   (`FORMULA_PREFIX`), also after leading whitespace. Numbers, dates, emails and `expiresAt` are strict formats instead.
9. **ZIP safety.** Own reader (no new dependency): central directory only, stored/deflate only, no encryption, no ZIP64, single
   disk. Flat names only: any `/`, `\`, control or format character, leading dot or trailing dot is refused as a whole-archive
   error (`ZIP_BAD_ENTRY_NAME`), so traversal, absolute paths, nested folders (including `__MACOSX/`) fail. The local header
   must agree with the central directory. Entry count, per-entry and total DECLARED sizes are checked before inflating; each
   inflation is capped at the declared size and must match it and its CRC, so a lying header cannot expand. Only JPEG is
   accepted (`.jpg|.jpeg` names, `ffd8ff` magic, and the existing `image.ts` structural walk with dimension caps). Only photos a
   row references are inflated; unreferenced entries are counted as `unmatched` and never decoded. Names are NFC-normalised for
   matching, duplicates (case-insensitive) refused.
10. **Status endpoint.** `{id, filename, status, totalRows, importedRows, errorRows, pendingRows, createdAt, completedAt,
    errors:[{row, error}]}` (up to 100 error rows, error text truncated to 200 chars). `filename` is the sanitised client name
    (control and format characters removed, directories stripped, 100 chars).

## For T-044 (worker)
- The API stores the ORIGINAL ZIP, not sanitised photos. The worker must run the same checks again before use (JPEG magic,
  EXIF/metadata stripping, `photo_sha256` over the stored bytes) and must not trust that the API pre-validated; the same
  zip-reading limits apply. Keeping that code in one shared place (move `image.ts` and `import-zip.ts` into `packages/core` or a
  shared package) is recommended; I did not move them to avoid touching the crypto-core's ownership.
- Rows hold `data` shaped as `ImportRowData` (`apps/api/src/credential-import.ts`). The worker creates or reuses the holder by
  `externalId`, sets the photo, and issues through the API's internal service-authenticated batch-issue path (not part of T-043).

## Not done / follow-ups
- The rate limiter and the active-batch cap are per process / per institution as in ADR 0005.
- Rows are stored with PII (`import_rows.data`) under RLS like holders; retention/cleanup of finished batches and their stored
  sources is not implemented.
