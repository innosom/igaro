# ADR 0008: Own-institution profile and private object storage (T-016)

Status: accepted. Every choice below is the recommended option, taken under the owner's standing permission.

## Context
T-016 adds `GET/PATCH /institution` and `POST /institution/logo`. The white paper leaves three things open: which fields
an institution can choose to show publicly, how to talk to S3/MinIO, and how to accept uploads.

## Decisions
1. **Public-field allow-list: `photo`, `idNumber`, `attributes`.** The white paper says name and status always appear and photo,
   ID number and attributes are optional. Stored in `institutions.public_fields` (JSONB array), deduplicated and kept in that
   canonical order. Adding a field later is a code change to one constant plus the verify endpoint (T-0xx); no migration.
2. **No migration.** The init migration already has the columns, the hex-colour CHECK constraints, the tenant SELECT/UPDATE
   policies, and an UPDATE column grant covering exactly these columns. `status` is guarded by a trigger, and PATCH does not
   accept it anyway.
3. **Strict PATCH.** Unknown properties are rejected (400 `UNKNOWN_PROPERTY`) rather than ignored, so a client that sends
   `institutionId` or `status` finds out. Colours must match `#rrggbb` and are lower-cased. `cardTitle` may be cleared with `null`.
4. **S3 client: hand-written SigV4 over `fetch`, no AWS SDK.** Three operations (PUT, DELETE, presigned GET) need about 100 lines
   of `node:crypto`; `@aws-sdk/client-s3` would add dozens of transitive packages to a security-sensitive service. The signer is
   checked against the AWS documented presigned-URL test vector. Works path-style (MinIO) and virtual-hosted (AWS). Errors are
   a fixed `StorageError` that never carries the URL, headers or response body. If more S3 features are needed (multipart
   upload, ListObjects), switch to the SDK instead of extending the signer.
5. **Upload parsing: `@fastify/multipart` (new dependency).** Hand-rolling multipart parsing is riskier than the dependency. It is
   registered only in the encapsulated scope of the logo route, with `files: 1`, `fields: 0`, `parts: 2` and `fileSize` =
   `LOGO_MAX_BYTES`. Text fields before the file are refused; parts after the file are not read.
6. **Content is judged by bytes.** Type comes from PNG/JPEG magic bytes. The file is then re-walked structurally and EXIF, XMP,
   text, timestamp and comment segments are dropped (the white paper requires EXIF stripped for photos and logos); malformed
   structure is rejected. Pixel data is copied untouched, so there is no decode or re-encode and no image library. SVG, GIF and
   anything else is refused (SVG can carry script). The stored object gets the sniffed content type.
7. **Object keys are server-generated:** `institutions/<session institution id>/logo/<random uuid>.<ext>`. Nothing from the
   request reaches the key. Each upload gets a new key (so a cached signed URL never serves a replaced logo), the DB points at
   it first, and only then is the previous object deleted (best effort; a failure is logged and leaves an orphan, not a broken logo).
   If the DB update fails, the new object is deleted.
8. **Private by default.** The API never returns the key or a URL; the profile only says `hasLogo`. `ObjectStorage.signedGetUrl`
   exists for later tasks (card render, dashboard preview) and is capped at 7 days by S3; callers should ask for minutes.
9. **Configuration.** `S3_ENDPOINT`, `S3_REGION`, `S3_BUCKET`, `S3_ACCESS_KEY`, `S3_SECRET_KEY`, `S3_FORCE_PATH_STYLE` (already in
   `.env.example`) plus `LOGO_MAX_BYTES` (default 1 MB, max 10 MB). All S3 variables unset means no storage: the API still
   starts and logo upload answers 503. Partial S3 settings, placeholder secrets and a non-https endpoint in production are
   startup errors that name the variable but never print it.
10. **Audit.** No audit mechanism exists yet, so PATCH and logo changes log a structured line (actor, institution, changed field
    names, never values or keys) with `TODO(T-024)` to move into the hash-chained audit log in the same transaction.
11. **Tests.** Memory storage for API tests; real Postgres as `igaro_app` for RLS. Cross-tenant, 401/403, CSRF, bad colours,
    bad types, oversize, EXIF stripping, storage failure and log hygiene are covered.

## Open follow-ups
- A retention job for orphaned logo objects (if a post-commit delete fails).
- Rate limiting on uploads (not specified for authenticated routes yet).
