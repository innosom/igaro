# ADR 0028: card.render job (T-039)

Status: accepted. Every choice below is the recommended option, taken under the owner's standing permission.

## Review fixes (security review of T-039)
- CHROME_NO_SANDBOX=true is refused when NODE_ENV=production.
- Logo key must start with institutions/<institutionId>/logo/, otherwise no logo is drawn.
- Queue expiry raised to 300 s.
- Correction: --host-resolver-rules only affects hostnames; request interception and the CSP block literal-IP requests.
- Follow-ups: scoped worker S3 credentials; T-040 verifies the signature before serving a card.

## Context
`card.render` turns an issued credential into a PNG and a PDF card (ID card or certificate) with institution branding, the
holder photo, and a QR code to the public verification page. The API (T-040) will enqueue it and serve the stored files; email
delivery (T-041) will link to them. The worker never signs and never holds key material (v1.0 section 5).

## Decisions
1. **Job contract.** Queue `card.render`, payload `{institutionId, credentialId}` (ids only, no token, no holder data). The
   contract and `enqueueCardRender()` live in `card-render-job.ts` and are re-exported from `@igaro/worker/producer`. Queue
   policy `short` plus `singletonKey = card.render:<credentialId>`: at most one queued render per credential. Retries: 5, 30 s,
   exponential backoff. Re-rendering overwrites the same keys, so a retry or a repeat is harmless. Concurrency 1 (one browser at a time).
2. **Headless Chrome through `puppeteer-core`** (no bundled browser download). The executable comes from `CHROME_PATH`, else the
   first existing of `/usr/bin/chromium`, `/usr/bin/chromium-browser`, `/usr/bin/google-chrome`. `CHROME_NO_SANDBOX=true` adds
   `--no-sandbox` for containers without user namespaces (off by default). One short-lived browser per job, so nothing is shared
   between credentials or tenants. The job is registered only if S3 and Chrome are both found (otherwise a startup warning, so existing
   deployments keep starting); once configured in production it also requires `WORKER_DATABASE_URL` (the igaro_worker login).
3. **QR holds only `<VERIFY_BASE_URL>/v/<verification_token>`.** `VERIFY_BASE_URL` defaults to `https://verify.igaro.app` in
   production and to `WEB_BASE_URL` elsewhere. `assertVerifyUrl` refuses anything that is not exactly an http(s) `/v/<16-128
   base64url>` URL (no query, fragment, credentials or extra path), so no credential data can be added later by mistake. The QR is
   an inline SVG made from the module matrix (`qrcode-generator`, level M). The card text is "Verify only at <host>".
4. **Photo only if the hash matches.** The stored photo is used only when SHA-256 of the stored bytes equals the signed
   `payload.holder.photoSha256`, and the bytes are a PNG, JPEG or WebP by magic bytes. Otherwise the card shows a neutral
   placeholder and logs `photo: omitted` (no key, no hash). This covers ADR 0010 point 6: an old credential whose holder photo was
   replaced no longer matches, so its card has no photo rather than showing an unsigned one. The photo is never taken from the
   holder row's own `photo_sha256`.
5. **Card text comes from the signed payload** (full name, external ID, credential number, dates, attributes), not from the mutable
   holder row, so the card shows what the institution signed. Credential type name and kind (layout) come from `credential_types`;
   branding (name, logo, two colours, `card_title`) from `institutions`. Only ACTIVE credentials render; others return
   `skipped_not_active` (the job completes). An unknown credential or tenant mismatch throws `CardRenderNotFoundError` and retries
   (the enqueue may race the issuing commit).
6. **Escaping and no network.** Every text value goes through `esc()` (HTML-escapes, and strips control, bidi and zero-width
   characters). Colours are re-emitted only as `#rgb`/`#rrggbb`, else defaults. Images are `data:` URLs built from sniffed bytes.
   The document has a CSP meta (`default-src 'none'; img-src data:; style-src 'unsafe-inline'`). The renderer also disables
   JavaScript, intercepts every request and aborts anything that is not `data:`/`about:blank` (counted, logged as a number), and starts Chrome with
   `--host-resolver-rules=MAP * ~NOTFOUND`. Three layers, so one template bug cannot reach the network.
7. **Output.** PNG at device scale 2 (ID card 856x540 CSS px, certificate 1123x794) and a one-page PDF of the same size. Keys:
   `institutions/<institutionId>/credentials/<credentialId>/card.png` and `card.pdf`, `Content-Type` set, in the private bucket.
   T-040 reads these keys (short signed URL or streamed through the API after its own tenancy check).
8. **Storage.** The API's `ObjectStorage` has no `get`, and apps must not import each other, so the worker has a small
   `WorkerObjectStorage {get, put}` with `S3WorkerStorage` (SigV4 via `node:crypto` and `fetch`, same `S3_*` variables as the API,
   MinIO path-style supported) and an in-memory version for tests. It duplicates about 60 lines of the API's signer; moving both into
   a shared package is a follow-up. No local-disk storage: the API has none either, and the photo must come from the same bucket.
9. **Database access and a new grant (migration `20261127000000_worker_card_render_grants`).** Each job opens a transaction,
   `SET LOCAL ROLE` (tests only), sets `app.institution_id` from the job and reads under RLS. The worker role gets column-level
   SELECT only: `credentials` (id, institution_id, holder_id, type_id, credential_number, status, payload, verification_token,
   issued_at, expires_at), `credential_holders` (id, institution_id, full_name, external_id, photo_key, photo_sha256),
   `credential_types` (id, institution_id, name, kind). No signature, data hash, holder token hash, e-mail, key tables or writes. The
   existing tenant policies apply to the role unchanged. `audit-head-worker.test.ts` now asserts these limits.
10. **Logging.** Only ids, outcome and counts. The verification token, salt, photo and keys never reach a log (the pino redact list
    and err serializer remain a second line).
11. **Tests.** Unit: escaping and injection, colour sanitising, QR content and URL refusal, photo hash match and mismatch, signed
    payload binding, job contract, config, handler with a fake pool. Integration (Postgres): tenant scoping, column grants, photo
    mismatch, status skip; with Chrome present: real PNG and PDF plus proof that non-`data:` requests are blocked and never reach a local server.
    Chrome tests skip when no Chrome exists.

## Not done here
Enqueueing after issuance and the card endpoints (T-040), the delivery email (T-041), bulk import (rendering 500 cards one browser
at a time is slow; reuse one browser across a batch if it matters), a shared storage package, deleting stored cards on photo
replacement or reissue (a reissue gets its own credential id and so its own keys).
