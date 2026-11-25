# ADR 0010: Holders, photo handling and image allow-lists (T-018)

Status: accepted. Every choice below is the recommended option, taken under the owner's standing permission.

## Context
T-018 adds holder CRUD and photo upload. It also had to close the two Medium findings the reviewer raised against T-016's
`image.ts`: the JPEG cleaner copied everything after the first SOS verbatim (metadata between scans and trailing data survived),
and the PNG cleaner was a deny-list with no CRC check or dimension cap.

## Decisions
1. **PNG is an allow-list.** Kept: IHDR, PLTE, tRNS, IDAT, IEND, gAMA, sRGB. All other ancillary chunks (text, eXIf, tIME, iCCP,
   pHYs, private chunks) are dropped. An unknown *critical* chunk is rejected, since dropping it could change the picture.
   Every chunk's CRC-32 (`node:zlib` `crc32`) is verified, including chunks that will be dropped, so a corrupt file is refused
   rather than silently repaired. IHDR must be first and 13 bytes, IDAT chunks contiguous, IEND empty, and anything after IEND is cut.
   Palette and colour chunks after IDAT are dropped.
2. **JPEG walks scan by scan.** Entropy-coded data is scanned for the next real marker (FF00 stuffing and RSTn are data), so
   headers between scans pass through the same filter as headers before the first scan. The file ends at the first EOI and
   everything after it is cut. A frame header (SOF) and at least one scan are required; a second SOF is rejected. Kept: tables
   (DQT, DHT, DRI, DNL), ICC profile, Adobe colour-transform segment. JFIF is reduced to its 16-byte header with the embedded
   thumbnail zeroed (thumbnails can carry their own metadata); JFXX and all other APPn and COM segments are dropped.
   The earlier `ICC_PROFILE` check compared 12 bytes including the NUL and never matched; it now matches the 11-character tag.
3. **Dimension cap.** Read from IHDR / SOF before storing: at most 10 000 px per side and 40 000 000 px total, zero rejected.
   This bounds decompression cost for whoever renders the image later (card render, browsers). No image library, no re-encode.
   Not decoded here, so a file whose compressed data does not match its header is not detected; the renderer must not trust it.
4. **Shared upload reader (`uploads.ts`).** Logo and photo routes use one function, so the type sniffing, size, structure and
   error codes cannot drift apart. `PHOTO_MAX_BYTES` defaults to 2 MB (max 10 MB); logos stay at 1 MB.
5. **`photoSha256` is the SHA-256 of the stored bytes** (after stripping), hex, computed in the API in the same request. It is
   what the credential payload will commit to (`holder.photoSha256`). The storage key is `institutions/<session institution>/holders/<holder id>/photo/<uuid>.<ext>`;
   the key is never returned, reads use a 300 s signed URL.
6. **Replacing a photo deletes the old object** after the DB commit (as logos do). Credentials issued earlier keep the old
   `photoSha256` inside their signed payload, so their photo no longer matches the holder's current file. That is accepted: a
   photo correction is a reissue (invariant 4). The card renderer (T-039) must therefore render an old credential's card from
   the data it needs at issue time or accept the replaced photo; flagged as a follow-up. Alternative (keep every version) needs a
   photo-history table and a migration; not taken for the MVP.
7. **Delete is allowed only without credentials.** `DELETE /holders/:id` locks the holder row, counts credentials (any status),
   and refuses with 409 `HOLDER_HAS_CREDENTIALS`. The composite FK `ON DELETE RESTRICT` is the backstop (23503 maps to the same 409).
   Holders with no credentials can be deleted because nothing signed refers to them. The existing grants already allow DELETE.
8. **Emails are trimmed and lower-cased in the API**, matching the DB check constraint. `externalId` uniqueness per institution
   returns 409 `DUPLICATE_EXTERNAL_ID`. Unknown body or query properties are rejected (400), as for the institution PATCH.
9. **List API:** `limit` (1-200, default 50) and `offset`, newest first, plus `q` substring search with LIKE wildcards escaped.
   Offset paging is enough for the MVP size (500 holders per import); switch to keyset paging if lists grow.
10. **No migration.** `credential_holders` columns, RLS policy, e-mail check, unique indexes and grants already exist.
11. **Audit.** Holder create/update/delete/photo are logged with ids and field names only (no names, emails or values) and carry
    `TODO(T-024)` until the audit service exists.

## Known gap
`DELETE` with `Content-Type: application/json` and an empty body is refused by Fastify (400) before auth runs, as for other
bodyless routes; clients must omit the header on bodyless requests. Not changed here.
