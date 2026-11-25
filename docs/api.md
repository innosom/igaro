# REST API contract, /api/v1

Conventions: JSON; session via httpOnly Secure cookie; mutating requests require CSRF header. Tenant endpoints derive institution from the session; foreign or unknown ids return 404. Errors: `{ "error": { "code", "message" } }`. Roles: PA = Platform Admin, IA = Institution Admin. Lists paginate with `?cursor=&limit=`.

## Auth
| Method Path | Who | Notes |
|---|---|---|
| POST /auth/login | anyone | email+password; rate limited; sets cookie |
| POST /auth/logout | any | |
| GET /auth/me | any | user, role, institution |
| POST /auth/invites/accept | invitee | token + new password |
| POST /auth/password-reset | anyone | two modes: `{email}` request (always 202), `{token,password}` confirm |

## Institutions (PA)
| GET /institutions | list; `?limit` (1-200, default 50) and `?cursor`; returns `{items:[{id,name,slug,status,createdAt,updatedAt,activeKid}], nextCursor}` (ordered by creation; `nextCursor` null on the last page) |
| POST /institutions | create `{name, slug, adminEmail}` in one transaction: institution, ACTIVE Ed25519 key (private key wrapped under the master key), first-admin invite; invite mail is enqueued after commit. 201 `{institution, inviteQueued}`. Slug: 3-40 chars `[a-z0-9-]`, no leading/trailing hyphen (400 `INVALID_SLUG`); duplicate slug 409 `SLUG_TAKEN`; admin email already registered 409 `EMAIL_IN_USE`; no master key configured 503 `KEY_CUSTODY_UNAVAILABLE` |
| PATCH /institutions/:id/status | `{status: ACTIVE|SUSPENDED, reason}`; `reason` required (1-500 chars) for SUSPENDED (400 `REASON_REQUIRED`). Idempotent. Returns the institution. Unknown or malformed id 404 |
All three: Platform Admin only (401 unauthenticated, 403 Institution Admin); PATCH/POST need the CSRF header like every authenticated mutation.

## Own institution (IA)
| GET /institution | own profile: `{id, name, slug, status, cardTitle, primaryColor, secondaryColor, publicFields, hasLogo, updatedAt}`. Never returns the logo key or any URL (private bucket) |
| PATCH /institution | any non-empty subset of `{cardTitle, primaryColor, secondaryColor, publicFields}`; returns the profile. `cardTitle`: 1-100 chars, no control characters, or `null` to clear (400 `INVALID_CARD_TITLE`). Colours: exactly `#rrggbb` (400 `INVALID_COLOR`), stored lower-case. `publicFields`: array drawn from `photo`, `idNumber`, `attributes` (name and status always show and are not configurable); duplicates collapse, stored in that canonical order, `[]` clears (400 `INVALID_PUBLIC_FIELDS`). Any other property, including `id`, `institutionId`, `name`, `slug`, `status`, `logoKey`: 400 `UNKNOWN_PROPERTY`, nothing written. Empty body: 400 |
| POST /institution/logo | `multipart/form-data` with exactly one file part named `file` and no text fields. PNG or JPEG decided from magic bytes (client content-type and file name ignored): 415 `UNSUPPORTED_IMAGE_TYPE` otherwise; damaged structure or empty file 400; over `LOGO_MAX_BYTES` (default 1 MB) 413 `PAYLOAD_TOO_LARGE`; not multipart 415. Metadata (EXIF, XMP, text chunks, comments) is stripped before storing. Stored in the private bucket under `institutions/<institutionId>/logo/<random uuid>.<png|jpg>`; the previous logo object is deleted. Returns the profile (`hasLogo: true`). Storage not configured or failing: 503 `STORAGE_UNAVAILABLE` and the logo is unchanged |
| GET /institution/keys | `{items}`: kid, algorithm, publicKey, status, createdAt, retiredAt. Never private key material |
| POST /institution/keys/rotate | 201 `{active, retiredKid}`: new ACTIVE key, previous ACTIVE becomes RETIRED, one transaction. 503 `KEY_CUSTODY_UNAVAILABLE` without master key |
| POST /institution/keys/:kid/compromise | body `{reason}` (required, 400 `REASON_REQUIRED`). Marks the key COMPROMISED (terminal, idempotent); if it was ACTIVE a replacement ACTIVE key is created in the same transaction. Returns `{key, replacement, previous}`. Unknown or other-tenant kid: 404 |
GET/PATCH/logo: Institution Admin only (401 unauthenticated, 403 Platform Admin); PATCH and POST need the CSRF header. The institution is always the session's; ids or tenant hints in the body, query or headers are ignored or rejected.

## Holders (IA)
Institution Admin only (401 unauthenticated, 403 Platform Admin); mutating routes need the CSRF header. The institution is always the session's. Another tenant's holder id, an unknown id and a malformed id are all 404 `NOT_FOUND` with the same body. Responses are `Cache-Control: no-store`.
Holder view: `{id, fullName, externalId, email, hasPhoto, photoSha256, credentialCount, createdAt, updatedAt, photoUrl?}`. The storage key is never returned. `photoSha256` is the SHA-256 (hex) of the stored, metadata-stripped photo bytes. `photoUrl` is a signed GET URL valid 300 s, present only on single-holder responses (GET/PATCH/photo) when the holder has a photo and storage is configured.

| Route | Behaviour |
|---|---|
| GET /holders | `?q=` (case-insensitive substring of name, external id or email; max 100 chars; `%` and `_` are literal), `?limit=` (1-200, default 50), `?offset=`. Returns `{items, total, limit, offset}` newest first. Other query parameters: 400 `UNKNOWN_PROPERTY` |
| POST /holders | `{fullName, externalId?, email?}` -> 201 holder. `fullName` required, 1-200 chars, trimmed (400 `INVALID_FULL_NAME`). `externalId` 1-100 chars or `null` (400 `INVALID_EXTERNAL_ID`), unique per institution (409 `DUPLICATE_EXTERNAL_ID`). `email` valid address, trimmed and lower-cased, or `null` (400 `INVALID_EMAIL`). Any other property (`institutionId`, `id`, `photoKey`, ...): 400 `UNKNOWN_PROPERTY` |
| GET /holders/:id | holder with `photoUrl` |
| PATCH /holders/:id | non-empty subset of `{fullName, externalId, email}`; same validation; `null` clears `externalId` and `email`; empty body 400 |
| DELETE /holders/:id | 204. 409 `HOLDER_HAS_CREDENTIALS` when the holder has any credential in any status (credentials are never deleted). The photo object is removed after the delete |
| POST /holders/:id/photo | `multipart/form-data`, exactly one file part named `file`, no text fields. Same rules as the logo: type from magic bytes (415 `UNSUPPORTED_IMAGE_TYPE`); damaged file, bad PNG CRC, dimensions over 10 000 px per side or 40 MP, or empty: 400; over `PHOTO_MAX_BYTES` (default 2 MB): 413; not multipart: 415. Metadata is stripped and trailing data cut (see Image handling), the SHA-256 of the stored bytes is saved as `photoSha256`, the object goes to the private bucket under `institutions/<institutionId>/holders/<holderId>/photo/<random uuid>.<png or jpg>`, and a previous photo object is deleted. Returns the holder. The holder is checked first (404 before the body is read). Storage not configured or failing: 503 `STORAGE_UNAVAILABLE`, photo unchanged |

Image handling (logo and photo): PNG keeps only IHDR, PLTE, tRNS, IDAT, IEND, gAMA, sRGB; other ancillary chunks are dropped, an unknown critical chunk is rejected, every CRC is verified, IDAT must be contiguous, bytes after IEND are cut. JPEG: EXIF/XMP/other APPn and comments are dropped everywhere (including between scans), JFIF is reduced to its 16-byte header (no thumbnail), ICC and Adobe segments are kept, a frame header and at least one scan are required, and everything after EOI is cut. See ADR 0010.

## Credential types (IA)
Institution Admin only; other tenants' ids are 404. Response shape: `{id, code, name, kind, attributes[{key,label,type: string|date|number,required}], defaultValidityDays, credentialCount, createdAt, updatedAt}`.
| GET /credential-types | `{items}` of the session institution's types |
| GET /credential-types/templates | built-in `STUDENT_ID` and `CERTIFICATE` templates |
| POST /credential-types | `{code, name, kind: ID_CARD|CERTIFICATE, attributes, defaultValidityDays}`, or `{template, ...overrides}`. `code` is `^[A-Z][A-Z0-9_]{1,39}$`, unique per institution (409 `DUPLICATE_TYPE_CODE`); attribute keys are camelCase `^[a-z][A-Za-z0-9]{0,49}$`, unique, at most 30, Object.prototype names reserved. 201 |
| GET /credential-types/:id | one type |
| PATCH /credential-types/:id | `name`, `attributes`, `defaultValidityDays` only; `code` and `kind` are immutable (400) |
| DELETE /credential-types/:id | 204; 409 `TYPE_HAS_CREDENTIALS` if any credential uses it |

Editing attributes never changes issued credentials: each signed payload carries its own attributes. See ADR 0011.

## Credentials (IA)
| GET /credentials | `?status` (DRAFT, ACTIVE, SUSPENDED, REVOKED, SUPERSEDED, EXPIRED; EXPIRED is computed from ACTIVE past `expiresAt`, and ACTIVE excludes expired), `?type` (type code), `?q` (case-insensitive substring of credential number or holder name, max 100, wildcards literal), `?limit` (1-200, default 50), `?cursor`. Returns `{items:[{id, credentialNumber, status, holder:{id,fullName}, type:{code,name}, issuedAt, expiresAt, supersededBy, createdAt}], nextCursor}` newest first. Bad parameter 400 (`INVALID_STATUS`, `INVALID_TYPE`, `INVALID_SEARCH`, `INVALID_LIMIT`, `INVALID_CURSOR`, `UNKNOWN_PROPERTY`). ADR 0018 |
| POST /credentials | `{holderId, credentialTypeCode, attributes, expiresAt?}` -> 201 signed ACTIVE credential (`id, credentialNumber, payload, dataHash, signature, issuerKeyId, verificationToken, holderToken`; `holderToken` is returned only here). 404 unknown/foreign holder or type; 409 `HOLDER_PHOTO_REQUIRED`, `NO_ACTIVE_KEY`, `INSTITUTION_SUSPENDED`; 503 `KEY_CUSTODY_UNAVAILABLE`. See ADR 0016 |
| GET /credentials/:id | list fields plus `storedStatus, attributes, dataHash, signature, issuerKeyId, anchorStatus, events[{id,type,payload,createdAt}]`. Never returns the verification token, holder token or hash, or the salt (so not the whole payload). Foreign, unknown or malformed id: 404 |
| POST /credentials/:id/suspend | `{reason}` required (400 `REASON_REQUIRED`). 200 `{id, credentialNumber, status, previousStatus}`; 404 unknown/foreign; 409 `INVALID_TRANSITION`. ADR 0017 |
| POST /credentials/:id/reinstate | optional `{reason}`; SUSPENDED -> ACTIVE; 409 otherwise |
| POST /credentials/:id/revoke | `{reason}` required; terminal; ACTIVE only |
| POST /credentials/:id/reissue | `{reason, attributes?, expiresAt?}` (omitted fields inherited); 201 `{credential, previous}`; ACTIVE old -> SUPERSEDED, REVOKED old stays REVOKED and the new one links to it (`ALREADY_REISSUED` 409 on repeat) |
| POST /credentials/import | multipart CSV + ZIP; `?dryRun=true` returns preview; otherwise creates batch job (202) |
| GET /credentials/:id/card.png, card.pdf | rendered card |
Illegal transitions return 409. Idempotency-Key header supported on issue.

## Dashboard and audit (IA)
| Route | Behaviour |
|---|---|
| GET /dashboard/stats | `{total, byStatus:{DRAFT,ACTIVE,SUSPENDED,REVOKED,SUPERSEDED,EXPIRED}}`, EXPIRED computed, all keys always present |
| GET /audit-logs | own chain, newest first; `?limit` (1-200, default 50), `?cursor`; `{items:[{id,seq,actorId,action,targetType,targetId,metadata,createdAt,prevHash,entryHash}], nextCursor}`; hashed IP not returned |
| GET /audit-logs/verify-chain | `{valid, entries, head?, brokenAtSeq?, reason?, headsRecorded, signedHeads:{checked,matched,mismatchedDays}}`. Recomputes the chain and checks each signed daily head is still in it; no head rows: `headsRecorded:false`. Head signatures and OTS proofs are not checked here (ADR 0018) |

All IA only, `Cache-Control: no-store`.

## Public (rate limited per IP and per token)
| GET /verify/:verificationToken | `{result: VERIFIED|VALID_WITH_WARNING|SUSPENDED|REVOKED|SUPERSEDED|EXPIRED|NOT_FOUND|VERIFICATION_FAILED, institution, holder (per publicFields), type, status, issuedAt, expiresAt, supersededBy?, proof:{signedBy, kid, anchorStatus}}` |
| GET /verify/:verificationToken/credential.json | `{payload, dataHash, signature, kid, publicKeysUrl}` for verify-cli |
| GET /i/:slug/keys.json | `{keys:[{kid, alg:"Ed25519", publicKey, status, createdAt, retiredAt}]}` (served at site root path /i/..., not under /api/v1) |
| GET /holder/:holderToken | holder view: card links, credential file (private link) |

Rate-limit exceeded: 429 with Retry-After. Unknown tokens always 200 NOT_FOUND-shaped or 404 with identical timing.
