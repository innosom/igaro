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
| GET /institutions | list |
| POST /institutions | create `{name, slug, adminEmail}`; generates key, sends invite |
| PATCH /institutions/:id/status | `{status: ACTIVE|SUSPENDED, reason}` |

## Own institution (IA)
| GET /institution | |
| PATCH /institution | branding (card title, two colours), `publicFields` |
| POST /institution/logo | multipart; private storage |
| POST /institution/keys/rotate | new ACTIVE key, previous RETIRED |

## Holders (IA)
GET/POST /holders; GET/PATCH /holders/:id; POST /holders/:id/photo (multipart, EXIF stripped, photoSha256 stored).

## Credential types (IA)
GET/POST /credential-types: `{code, name, kind: ID_CARD|CERTIFICATE, attributes[], defaultValidityDays}`.

## Credentials (IA)
| GET /credentials | filter `status, type, q`; status is computed (EXPIRED) |
| POST /credentials | `{holderId, credentialTypeCode, attributes, expiresAt?}` -> signed ACTIVE credential |
| GET /credentials/:id | includes events |
| POST /credentials/:id/suspend | `{reason}` required |
| POST /credentials/:id/reinstate | |
| POST /credentials/:id/revoke | `{reason}` required; terminal |
| POST /credentials/:id/reissue | `{attributes?, expiresAt?, reason}`; old -> SUPERSEDED, returns new |
| POST /credentials/import | multipart CSV + ZIP; `?dryRun=true` returns preview; otherwise creates batch job (202) |
| GET /credentials/:id/card.png, card.pdf | rendered card |
Illegal transitions return 409. Idempotency-Key header supported on issue.

## Dashboard and audit (IA)
GET /dashboard/stats (counts by status); GET /audit-logs; GET /audit-logs/verify-chain (compares chain with signed daily heads).

## Public (rate limited per IP and per token)
| GET /verify/:verificationToken | `{result: VERIFIED|VALID_WITH_WARNING|SUSPENDED|REVOKED|SUPERSEDED|EXPIRED|NOT_FOUND|VERIFICATION_FAILED, institution, holder (per publicFields), type, status, issuedAt, expiresAt, supersededBy?, proof:{signedBy, kid, anchorStatus}}` |
| GET /verify/:verificationToken/credential.json | `{payload, dataHash, signature, kid, publicKeysUrl}` for verify-cli |
| GET /i/:slug/keys.json | `{keys:[{kid, alg:"Ed25519", publicKey, status, createdAt, retiredAt}]}` (served at site root path /i/..., not under /api/v1) |
| GET /holder/:holderToken | holder view: card links, credential file (private link) |

Rate-limit exceeded: 429 with Retry-After. Unknown tokens always 200 NOT_FOUND-shaped or 404 with identical timing.
