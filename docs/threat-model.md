# iGARO threat model (MVP)

| # | Threat | Mitigation in MVP | Residual / Phase 1 |
|---|---|---|---|
| 1 | Forged or edited card/PDF | Ed25519 signature; verification page recomputes hash; photo hash signed | none |
| 2 | Insider edits DB row | Integrity checked before status -> VERIFICATION FAILED + alert; REVOKED-final trigger; append-only hash-chained audit with signed, timestamped daily head | Per-credential external timestamp waits for Phase 1 anchoring |
| 3 | Insider rewrites whole audit chain | Daily head hash signed + OpenTimestamps; verify-chain compares to heads | Up to 24h window of undetected tail edits |
| 4 | Compromised server / master key | Private keys AES-256-GCM under master key outside DB; decrypt only at signing; KMS in production; key marked COMPROMISED fails all its credentials | Server compromise can sign fraudulently until detected; HSM/KMS Phase 1 |
| 5 | URL enumeration | 128-bit random verification token; credential number never a lookup key; per-IP and per-token rate limits | none |
| 6 | Phishing / fake QR | Card text "Verify only at verify.igaro.app"; QR holds URL only | User behaviour |
| 7 | Stolen admin account | Argon2id, login rate limiting, httpOnly Secure cookies, hashed session tokens, audit of all actions | MFA/SSO out of scope (Phase 1) |
| 8 | Stolen institution signing key | Rotation, retired/compromised states in keys.json | Credentials by compromised key must be reissued |
| 9 | Cross-tenant access | Session-derived institution_id + RLS (ENABLE + FORCE, non-owner app role, column-level UPDATE grants, ON UPDATE RESTRICT FKs); 404 tests | M2: scope is a plain session setting (`app.institution_id`, `app.is_platform_admin`, lookup settings). Anyone who can run arbitrary SQL as the app role (SQL injection, a compromised API process) can set them and read or write any tenant, so RLS backs up the data-access layer and does not replace it. Superusers and BYPASSRLS roles skip RLS entirely. |
| 10 | Dictionary guess of hash from name+ID | 256-bit salt in payload | Salt deletion unlinks person |
| 11 | Replay of signature in another context | Domain prefix `igaro.credential.sig.v1:` | none |
| 12 | Secrets in logs | Redaction, QA test | none |
| 13 | Photo/EXIF leakage, file abuse | Private storage, signed short-lived links, EXIF stripped, type/size limits; CSV/ZIP path-traversal and zip-bomb limits | none |
| 14 | Revocation status trust | Status served by iGARO only | On-chain status Phase 1 |
| 15 | XSS/CSRF | CSP, SameSite cookies, CSRF token on mutating requests, no browser storage of sessions | none |
