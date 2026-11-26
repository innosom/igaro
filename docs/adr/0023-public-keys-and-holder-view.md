# ADR 0023: Public keys.json and holder view

Status: Accepted (recommended option taken under the owner's standing permission)

## Decisions
1. **No migration.** Both endpoints use existing narrow lookup policies from the init migration: `app.institution_slug`
   (institutions) and `app.holder_token_hash` (credentials), via `Db.withLookup`. After the row is found, `app.institution_id`
   is set from it so the rest is read under the normal tenant policies. RLS is not widened.
2. **keys.json** is served at the site root `/i/:slug/keys.json` (not under `/api/v1`). Response `{keys:[{kid, alg:"Ed25519",
   publicKey, status, createdAt, retiredAt}]}` for every key of the institution (ACTIVE, RETIRED, COMPROMISED), oldest first.
   The query names its columns, so `encrypted_private_key` is never selected. Unknown or malformed slug: 404. Keys of a
   suspended institution are still published (verifiers need them). `Cache-Control: no-store` (safest: a compromise marking must
   reach verifiers at once; a CDN cache can be added later by a deliberate decision). Per-IP rate limit (hashed IP), same
   defaults as verify.
3. **Holder view** `GET /api/v1/holder/:holderToken`. The token must be 22 base64url characters; it is looked up by
   `SHA-256(token)` (ADR 0002), matched against `credentials.holder_token_hash`. Unknown, malformed, over-long and DRAFT: one
   identical 404 body. `Cache-Control: no-store` and `Referrer-Policy: no-referrer`. Per-IP limit on every request; per-token
   limit (keyed by the token's hash) counts only misses, as in ADR 0022. No verification_logs row (not a verification check).
4. **Scope of the view.** A holder token is issued with one credential and is stored on that credential, so the view returns
   exactly that credential (in a `credentials` array of one) and never other credentials of the same holder: a leaked link
   exposes the least possible. Fields: `holder.fullName`; institution `{name, slug, cardTitle, primaryColor, secondaryColor}`;
   per credential `{verificationToken, type, status (EXPIRED computed from expires_at), issuedAt, expiresAt, links}`. Not returned:
   ids, credential number, salt, payload, photo, attributes, the holder token. Status is informational; the verify page
   (`links.verify`) remains authoritative and re-checks integrity.
5. **Links.** `verify` (`/v/:token`), `credentialJson` (`/api/v1/verify/:token/credential.json`, the signed file), `publicKeys`.
   `card` is `null` for now: the holder-accessible card.png/card.pdf downloads do not exist until T-040/T-042 (existing card
   routes are institution-admin only). T-040 should fill `links.card` with holder-token-authorised URLs.
6. **Logging.** The log serializer already masks `/holder/:token`; tests assert no holder token, salt or key material in logs.
