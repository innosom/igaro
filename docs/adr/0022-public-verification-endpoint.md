# ADR 0022: Public verification endpoint design

Status: Accepted (recommended option taken under the owner's standing permission)

## Decisions
1. **Lookup and RLS.** No migration. The credential is found with the existing narrow `app.verification_token` lookup policy
   (`Db.withLookup`); the verification token is stored in clear (ADR 0002), so it is matched directly, and only if it is a
   well-formed 22-character base64url value (anything else is a miss and never reaches Postgres). After the row is found,
   `app.institution_id` is set from that row (the same pattern as the session lookup) so the key, institution, holder, type and
   superseding credential can be read under the normal tenant policies. RLS is not widened.
2. **Uniform not-found.** Unknown, malformed, over-long and DRAFT tokens all return HTTP 200 with the same body shape
   (`result: "NOT_FOUND"`, every other field `null`) and an identical code path including the log insert. `credential.json` answers a
   plain 404 for the same cases. Timing is equalised by structure (one lookup transaction plus one log insert), not by padding.
3. **What is shown.** Only for non-failed results: institution `{name, slug, cardTitle, primaryColor, secondaryColor}`, holder
   `fullName` always plus `idNumber`, `attributes`, `photoUrl` per the institution's `publicFields`, type `{code, name, kind}`,
   status (EXPIRED computed), `issuedAt`/`expiresAt` from the authenticated payload, `supersededBy` (the new credential's
   verification token), `proof {signedBy, kid, anchorStatus}`, and `warning: "INSTITUTION_SUSPENDED"` for VALID_WITH_WARNING.
   NOT_FOUND and VERIFICATION_FAILED reveal nothing from the row (a failed row may have been altered). A photo URL (5-minute
   signed GET) is only produced when the holder's stored `photo_sha256` equals the payload's signed `photoSha256`.
   KEY_COMPROMISED is public VERIFICATION_FAILED and `KEY_COMPROMISED` only in `verification_logs.result` (ADR 0002).
4. **Logging.** Every check inserts a `verification_logs` row (hash = `hashIp` with IP_HASH_KEY, user agent truncated to 200
   chars, credential/institution ids only when the credential exists and is not a draft). A failed log insert fails the request
   (500): a check that cannot be recorded is not served. `credential.json` fetches are not checks and are not logged.
5. **Ops alert.** On `alertOps` from core the API writes one structured `error` log line
   (`event: VERIFICATION_INTEGRITY_FAILURE, alert: "ops"`, reason code, institution and credential ids, ipHash; no token, salt, payload
   or IP). Log shipping or alerting rules key on that event. No audit_logs row: the public path has no actor, and a flood of
   forged requests must not be able to grow a tenant's audit chain. Known compromised keys do not alert (core decision, ADR 0021).
6. **Rate limits.** In-process fixed windows (ADR 0005), 429 with `Retry-After`. The per-IP limit (hashed IP) counts every request
   on both routes. The per-token limit (SHA-256 of the token, shared by both routes) counts ONLY NOT_FOUND and
   VERIFICATION_FAILED outcomes (and credential.json 404s), so a QR holder cannot lock a genuine credential out by hammering it;
   traffic against real credentials is bounded by the per-IP limit alone. Over-long tokens (Fastify `maxParamLength` raised to
   1024) are ordinary unknown tokens: 200 NOT_FOUND, logged and rate limited. DRAFT returns before any further query, so its
   path matches an unknown token. The displayed `EXPIRED` status comes from core's outcome (signed expiry), not the column.
   A single default constant (`DEFAULT_VERIFY_LIMIT` in config.ts) is used. Defaults 60 per IP, 120 per token, per 60 s; env `RATE_LIMIT_VERIFY_IP_MAX`,
   `RATE_LIMIT_VERIFY_TOKEN_MAX`, `RATE_LIMIT_VERIFY_WINDOW_SECONDS`. `RateLimitConfig.verify` is optional so existing callers compile.
   Limiter state is per process (multi-instance trade-off as in ADR 0005).
7. **credential.json.** `{payload, dataHash, signature, kid, publicKeysUrl}` is served exactly as stored (for every non-draft status,
   including tampered rows, so verify-cli can detect it). The payload necessarily contains the salt, the holder's `externalId` and
   attributes, so this document is NOT limited by `publicFields`: possession of the verification token (the QR) discloses the full
   signed document. This bypass of `publicFields` is accepted for the MVP because independent verification (verify-cli) needs the
   full payload; it is to be revisited before the pilot (alternative: require the holder token for this file).
   `publicKeysUrl` is the site-relative `/i/<slug>/keys.json` (T-033).
