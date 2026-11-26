# ADR 0031: holder card download (T-042)

Status: accepted. Every choice below is the recommended option, taken under the owner's standing permission.

## Context
The private holder page (ADR 0023) returned `links.card = null`. Holders have no account; the holder token is their only
credential. Cards are rendered by the worker (ADR 0028) and served to institution admins by ADR 0029.

## Decisions
1. **Two token routes.** `GET /api/v1/holder/:holderToken/card.png` and `card.pdf`, in `PublicLookupService.holderCard`. The
   credential is found by SHA-256 of the token through the existing `app.holder_token_hash` lookup policy (no migration). Tokens
   stay hashed at rest; the card key is derived from the row (`cardStorageKeys(institution_id, credential_id)`), never from the request.
2. **Same rules as ADR 0029.** Integrity is re-checked with `@igaro/core` (hash, signature, `credentialId`, `institutionId`, key not
   COMPROMISED) before any state decision; failure logs `card.integrity_failure` (ids only, `via: holder`) and answers the uniform 404.
   Then only ACTIVE and unexpired (signed `expiresAt`) credentials are served. Unknown, malformed, draft, suspended, revoked,
   superseded and expired are one identical `404 NOT_FOUND`. `404 CARD_NOT_READY` + `Retry-After: 15`, `503 STORAGE_UNAVAILABLE`
   (storage missing or failing), `302` to a 60 s signed URL with `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.
3. **Rate limits reused.** Per-IP limiter shared with the holder view; every 404 on these routes counts against the per-token miss
   limiter, so a guessing client is throttled the same way as on the view.
4. **Links.** `links.card` (PNG) and new `links.cardPdf` are relative paths `/api/v1/holder/<token>/card.{png,pdf}` only when the
   credential is ACTIVE and unexpired, otherwise `null`. The token in the path is the one the caller already presented. The
   response therefore contains the holder token twice (previously never); the view is `no-store` and `no-referrer`.
5. **No leaks.** Logs mask `/holder/<token>/...` to `/holder/:token/...` (existing redaction); the token and signed URL are never logged.
6. **Not done.** A "not ready yet" card is not re-queued from this route (the job is enqueued at issuance, ADR 0029).
