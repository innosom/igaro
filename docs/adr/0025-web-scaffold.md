# ADR 0025: apps/web scaffold and auth pages (T-035)

Status: accepted (recommended option taken under the owner's standing permission)

1. **Next.js app router + Tailwind**; the browser only talks to same-origin `/api/v1`, rewritten by Next to `API_URL`
   (default `http://localhost:4000`). The session cookie stays httpOnly and first-party.
2. **Invite/reset tokens are read from the URL fragment** (`#token=`), matching ADR 0006 §9 and the worker's `buildLink`.
   A `?token=` query string is ignored, so a token never reaches server or proxy logs. The fragment is cleared with
   `history.replaceState` after reading.
3. **CSRF token in memory only** (ADR 0004 §3); the shared API client throws if used on the server.
4. **CSP** with per-request nonce + `strict-dynamic` set in `src/proxy.ts`; pages render per request. Other headers
   (Referrer-Policy no-referrer, nosniff, frame DENY, noindex) in `next.config.mjs`; HSTS in production only.
5. Password-reset request always shows the same neutral message.
6. **Open item (reviewer M1, owner igaro-platform, T-047):** because the Next server proxies API calls, the API sees the
   Next host as the client. Staging must set `TRUST_PROXY` to a hop count that includes the Next hop and verify that the
   rewrite forwards `X-Forwarded-For`; otherwise per-IP rate limits and IP hashing (ADR 0003) collapse to one bucket.
   QA should test that two clients get separate buckets (T-037).
