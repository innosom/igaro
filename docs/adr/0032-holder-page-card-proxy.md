# ADR 0032: holder page and same-origin card proxy (T-042, web)

Status: accepted (recommended option, taken under the owner's standing permission).

## Decisions
1. `/h/:token` is server-rendered, `force-dynamic`, `Cache-Control: no-store`, robots noindex, `Referrer-Policy: no-referrer`,
   nonce CSP (from `proxy.ts`). The token is in the URL path (not a fragment), so there is nothing to scrub client-side
   (`token-url.ts` is for one-time fragment tokens). Unknown or malformed token is "link not found"; 429, 5xx and parse
   errors are "temporarily unavailable". The two are never conflated.
2. Download hrefs are built from the validated page token (`/h/<token>/card.png|pdf`, `/api/v1/verify/<vt>/credential.json`).
   `links.card` and `links.cardPdf` from the API only decide whether a button is shown (null hides it), so an API value is never
   used as an href.
3. Card downloads go through web route handlers, not a direct link to the API. The API answers 302 to a 60 s signed storage URL
   that may be on an origin the browser cannot reach or the CSP blocks. The handler follows it server-side (`redirect: manual`
   then no further redirects), follows the Location only if its `URL.origin` equals the `STORAGE_PUBLIC_ORIGIN` env var (unset or mismatch: 503, so a tampered redirect cannot cause SSRF), streams the body with a running byte count and aborts past 8 MB (a non-numeric or oversized Content-Length is refused), checks PNG/PDF magic bytes, and returns an
   attachment with `no-store`, `no-referrer` and a sandbox CSP. The token and signed URL are never logged or sent to the browser.
   Status mapping: 404 stays 404 (with `Retry-After` for CARD_NOT_READY), 429 stays 429, anything else is 503.
4. The page forwards only a validated client IP (`WEB_TRUST_PROXY_HOPS`), as the verify page does.
5. `next.config.mjs` rewrites every `/api/v1/*` path to the API unchanged. This is a plain pass-through, not an allow-list:
   the web app does not restrict which API routes a browser can reach through it. Access control stays in the API (session
   cookie, RLS, rate limits, uniform 404s). Web pages link only to specific paths (`credential.json`, `/holder/...`).
