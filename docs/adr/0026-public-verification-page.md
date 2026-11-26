# ADR 0026: public verification page `/v/:token` (T-036)

Status: accepted (recommended option taken under the owner's standing permission)

1. **Server-rendered.** The page is a dynamic server component that calls `API_URL/api/v1/verify/:token` (no-store,
   no-referrer, no redirects, 8 s timeout), so the result shows without JavaScript. The token comes from the path only;
   it is never logged and never put in a query string. Implausible tokens (not 16-128 base64url chars) are shown as
   NOT FOUND without calling the API.
2. **Fail closed.** Any network error, timeout, non-200, 429, bad JSON or unknown `result` shows a distinct
   "CANNOT VERIFY RIGHT NOW" state (not a verification result), never VERIFIED. NOT_FOUND and VERIFICATION_FAILED are
   reduced to a blank record client-side even if the body carries more.
3. **States** each have a unique label, icon and fixed AA-contrast palette; colour is never the only signal.
   Institution colours are not used for result banners, only for the header bar.
4. **Branding without inline styles.** The CSP forbids inline style attributes, so sanitised `#rrggbb` values (3-digit
   expanded, anything else replaced by defaults) are emitted as CSS custom properties in a `<style nonce>` tag; the
   foreground is black or white by contrast.
5. **Photo.** The API's `photoUrl` is a short-lived signed storage URL on another origin. Rather than loosening
   `img-src`, `/v/:token/photo` re-runs the verification, requires a returned `photoUrl` (so the institution's public
   fields still decide), fetches it server-side (http/https only, no redirects, png/jpeg/webp, 2 MiB cap) and serves it
   same-origin with `nosniff`, `no-store` and a sandbox CSP. The page shows an `<img>` only if `photoUrl` was returned.
   Residual risk: the server fetches a URL supplied by our own API; it is trusted, not user input.
6. **Proof panel is data driven.** `buildProofRows(proof)` maps the API `proof` object to rows; `ANCHOR_LABELS` has
   `NOT_ANCHORED: "Not anchored"`, and unknown statuses render a sanitised generic row marked not established.
7. **Links.** `credential.json` via the `/api/v1` rewrite; `keys.json` via a new `/i/:slug/keys.json` rewrite to the API
   (slug validated); the SUPERSEDED link is `/v/<newtoken>`; offline instructions use
   `igaro-verify credential.json --keys keys.json`. The credential number is never shown or linked.
8. `Cache-Control: no-store` on `/v/*`; noindex, `Referrer-Policy: no-referrer` and the nonce CSP apply as for all pages.
9. **Visitor IP forwarding (operational requirement, T-047).** The web server calls the API, so without help every
   visitor shares one rate-limit bucket and hashed-IP log entry. Env `WEB_TRUST_PROXY_HOPS` (integer 0-10, default 0 =
   untrusted, nothing forwarded) says how many trusted proxies sit in front of web. With N >= 1 the page and photo
   route take the Nth address from the right of the incoming `X-Forwarded-For` (appended by our own ingress; anything to
   its left is client-controlled and ignored), validate it with `net.isIP`, and send it to the API as a single-value
   `X-Forwarded-For`. The raw client header is never passed through; if no valid IP is derivable, no header is sent.
   **Staging/production must set `WEB_TRUST_PROXY_HOPS` to match the ingress and run the API with `TRUST_PROXY` equal to the same value (rewritten API requests keep the browser XFF chain, so a smaller value would put every user in one login bucket); keep web and API reachable only via the ingress**
   (web counts as one hop); otherwise the buckets collapse or the header is spoofable.
10. Photo proxy rejects `Content-Length` over 2 MiB up front and reads the body with a capped reader.
11. **Not yet done:** in-browser signature check (needs the browser build of `packages/core`), a later task.
