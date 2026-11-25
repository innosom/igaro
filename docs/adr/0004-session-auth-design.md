# ADR 0004: Session authentication design (T-009)

Status: Accepted. Recommended options taken under the owner's standing permission; the owner can overrule any item.

## Context
docs/api.md and ADR 0002 fix the broad shape (httpOnly Secure cookie, hashed session token, CSRF header on mutating
requests, Argon2id). Several details were left open.

## Decisions
1. **Session token and storage.** 256 random bits, base64url, in the cookie only. `sessions.token_hash = hex(SHA-256(token))`.
   The cookie is `HttpOnly; SameSite=Lax; Path=/; Max-Age=<absolute lifetime>`, plus `Secure` (on by default, required
   in production, `COOKIE_SECURE=false` allowed only in development/test) and an optional `Domain`.
2. **Lifetimes.** Idle timeout 60 minutes (`SESSION_IDLE_MINUTES`) and absolute maximum 12 hours (`SESSION_MAX_HOURS`).
   `sessions.expires_at` is the sliding idle deadline, extended on use at most once a minute and never beyond
   `created_at + max`. Expired sessions are deleted when seen. No schema change: a migration only grants `UPDATE (expires_at)`
   on `sessions` to `igaro_app` (`20261125000000_session_sliding_expiry`); `token_hash`, `user_id` and `institution_id`
   remain immutable. A periodic purge of never-used expired rows is left to a later worker job.
3. **CSRF.** Mutating methods (anything but GET/HEAD/OPTIONS) on authenticated routes need header `X-CSRF-Token`
   equal to `base64url(SHA-256("igaro.csrf.v1:" + sessionToken))`. It is derived from the raw token, so the database
   (which holds only the hash) cannot compute it, and nothing extra is stored. The client gets it in the `csrfToken`
   field of the login and `/auth/me` responses and keeps it in memory only. Missing or wrong gives 403 `CSRF_REQUIRED`.
   `POST /auth/login` is exempt (no session exists). It is safe against login CSRF because it accepts only
   `application/json` (415 otherwise; a cross-site form cannot send that without a CORS preflight and the API enables no CORS)
   and the cookie is SameSite=Lax. `POST /auth/logout` with a live session requires the header; without a valid session it
   is an idempotent 204 that clears the cookie.
4. **Login failures.** Unknown email, wrong password, DISABLED user and a user with no password set all return the same
   `401 INVALID_CREDENTIALS` body. Every attempt runs exactly one Argon2id verification (against a dummy hash when there is
   no usable stored hash), so timing is similar. A suspended *institution* does not block login: admins of a suspended
   institution can still sign in to see the state (verification pages already show VALID WITH WARNING). Revisit if the
   owner wants otherwise. A successful login replaces any session cookie the browser already holds.
5. **Argon2id parameters.** m=19456 KiB, t=2, p=1 (OWASP minimum), the same as the seed. Passwords over 256 characters
   are rejected with 400 to bound CPU use.
6. **Pre-auth database access under RLS.** No new policies: login uses `app.login_email`, session lookup uses
   `app.session_token_hash` (both already in the init migration). After the lookup the scope is set from the matched row
   (`app.institution_id`, or `app.is_platform_admin` when `institution_id` is NULL) so the user, institution, extension
   and deletion run under the normal tenant/platform policies. Only `auth.ts` uses `Db.withLookup`.
7. **`sessions.ip` stores the HMAC IP hash (ADR 0003), not the raw address**, and `user_agent` is truncated to 200 characters.
8. **Request context.** `app.authenticate` and `app.requireRole(...roles)` set `request.session` (a `Session` plus
   `sessionId` and `role`, ready for `Db.withTenant`) and `request.authMe`. Wrong role gives 403; a foreign tenant's resource
   stays 404 in the repositories.
9. **Not in this task.** Login rate limiting, invite acceptance and password reset (T-010); audit entries for login/logout
   (the audit chain arrives in W3; add LOGIN/LOGOUT entries then).

## Consequences
- A stolen database cannot produce a session cookie or a CSRF token.
- The web app must send `X-CSRF-Token` on every non-GET call and refresh it from `/auth/me` on load.
- Changing a user's password or disabling a user should delete their sessions (T-010 for password change; disabling is
  already enforced at read time because the user's status is checked on every request).
