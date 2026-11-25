# ADR 0005: Invite accept, password reset and rate limiting (T-010)

Status: Accepted. Recommended options taken under the owner's standing permission; the owner can overrule any item.

## Context
docs/api.md fixes the endpoints (`POST /auth/invites/accept`, `POST /auth/password-reset` with request and confirm modes).
ADR 0002 requires invite/reset tokens to be stored only as hashes. ADR 0004 left rate limiting, invite/reset and
"kill sessions on password change" to this task. The white paper does not settle the details below.

## Decisions
1. **Tokens.** 256 random bits, base64url (43 chars), stored as hex SHA-256 in `invites.token_hash` /
   `password_resets.token_hash` (unique). Single use: the claiming `UPDATE ... SET used_at = now() WHERE used_at IS NULL AND
   expires_at > now() RETURNING id` is atomic, so concurrent redemptions yield exactly one winner (tested).
2. **Lifetimes.** Invite 72 h (`INVITE_TTL_HOURS`, 1-720). Reset 60 min (`RESET_TTL_MINUTES`, 5-1440). Expiry is judged by the
   database clock.
3. **One error for every token problem.** Unknown, malformed, expired, used, or "user disabled" all return
   `400 INVALID_TOKEN` with an identical body. The password is Argon2id-hashed before the token is looked up, so valid and
   invalid tokens cost about the same.
4. **Reset request never reveals the account.** `{email}` always returns `202 {"status":"accepted"}` (unknown, disabled,
   known, internal queue or DB failure). A mail job is enqueued only for an ACTIVE user. Residual: a known email does one
   extra INSERT, a few ms; no Argon2 work is done on either path. Accepted. A new request voids the user's earlier unused
   reset tokens.
5. **Password policy.** 12 to 256 characters (`400 WEAK_PASSWORD`; over-long input is bounded for CPU). No composition rules and no
   breached-password list (NIST 800-63B suggests one; deferred, needs a data source). A weak password
   is rejected before the token is touched, so it does not burn the token.
6. **Invite accept.** Body `{token, password, name?}`. Creates an `INSTITUTION_ADMIN` (the only role an invite can create; no
   role in the request) in the invite's institution, taken from the invite row, never the request. `name` is optional
   (default: local part of the email) because `users.name` is NOT NULL and invites carry no name. It does **not** log the
   user in: they sign in normally (one code path for session creation, no token-to-session shortcut). Responds `204`. If the
   email already has an account (emails are globally unique) the unique violation rolls back and the answer is the generic
   `INVALID_TOKEN`; the invite stays unused, which avoids revealing that the address is registered elsewhere. Issuing an invite
   (`AccountService.issueInvite`, used by T-015) also does not check for an existing account, for the same reason.
7. **Sessions.** `setPasswordAndKillSessions` (auth.ts) updates the hash and deletes every session of the user in the same
   transaction; reset confirm uses it and any future change-password endpoint must too. Reset confirm also voids the user's
   other outstanding reset tokens and clears the caller's cookie. Platform admins (no institution) use the same path under
   platform scope.
8. **Unauthenticated endpoints and CSRF.** Like login, these have no session and so no CSRF token; they accept only
   `application/json` (415 otherwise) with no CORS, and set no session cookie. Responses are `Cache-Control: no-store`.
9. **Pre-auth DB access.** `Db.withLookup` now accepts only an allowlist of keys (`LOOKUP_KEYS`: the seven lookup settings
   in migration PART 4); any other key throws. Invite and reset use `app.invite_token_hash` / `app.reset_token_hash`, then
   set the scope from the row found (as ADR 0004 does for sessions). No migration or new grant was needed.
10. **Mail is the worker's job.** The API enqueues through `AccountMailQueue` (`apps/api/src/notifications.ts`) with
    `NoopAccountMailQueue` (default) and `MemoryAccountMailQueue` (tests). Jobs carry the raw token, since the email needs it.
    **For T-011:** the pg-boss implementation must never log the payload, should use short retention (the token is useless
    after its expiry and after use), and should send nothing for jobs whose token is already expired. Until T-011 wires a real
    queue, `server.ts` uses the no-op, so no invite/reset mail is sent.
11. **Rate limiting.** In-process fixed-window counters (`rate-limit.ts`), keys are HMAC IP hash or SHA-256 of the lower-cased
    email, never raw values; memory is bounded (50 000 keys, expired then oldest evicted). Exceeding returns
    `429 RATE_LIMITED` with `Retry-After`; blocked attempts do not extend the window. Defaults and env vars:

    | Endpoint | Per IP | Per account (email) | Window |
    |---|---|---|---|
    | login | 30 (`RATE_LIMIT_LOGIN_IP_MAX`) | 5 (`RATE_LIMIT_LOGIN_ACCOUNT_MAX`) | 900 s (`RATE_LIMIT_LOGIN_WINDOW_SECONDS`) |
    | reset request | 10 (`RATE_LIMIT_RESET_IP_MAX`) | 3 (`RATE_LIMIT_RESET_ACCOUNT_MAX`) | 3600 s (`RATE_LIMIT_RESET_WINDOW_SECONDS`) |
    | invite accept, reset confirm | 20 (`RATE_LIMIT_TOKEN_IP_MAX`) | n/a | 900 s (`RATE_LIMIT_TOKEN_WINDOW_SECONDS`) |

    Login counts every attempt against the account key until a success clears it (consumed before the Argon2 check, so
    parallel guesses cannot overshoot). The account key is derived from the submitted email whether or not the account exists,
    so a 429 does not reveal existence. IP checks run first. Rate limits cannot be disabled (minimum 1).
12. **Trade-offs accepted.**
    - A per-account login limit lets an attacker lock a victim out for up to the window by failing logins for their email
      (brute-force protection is preferred over availability; the victim can still reset the password, which does not depend on
      the login counter). Revisit with per-account plus IP-pair keys if it bites.
    - Counters are per process. With N API instances the effective limit is N times higher; fine for the single-instance MVP.
      Move to a Postgres or Redis counter before scaling out (not needed for the MVP; no new infrastructure added).
    - Behind a proxy the IP is only as good as `TRUST_PROXY` (ADR 0003).
13. **Precomputed dummy hash.** The Argon2id hash used for unknown users is computed once at module load, so the first unknown-user
    login is not slower than the rest.
14. **Not in this task.** Audit entries for invite accept and password reset (the audit chain arrives with T-024; add
    `INVITE_ACCEPTED`, `PASSWORD_RESET_REQUESTED/COMPLETED` then). Expired invite/reset/session row purge is for a worker job.
    Cookie `__Host-` prefix is not adopted: it conflicts with the optional `COOKIE_DOMAIN`.

## Consequences
- A stolen database yields no usable invite, reset or session token.
- The web app (T-035) sends JSON, shows one generic message for `INVALID_TOKEN`, and treats `202` on reset request as always successful.
- T-015 calls `AccountService.issueInvite` for the first institution admin.
