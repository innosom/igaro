# ADR 0040: Postgres-backed rate limiter shared across API instances (T-052)

Status: Accepted. Recommended options taken under the owner's standing permission; the owner can overrule any item.
Supersedes the single-instance trade-off in ADR 0005 (and the "limiter is per-process" note in ADR 0020).

## Context
ADR 0005 kept login, reset, token, verify, public-lookup, key-change and import limits in process memory. With two or more
API instances the effective limit is multiplied by the instance count and restarts reset every counter (final review M3).
Adding Redis or another service is out of scope for the MVP.

## Decisions
1. **Store.** Table `rate_limit_counters(key text PK, count int, reset_at timestamptz)` (migration `20261129000000`). Not
   tenant data: no `institution_id`, no RLS. Least privilege: `REVOKE ALL FROM PUBLIC`, `GRANT SELECT, INSERT, UPDATE,
   DELETE` to `igaro_app` only (the worker has no access).
2. **Atomic consume.** One `INSERT ... ON CONFLICT (key) DO UPDATE ... RETURNING` statement. If the window has expired the
   count restarts at 1 with a new `reset_at`; otherwise the count rises to at most `max + 1`. `count <= max` means allowed.
   Blocked attempts therefore never move `reset_at`, so a flood cannot extend its own lockout. Same contract as the old
   class: returns 0 when allowed, else the seconds to wait (minimum 1). The row lock serialises concurrent consumers, so
   exactly `max` of N parallel attempts pass (tested).
3. **Clock.** The database clock (`statement_timestamp()`, evaluated once per statement), so instances with skewed clocks agree. A `now` test hook passes an
   explicit timestamp instead.
4. **Keys.** Callers already pass hashes (IP hash, `sha256(acct:email)`, `sha256(token)`) or an institution id. The limiter
   prefixes a family name (`login-ip`, `login-acct`, `reset-ip`, `reset-acct`, `token-ip`, `verify-ip`, `verify-token`,
   `keys-ip`, `holder-ip`, `holder-miss`, `keychange`, `import`) because all families share one table. No raw IP, email or
   token is stored or logged. The account key is an HMAC under `IP_HASH_KEY` (same mechanism as `hashIp`), not a plain
   hash, so a database reader cannot confirm an email by hashing it. **`IP_HASH_KEY` must be identical on all API instances**
   (and stable across restarts), otherwise per-IP and per-account counters diverge between instances. The pool has a 5 s
   `connectionTimeoutMillis` so a stuck database fails closed instead of hanging requests. No per-statement timeout was added.
5. **Bounded table.** About 2% of calls delete one batch (500) of rows expired for over a minute, using
   `FOR UPDATE SKIP LOCKED` so cleanup never blocks consumers. Failures of cleanup are ignored.
6. **Fail mode when the database errors.**
   - **Closed (503 `RATE_LIMIT_UNAVAILABLE`)** for login, password reset, token redemption, import and key change: these are
     brute-force and abuse controls; losing them silently is worse than a short refusal. The error body carries no detail.
   - **Open to a per-process memory limiter** (the ADR 0005 class, kept for this) for `/verify`, `keys.json` and the holder
     view: they need the same database to answer at all, so a counter outage should not add a second failure mode.
7. **Reset.** A successful login deletes the account counter (best effort: failure only leaves the limiter stricter).
8. **Async.** `consume` and `reset` are async; all callers `await` them. Limits run before any Argon2id work as before.

## Consequences
- One extra indexed upsert per limited request (verify p95 stayed about 43 ms in the QA test, budget 300 ms).
- Counters persist across restarts and are shared by all instances. Tests that need a fresh limiter clear the table.
- Tested with two `buildApp` instances on one database: login per IP, login per account, verify per IP and per token.
