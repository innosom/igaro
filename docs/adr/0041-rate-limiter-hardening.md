# ADR 0041: Rate limiter hardening (T-054)

Status: Accepted. Addendum to ADR 0040 (resolves the T-052 review items M1, L2, L5). Invariants unchanged.

## Decisions
1. **Blocked-key cache.** `PgRateLimiter` keeps an in-process map `namespaced key -> window end`. Once the database
   reports a key as blocked, further attempts are refused from memory with no query until the window ends. The end is
   `T0 + wait`, where `T0` is the process clock read BEFORE the query and `wait` is the database's remaining time, so the
   cached end is never later than the real `reset_at`: the cache cannot block after the window expired. An expired entry
   is deleted on the next call and the database decides. The map is bounded (default 10000 keys): expired entries are
   dropped first, then the oldest. Only blocked keys are cached; allowed attempts always count in Postgres, so the
   shared limit across instances is unchanged. Blocked attempts never extended the lockout (ADR 0040 item 2), so skipping
   them changes no stored state. Each instance caches independently; at worst an instance refuses a little less than
   the database would, never more.
2. **Reset.** `reset` deletes the cache entry before and after the database delete, and bumps an epoch so a blocked
   `consume` already in flight cannot re-cache the key after the reset.
3. **Per-query timeout.** Every limiter query (consume, reset, cleanup) carries a client-side `query_timeout`
   (default 2000 ms, option `queryTimeoutMs`) on top of the 5 s connection timeout. A stuck database therefore takes the
   ADR 0040 fail path: closed (503) for login, reset, token, import and key change; open (memory fallback) for public reads.
   This replaces "no per-statement timeout was added" in ADR 0040 item 4. It is client-side: the driver stops waiting, the
   server statement ends when the lock clears. The limiter shares the app pool (no separate pool was added).
4. **Single-flight cleanup.** At most one cleanup runs per pool per process; calls that would start another are skipped
   until it finishes (success or failure).
5. **Verify ordering.** In `VerifyService.verify` the `VERIFICATION_INTEGRITY_FAILURE` ops alert is logged before
   `noteMiss`, so a limiter refusal or failure cannot suppress it.

## Addendum (T-055): server-side timeouts
Recommended option taken under the owner's standing permission.
- Item 3 is amended: the client-side `query_timeout` is now only a backstop. Limiter queries (consume, reset, cleanup) run on a small
  dedicated pool, `Db.limiterPool` (default 4 connections, same role and search_path as the main pool), whose connections start with
  `-c statement_timeout=<ms> -c lock_timeout=<ms>` (`limiterTimeoutMs`, default 2000). Postgres cancels a stuck or lock-waiting statement
  itself, so it no longer keeps running after the client gave up. A separate pool (not SET LOCAL) keeps each limiter query a single round
  trip and keeps a slow limiter from exhausting the main pool. The failure path is unchanged (closed 503 / open memory fallback).
- L3 (known, accepted): `reset` of a key that is still blocked clears the counter and the cache entry, so the key starts a fresh window. It is
  called only after a successful login (or equivalent), which proves the caller holds the secret; other instances may still hold a cached
  block until it expires (they refuse a little more, never less).

- Known Low (T-055 review): a `?options=` in the database URL overrides pool `options` and would drop the server-side timeouts (the client
  `query_timeout` backstop stays). The limiter pool is shared by all limiter families (4 connections); size `max_connections` for 4 extra
  connections per API process.

## Tests
`apps/api/src/rate-limit-pg.test.ts` (cache skips DB and expires, reset, reset race, bound, timeout both modes, single
flight) and `apps/api/src/verify.test.ts` (alert emitted when the token limiter then refuses).
