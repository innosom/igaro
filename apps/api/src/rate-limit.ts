// Rate limiters. Keys are hashed by the caller (never raw emails, IPs or tokens).
//  - PgRateLimiter (T-052, ADR 0040): the production path. Fixed windows in Postgres, shared by every API instance.
//  - RateLimiter (ADR 0005): in-process fixed window. Used only as the fail-open fallback of PgRateLimiter and in
//    unit tests. Memory is bounded: when the table is full, expired windows are dropped first, then the oldest.
import type { Db } from './db.js';
import { AppError } from './errors.js';

export interface RateLimiterOptions {
  max: number;
  windowSeconds: number;
  maxKeys?: number;
  /** Test hook. */
  now?: () => number;
}

interface Entry {
  count: number;
  resetAt: number;
}

export class RateLimiter {
  private readonly entries = new Map<string, Entry>();
  private readonly max: number;
  private readonly windowMs: number;
  private readonly maxKeys: number;
  private readonly now: () => number;

  constructor(o: RateLimiterOptions) {
    this.max = o.max;
    this.windowMs = o.windowSeconds * 1000;
    this.maxKeys = o.maxKeys ?? 50_000;
    this.now = o.now ?? Date.now;
  }

  /**
   * Count one attempt. Returns 0 when allowed, otherwise the seconds until the window resets.
   * Blocked attempts are not counted further, so a flood cannot extend its own lockout.
   */
  consume(key: string): number {
    const t = this.now();
    let e = this.entries.get(key);
    if (!e || e.resetAt <= t) {
      this.makeRoom(t);
      e = { count: 0, resetAt: t + this.windowMs };
      this.entries.set(key, e);
    }
    if (e.count >= this.max) return Math.max(1, Math.ceil((e.resetAt - t) / 1000));
    e.count += 1;
    return 0;
  }

  /** Forget a key (a successful login clears the account counter). */
  reset(key: string): void {
    this.entries.delete(key);
  }

  private makeRoom(t: number): void {
    if (this.entries.size < this.maxKeys) return;
    for (const [k, e] of this.entries) if (e.resetAt <= t) this.entries.delete(k);
    // Map iterates in insertion order: drop the oldest until there is room.
    for (const k of this.entries.keys()) {
      if (this.entries.size < this.maxKeys) break;
      this.entries.delete(k);
    }
  }
}

export interface Limiter {
  /** Count one attempt. Returns 0 when allowed, otherwise the seconds to wait. */
  consume(key: string): Promise<number>;
  reset(key: string): Promise<void>;
}

export interface PgRateLimiterOptions {
  db: Db;
  /** Namespace: limiters share one table, so every family has its own prefix. */
  family: string;
  max: number;
  windowSeconds: number;
  /**
   * What to do when the database errors. 'closed': refuse with 503 (login, reset, token, import, key
   * change: brute-force and abuse controls must not vanish). 'open': fall back to a per-process memory
   * limiter (public reads, which need the same database anyway).
   */
  onError: 'closed' | 'open';
  /** Probability per call of deleting a batch of expired rows. Default 0.02. */
  cleanupRate?: number;
  /** Test hook (ms since epoch). Default: the database clock for counting; the process clock for the blocked-key cache. */
  now?: () => number;
  /** Client-side per-query timeout in ms (T-054). A stuck database then takes the 'onError' path. Default 2000. */
  queryTimeoutMs?: number;
  /** Bound on the blocked-key cache (T-054). Default 10000. */
  maxCachedKeys?: number;
}

const CLEANUP_BATCH = 500;
const DEFAULT_QUERY_TIMEOUT_MS = 2000;
const DEFAULT_MAX_CACHED = 10_000;
/** node-postgres honours query_timeout at runtime but its typings omit it. */
function withTimeout<T extends { text: string; values?: unknown[] }>(q: T, ms: number): T {
  return { ...q, query_timeout: ms } as T;
}

/** Pools with a cleanup in flight: at most one per process per pool (T-054). */
const cleaning = new WeakSet<object>();

const CONSUME_SQL = `
INSERT INTO rate_limit_counters AS r ("key", "count", "reset_at")
VALUES ($1, 1, COALESCE($4::timestamptz, statement_timestamp()) + make_interval(secs => $2))
ON CONFLICT ("key") DO UPDATE SET
  "count" = CASE
    WHEN r."reset_at" <= COALESCE($4::timestamptz, statement_timestamp()) THEN 1
    ELSE LEAST(r."count" + 1, $3::int + 1)
  END,
  "reset_at" = CASE
    WHEN r."reset_at" <= COALESCE($4::timestamptz, statement_timestamp()) THEN EXCLUDED."reset_at"
    ELSE r."reset_at"
  END
RETURNING "count", EXTRACT(EPOCH FROM (r."reset_at" - COALESCE($4::timestamptz, statement_timestamp())))::float8 AS wait`;

const CLEANUP_SQL = `
DELETE FROM rate_limit_counters WHERE "key" IN (
  SELECT "key" FROM rate_limit_counters
   WHERE "reset_at" < clock_timestamp() - interval '1 minute'
   LIMIT ${CLEANUP_BATCH} FOR UPDATE SKIP LOCKED)`;

export class PgRateLimiter implements Limiter {
  private readonly fallback: RateLimiter;
  /** Blocked keys (namespaced) -> process-clock ms when the window ends. Rejected requests skip the database. */
  private readonly blocked = new Map<string, number>();
  /** Bumped by reset() so an in-flight consume cannot re-cache a key that was just cleared. */
  private resetEpoch = 0;

  constructor(private readonly o: PgRateLimiterOptions) {
    this.fallback = new RateLimiter({ max: o.max, windowSeconds: o.windowSeconds, ...(o.now ? { now: o.now } : {}) });
  }

  private k(key: string): string {
    return this.o.family + ':' + key;
  }

  /**
   * Blocked attempts are not counted further: the stored count saturates at max + 1 and reset_at only
   * moves when the window has expired, so a flood cannot extend its own lockout.
   */
  async consume(key: string): Promise<number> {
    const nsKey = this.k(key);
    const clock = this.o.now ?? Date.now;
    // Blocked-key cache: never blocks once the window has passed. The stored end is computed from a timestamp taken
    // BEFORE the query, so it is never later than the database's reset_at.
    const cachedUntil = this.blocked.get(nsKey);
    if (cachedUntil !== undefined) {
      const t = clock();
      if (cachedUntil > t) return Math.max(1, Math.ceil((cachedUntil - t) / 1000));
      this.blocked.delete(nsKey);
    }
    let row: { count: number; wait: number } | undefined;
    const startedAt = clock();
    const epoch = this.resetEpoch;
    try {
      const at = this.o.now ? new Date(this.o.now()) : null;
      const r = await this.o.db.pool.query<{ count: number; wait: number }>(
        withTimeout(
          { text: CONSUME_SQL, values: [nsKey, this.o.windowSeconds, this.o.max, at] },
          this.o.queryTimeoutMs ?? DEFAULT_QUERY_TIMEOUT_MS,
        ),
      );
      row = r.rows[0];
    } catch {
      row = undefined; // not logged or echoed: driver errors can carry statement parameters
    }
    if (!row) {
      if (this.o.onError === 'open') return this.fallback.consume(key);
      throw new AppError(503, 'RATE_LIMIT_UNAVAILABLE', 'Service temporarily unavailable');
    }
    this.maybeCleanup();
    if (row.count <= this.o.max) return 0;
    if (epoch === this.resetEpoch && row.wait > 0) this.remember(nsKey, startedAt + row.wait * 1000, startedAt);
    return Math.max(1, Math.ceil(row.wait));
  }

  private remember(nsKey: string, until: number, t: number): void {
    const cap = this.o.maxCachedKeys ?? DEFAULT_MAX_CACHED;
    if (!this.blocked.has(nsKey) && this.blocked.size >= cap) {
      for (const [k, u] of this.blocked) if (u <= t) this.blocked.delete(k);
      for (const k of this.blocked.keys()) {
        if (this.blocked.size < cap) break;
        this.blocked.delete(k); // insertion order: oldest first
      }
    }
    this.blocked.set(nsKey, until);
  }

  async reset(key: string): Promise<void> {
    this.resetEpoch += 1;
    this.blocked.delete(this.k(key));
    try {
      await this.o.db.pool.query(
        withTimeout(
          { text: 'DELETE FROM rate_limit_counters WHERE "key" = $1', values: [this.k(key)] },
          this.o.queryTimeoutMs ?? DEFAULT_QUERY_TIMEOUT_MS,
        ),
      );
    } catch {
      // A counter that cannot be cleared only makes the limiter stricter; do not fail a successful login for it.
    }
    this.resetEpoch += 1;
    this.blocked.delete(this.k(key));
    this.fallback.reset(key);
  }

  /** Keeps the table bounded: now and then delete one batch of long-expired windows. */
  private maybeCleanup(): void {
    if (Math.random() >= (this.o.cleanupRate ?? 0.02)) return;
    const pool = this.o.db.pool;
    if (cleaning.has(pool)) return; // single flight per process
    cleaning.add(pool);
    void pool
      .query(withTimeout({ text: CLEANUP_SQL }, this.o.queryTimeoutMs ?? DEFAULT_QUERY_TIMEOUT_MS))
      .catch(() => undefined)
      .finally(() => cleaning.delete(pool));
  }
}
