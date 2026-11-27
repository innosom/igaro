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
  /** Test hook (ms since epoch). Default: the database clock. */
  now?: () => number;
}

const CLEANUP_BATCH = 500;

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
    let row: { count: number; wait: number } | undefined;
    try {
      const at = this.o.now ? new Date(this.o.now()) : null;
      const r = await this.o.db.pool.query<{ count: number; wait: number }>(CONSUME_SQL, [
        this.k(key),
        this.o.windowSeconds,
        this.o.max,
        at,
      ]);
      row = r.rows[0];
    } catch {
      row = undefined; // not logged or echoed: driver errors can carry statement parameters
    }
    if (!row) {
      if (this.o.onError === 'open') return this.fallback.consume(key);
      throw new AppError(503, 'RATE_LIMIT_UNAVAILABLE', 'Service temporarily unavailable');
    }
    this.maybeCleanup();
    return row.count <= this.o.max ? 0 : Math.max(1, Math.ceil(row.wait));
  }

  async reset(key: string): Promise<void> {
    try {
      await this.o.db.pool.query('DELETE FROM rate_limit_counters WHERE "key" = $1', [this.k(key)]);
    } catch {
      // A counter that cannot be cleared only makes the limiter stricter; do not fail a successful login for it.
    }
    this.fallback.reset(key);
  }

  /** Keeps the table bounded: now and then delete one batch of long-expired windows. */
  private maybeCleanup(): void {
    if (Math.random() >= (this.o.cleanupRate ?? 0.02)) return;
    void this.o.db.pool.query(CLEANUP_SQL).catch(() => undefined);
  }
}
