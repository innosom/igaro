// In-process fixed-window rate limiter (ADR 0005). Keys are hashed by the caller (never raw emails
// or IPs). Memory is bounded: when the table is full, expired windows are dropped first, then the
// oldest entries. State is per process; see ADR 0005 for the multi-instance trade-off.

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
