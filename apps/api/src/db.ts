// Tenant-scoped data access. The ONLY way to run a query is Db.withTenant, which opens a
// transaction and sets the RLS scope from the authenticated session object (never from a request
// parameter or body). Row-level security in Postgres backs this up (invariant 5).
import pg from 'pg';

export interface TenantSession {
  readonly kind: 'tenant';
  readonly userId: string;
  readonly institutionId: string;
}

export interface PlatformSession {
  readonly kind: 'platform';
  readonly userId: string;
  // Deliberately no institutionId: platform scope is read-only per the RLS policies and must never
  // be combined with a tenant scope (that would let platform sessions write tenant rows).
}

export type Session = TenantSession | PlatformSession;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export const isUuid = (v: unknown): v is string => typeof v === 'string' && UUID.test(v);

export interface DbOptions {
  connectionString: string;
  max?: number;
  /** Extra pg pool settings (tests use this for search_path). */
  poolConfig?: pg.PoolConfig;
}

/**
 * The only settings an unauthenticated lookup may set. Each matches a narrow SELECT policy in the
 * init migration (PART 4); anything else is refused so a typo or caller-supplied key cannot widen scope.
 */
export const LOOKUP_KEYS = [
  'app.login_email',
  'app.session_token_hash',
  'app.invite_token_hash',
  'app.reset_token_hash',
  'app.institution_slug',
  'app.verification_token',
  'app.holder_token_hash',
] as const;
export type LookupKey = (typeof LOOKUP_KEYS)[number];
const LOOKUP_KEY_SET: ReadonlySet<string> = new Set(LOOKUP_KEYS);

export class Db {
  readonly pool: pg.Pool;

  constructor(opts: DbOptions) {
    this.pool = new pg.Pool({
      max: opts.max ?? 10,
      ...opts.poolConfig,
      connectionString: opts.connectionString,
    });
    // An idle-client error must not crash the process.
    this.pool.on('error', () => undefined);
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  /**
   * Run fn in one transaction carrying only narrow single-row lookup settings (migration PART 4:
   * app.login_email, app.session_token_hash, ...). No tenant or platform scope is set; fn may set
   * one afterwards from the row it found. Only the auth module calls this, with values it was
   * handed on an unauthenticated path.
   */
  async withLookup<T>(
    settings: Readonly<Partial<Record<LookupKey, string>>>,
    fn: (c: pg.PoolClient) => Promise<T>,
  ): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      for (const [k, v] of Object.entries(settings)) {
        if (!LOOKUP_KEY_SET.has(k) || typeof v !== 'string') {
          throw new TypeError('invalid lookup setting');
        }
        await client.query('SELECT set_config($1, $2, true)', [k, v]);
      }
      const out = await fn(client);
      await client.query('COMMIT');
      return out;
    } catch (e) {
      try {
        await client.query('ROLLBACK');
      } catch {
        // connection is broken; release below discards it
      }
      throw e;
    } finally {
      client.release();
    }
  }

  /**
   * Run fn in one transaction scoped to the session. A tenant session sets only app.institution_id;
   * a platform session sets only app.is_platform_admin (never both, so it stays read-only).
   * Commits on success, rolls back on error.
   */
  async withTenant<T>(session: Session, fn: (c: pg.PoolClient) => Promise<T>): Promise<T> {
    const settings: [string, string][] = [];
    if (session.kind === 'platform') {
      settings.push(['app.is_platform_admin', 'true']);
    } else {
      if (!isUuid(session.institutionId)) throw new TypeError('invalid session institution id');
      settings.push(['app.institution_id', session.institutionId]);
    }

    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      for (const [k, v] of settings) await client.query('SELECT set_config($1, $2, true)', [k, v]);
      const out = await fn(client);
      await client.query('COMMIT');
      return out;
    } catch (e) {
      try {
        await client.query('ROLLBACK');
      } catch {
        // connection is broken; release below discards it
      }
      throw e;
    } finally {
      client.release();
    }
  }
}
