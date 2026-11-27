// Startup check for the runtime database role (T-050, ADR 0037). RLS only protects tenants when the
// connecting role is neither a superuser, nor BYPASSRLS, nor the owner of the tenant tables (owners
// skip RLS unless FORCE is set). The API and worker call this once at boot.
import type pg from 'pg';

export interface RoleCheckResult {
  role: string;
  problems: string[];
}

type Queryable = Pick<pg.Pool, 'query'>;

/** Inspect current_user; never logs or returns credentials. */
export async function checkRuntimeRole(db: Queryable): Promise<RoleCheckResult> {
  const r = await db.query<{ role: string; rolsuper: boolean; rolbypassrls: boolean }>(
    `SELECT current_user::text AS role, r.rolsuper, r.rolbypassrls
       FROM pg_roles r WHERE r.rolname = current_user`,
  );
  const row = r.rows[0];
  if (!row) return { role: 'unknown', problems: ['current role not found in pg_roles'] };
  const owned = await db.query<{ n: number }>(
    `SELECT count(*)::int AS n
       FROM pg_class c
       JOIN pg_namespace ns ON ns.oid = c.relnamespace
      WHERE ns.nspname = current_schema() AND c.relkind IN ('r', 'p')
        AND c.relname <> '_prisma_migrations'
        AND pg_has_role(current_user, c.relowner, 'USAGE')`,
  );
  // Membership in a superuser/BYPASSRLS role (SET ROLE is then one statement away).
  const member = await db.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM pg_roles r
      WHERE (r.rolsuper OR r.rolbypassrls) AND r.rolname <> current_user
        AND pg_has_role(current_user, r.oid, 'MEMBER')`,
  );
  const problems: string[] = [];
  if ((member.rows[0]?.n ?? 0) > 0) problems.push('role is a member of a superuser/BYPASSRLS role');
  if (row.rolsuper) problems.push('role is a superuser');
  if (row.rolbypassrls) problems.push('role has BYPASSRLS');
  if ((owned.rows[0]?.n ?? 0) > 0) problems.push('role owns tenant tables');
  return { role: row.role, problems };
}

export class RuntimeRoleError extends Error {
  constructor(public readonly problems: string[]) {
    super(`unsafe runtime database role: ${problems.join('; ')} (RLS would not protect tenants)`);
    this.name = 'RuntimeRoleError';
  }
}

/**
 * T-053 (ADR 0039): the API's queue connection must be enqueue-only. Problems: the role is or inherits the worker
 * role, or can read job data. Never returns credentials.
 */
export async function checkQueueRole(
  db: Queryable,
  opts: { schema?: string; workerRole?: string } = {},
): Promise<string[]> {
  const schema = opts.schema ?? 'pgboss';
  const worker = opts.workerRole ?? 'igaro_worker';
  const problems: string[] = [];
  const m = await db.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM pg_roles r
      WHERE r.rolname = $1 AND pg_has_role(current_user, r.oid, 'MEMBER')`,
    [worker],
  );
  if ((m.rows[0]?.n ?? 0) > 0) problems.push(`queue role is or inherits ${worker}`);
  const rel = await db.query<{ ok: boolean | null }>(
    `SELECT has_column_privilege(current_user, to_regclass(quote_ident($1) || '.job'), 'data', 'SELECT') AS ok`,
    [schema],
  );
  if (rel.rows[0]?.ok === true) problems.push('queue role can SELECT job data');
  return problems;
}

/** Refuse in production, warn elsewhere. */
export async function assertQueueRole(
  db: Queryable,
  opts: { nodeEnv: string; warn: (msg: string) => void; schema?: string; workerRole?: string },
): Promise<void> {
  const problems = await checkQueueRole(db, opts);
  if (problems.length === 0) return;
  if (opts.nodeEnv === 'production') throw new RuntimeRoleError(problems);
  opts.warn(`unsafe queue database role: ${problems.join('; ')}. Production would refuse to start.`);
}

/** Refuse to start (throw) in production, warn elsewhere. `warn` receives no secrets. */
export async function assertRuntimeRole(
  db: Queryable,
  opts: { nodeEnv: string; warn: (msg: string) => void },
): Promise<void> {
  const { problems } = await checkRuntimeRole(db);
  if (problems.length === 0) return;
  if (opts.nodeEnv === 'production') throw new RuntimeRoleError(problems);
  opts.warn(`unsafe runtime database role: ${problems.join('; ')}. Production would refuse to start.`);
}
