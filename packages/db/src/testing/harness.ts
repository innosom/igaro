// Shared integration-test harness for anything that needs the real schema (T-012).
//
// Exposed as `@igaro/db/testing` for test code only. It contains no secrets: every value is a fixed
// test value, and the only credential it uses is DATABASE_URL, which the caller already has.
//
// createHarness() applies every migration into a fresh scratch schema (dropped on close()), seeds
// two tenants A and B with one row in EVERY tenant table, and gives helpers that run statements as
// the restricted `igaro_app` role (the role the API uses, which is what RLS and the grants are
// proven against) in tenant, platform, anonymous or owner scope. Every helper transaction is rolled
// back, so tests never leak state into each other.
//
//   const h = await createHarness('t099');
//   await h.asTenant(h.A.institutionId, async (c) => { ... });
//   const code = await h.code(() => c.query('...'));      // SQLSTATE or undefined
//   const db = new Db({ connectionString: url, poolConfig: { options: h.appConnectionOptions } });
//   await h.close();
import { randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import pg from 'pg';

export const databaseUrl: string | undefined = process.env.DATABASE_URL;
/** Use as `describe.skipIf(!hasDatabase)`. */
export const hasDatabase: boolean = Boolean(databaseUrl);

const migrationsDir = new URL('../../prisma/migrations/', import.meta.url);

/** Every tenant-scoped table, with the column that holds the owning institution. */
export const TENANT_TABLES = [
  'institutions',
  'institution_keys',
  'users',
  'sessions',
  'invites',
  'password_resets',
  'credential_types',
  'credential_holders',
  'credentials',
  'credential_events',
  'verification_logs',
  'audit_logs',
  'audit_head_hashes',
  'audit_head_timestamps',
  'import_batches',
  'import_rows',
] as const;
export type TenantTable = (typeof TENANT_TABLES)[number];

/** The owning-institution column of a table (the institutions table owns itself by `id`). */
export const tenantColumn = (t: TenantTable): string => (t === 'institutions' ? 'id' : 'institution_id');

/** Ids of the rows seeded for one tenant, one per tenant table (test values only). */
export interface TenantFixture {
  tag: string;
  institutionId: string;
  slug: string;
  kid: string;
  keyId: string;
  userId: string;
  email: string;
  sessionId: string;
  inviteId: string;
  resetId: string;
  typeId: string;
  holderId: string;
  credentialId: string;
  credentialNumber: string;
  verificationToken: string;
  eventId: string;
  verificationLogId: string;
  auditLogId: string;
  headHashId: string;
  headTimestampId: string;
  batchId: string;
  rowId: string;
  /** id of the seeded row in each tenant table */
  rowIds: Record<TenantTable, string>;
}

const mkId = (prefix: string, n: number): string =>
  `${prefix.repeat(8)}-${prefix.repeat(4)}-4${prefix.repeat(3)}-8${prefix.repeat(3)}-${String(n).padStart(12, '0')}`;

function fixture(prefix: string, tag: string): TenantFixture {
  const f = {
    tag,
    institutionId: mkId(prefix, 0),
    slug: `inst-${tag}`,
    kid: `kid-${tag}`,
    keyId: mkId(prefix, 1),
    userId: mkId(prefix, 2),
    email: `admin-${tag}@example.test`,
    sessionId: mkId(prefix, 3),
    inviteId: mkId(prefix, 4),
    resetId: mkId(prefix, 5),
    typeId: mkId(prefix, 6),
    holderId: mkId(prefix, 7),
    credentialId: mkId(prefix, 8),
    credentialNumber: `NUM-${tag}`,
    verificationToken: `test-vt-${tag}`,
    eventId: mkId(prefix, 9),
    verificationLogId: mkId(prefix, 10),
    auditLogId: mkId(prefix, 11),
    headHashId: mkId(prefix, 12),
    batchId: mkId(prefix, 13),
    rowId: mkId(prefix, 14),
    headTimestampId: mkId(prefix, 15),
  };
  return {
    ...f,
    rowIds: {
      institutions: f.institutionId,
      institution_keys: f.keyId,
      users: f.userId,
      sessions: f.sessionId,
      invites: f.inviteId,
      password_resets: f.resetId,
      credential_types: f.typeId,
      credential_holders: f.holderId,
      credentials: f.credentialId,
      credential_events: f.eventId,
      verification_logs: f.verificationLogId,
      audit_logs: f.auditLogId,
      audit_head_hashes: f.headHashId,
      audit_head_timestamps: f.headTimestampId,
      import_batches: f.batchId,
      import_rows: f.rowId,
    },
  };
}

export type Scope =
  | { kind: 'tenant'; institutionId: string }
  | { kind: 'platform' }
  | { kind: 'anonymous' }
  | { kind: 'owner' };

export interface Harness {
  schema: string;
  /** Connection as the DATABASE_URL role (owner/superuser), search_path set to the scratch schema. */
  owner: pg.Client;
  A: TenantFixture;
  B: TenantFixture;
  /** `-c search_path=<schema> -c role=igaro_app`: pass as pg `options` so a pool runs as igaro_app. */
  appConnectionOptions: string;
  /** Run fn in a rolled-back transaction as igaro_app with the given RLS settings. */
  asApp<T>(settings: Record<string, string>, fn: (c: pg.Client) => Promise<T>): Promise<T>;
  /** igaro_app with a tenant session for the institution (what the API's DAL sets). */
  asTenant<T>(institutionId: string, fn: (c: pg.Client) => Promise<T>): Promise<T>;
  /** igaro_app with a platform-admin session. */
  asPlatform<T>(fn: (c: pg.Client) => Promise<T>): Promise<T>;
  /** igaro_app with no scope at all (a public/unauthenticated connection). */
  asAnonymous<T>(fn: (c: pg.Client) => Promise<T>): Promise<T>;
  /** The connecting role (usually superuser: bypasses RLS and grants, but not triggers). Rolled back. */
  asOwner<T>(fn: (c: pg.Client) => Promise<T>): Promise<T>;
  /** Run fn as the igaro_worker role (T-028, ADR 0019) with the given RLS settings. Rolled back. */
  asWorker<T>(settings: Record<string, string>, fn: (c: pg.Client) => Promise<T>): Promise<T>;
  asScope<T>(scope: Scope, fn: (c: pg.Client) => Promise<T>): Promise<T>;
  /** Run fn under a savepoint; returns the SQLSTATE of the error, or undefined if it succeeded. */
  code(fn: () => Promise<unknown>): Promise<string | undefined>;
  /** Text snapshot of every row in a table, read as owner (to prove refused statements changed nothing). */
  snapshot(table: TenantTable): Promise<string[]>;
  /** Next unused UUID (unique within this harness). */
  uid(): string;
  /** Drop the scratch schema and disconnect. */
  close(): Promise<void>;
}

/** Applies every migration into a scratch schema, seeds tenants A and B, and returns the helpers. */
export async function createHarness(prefix = 'h'): Promise<Harness> {
  if (!databaseUrl) throw new Error('DATABASE_URL is not set');
  const schema = `${prefix}_${randomBytes(4).toString('hex')}`;
  const owner = new pg.Client({ connectionString: databaseUrl });
  await owner.connect();
  let n = 0;
  const uid = (): string => {
    n += 1;
    return `00000000-0000-4000-a000-${String(n).padStart(12, '0')}`;
  };
  const close = async (): Promise<void> => {
    await owner.query('ROLLBACK').catch(() => undefined);
    await owner.query('RESET search_path').catch(() => undefined);
    await owner.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`).catch(() => undefined);
    await owner.end().catch(() => undefined);
  };

  const A = fixture('a', 'a');
  const B = fixture('b', 'b');
  try {
    await owner.query(`CREATE SCHEMA "${schema}"`);
    await owner.query(`SET search_path TO "${schema}"`);
    const dirs = readdirSync(migrationsDir, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => d.name)
      .sort();
    for (const d of dirs) {
      await owner.query(readFileSync(new URL(`${d}/migration.sql`, migrationsDir), 'utf8'));
    }
    // The first migration grants USAGE for the current schema; repeat explicitly so a harness
    // never depends on that detail.
    await owner.query(`GRANT USAGE ON SCHEMA "${schema}" TO igaro_app`);
    await seed(owner, [A, B]);
  } catch (e) {
    await close();
    throw e;
  }

  async function scoped<T>(
    settings: Record<string, string>,
    role: 'igaro_app' | 'igaro_worker' | false,
    fn: (c: pg.Client) => Promise<T>,
  ): Promise<T> {
    await owner.query('BEGIN');
    try {
      for (const [k, v] of Object.entries(settings)) {
        await owner.query('SELECT set_config($1, $2, true)', [k, v]);
      }
      if (role) await owner.query(`SET LOCAL ROLE ${role}`);
      return await fn(owner);
    } finally {
      await owner.query('ROLLBACK');
    }
  }

  const harness: Harness = {
    schema,
    owner,
    A,
    B,
    appConnectionOptions: `-c search_path=${schema} -c role=igaro_app`,
    asApp: (settings, fn) => scoped(settings, 'igaro_app', fn),
    asWorker: (settings, fn) => scoped(settings, 'igaro_worker', fn),
    asTenant: (institutionId, fn) => scoped({ 'app.institution_id': institutionId }, 'igaro_app', fn),
    asPlatform: (fn) => scoped({ 'app.is_platform_admin': 'true' }, 'igaro_app', fn),
    asAnonymous: (fn) => scoped({}, 'igaro_app', fn),
    // Settings keep statements valid for a non-superuser owner too; a superuser ignores them.
    asOwner: (fn) => scoped({ 'app.is_platform_admin': 'true', 'app.institution_id': A.institutionId }, false, fn),
    asScope(scope, fn) {
      switch (scope.kind) {
        case 'tenant':
          return harness.asTenant(scope.institutionId, fn);
        case 'platform':
          return harness.asPlatform(fn);
        case 'anonymous':
          return harness.asAnonymous(fn);
        case 'owner':
          return harness.asOwner(fn);
      }
    },
    async code(fn) {
      await owner.query('SAVEPOINT harness_s');
      try {
        await fn();
        await owner.query('RELEASE SAVEPOINT harness_s');
        return undefined;
      } catch (e) {
        await owner.query('ROLLBACK TO SAVEPOINT harness_s');
        return (e as { code?: string }).code ?? String(e);
      }
    },
    async snapshot(table) {
      return scoped({ 'app.is_platform_admin': 'true' }, false, async (c) => {
        const r = await c.query(`SELECT t::text AS row FROM "${table}" t ORDER BY id`);
        return r.rows.map((x: { row: string }) => x.row);
      });
    },
    uid,
    close,
  };
  return harness;
}

async function seed(c: pg.Client, tenants: TenantFixture[]): Promise<void> {
  await c.query('BEGIN');
  try {
    await c.query(`SELECT set_config('app.is_platform_admin','true',true)`);
    for (const f of tenants) {
      await c.query(`SELECT set_config('app.institution_id',$1,true)`, [f.institutionId]);
      const i = f.institutionId;
      await c.query(`INSERT INTO institutions (id, name, slug, updated_at) VALUES ($1,$2,$3,now())`, [
        i,
        `Institution ${f.tag}`,
        f.slug,
      ]);
      await c.query(
        `INSERT INTO institution_keys (id, institution_id, kid, public_key, encrypted_private_key)
         VALUES ($1,$2,$3,'test-pub','test-enc')`,
        [f.keyId, i, f.kid],
      );
      await c.query(
        `INSERT INTO users (id, institution_id, email, name, role, updated_at)
         VALUES ($1,$2,$3,'Admin','INSTITUTION_ADMIN',now())`,
        [f.userId, i, f.email],
      );
      await c.query(
        `INSERT INTO sessions (id, institution_id, user_id, token_hash, expires_at)
         VALUES ($1,$2,$3,$4, now() + interval '1 hour')`,
        [f.sessionId, i, f.userId, `test-session-hash-${f.tag}`],
      );
      await c.query(
        `INSERT INTO invites (id, institution_id, email, token_hash, expires_at)
         VALUES ($1,$2,$3,$4, now() + interval '1 day')`,
        [f.inviteId, i, `invitee-${f.tag}@example.test`, `test-invite-hash-${f.tag}`],
      );
      await c.query(
        `INSERT INTO password_resets (id, institution_id, user_id, token_hash, expires_at)
         VALUES ($1,$2,$3,$4, now() + interval '1 hour')`,
        [f.resetId, i, f.userId, `test-reset-hash-${f.tag}`],
      );
      await c.query(
        `INSERT INTO credential_types (id, institution_id, code, name, kind, updated_at)
         VALUES ($1,$2,'STUDENT_ID','Student ID','ID_CARD',now())`,
        [f.typeId, i],
      );
      await c.query(
        `INSERT INTO credential_holders (id, institution_id, full_name, updated_at)
         VALUES ($1,$2,$3,now())`,
        [f.holderId, i, `Holder ${f.tag}`],
      );
      await c.query(
        `INSERT INTO credentials (id, institution_id, holder_id, type_id, credential_number, status,
           payload, data_hash, issuer_kid, signature, verification_token, holder_token_hash, updated_at)
         VALUES ($1,$2,$3,$4,$5,'ACTIVE','{}','test-hash',$6,'test-sig',$7,$8,now())`,
        [f.credentialId, i, f.holderId, f.typeId, f.credentialNumber, f.kid, f.verificationToken, `test-holder-hash-${f.tag}`],
      );
      await c.query(
        `INSERT INTO credential_events (id, institution_id, credential_id, type) VALUES ($1,$2,$3,'ISSUED')`,
        [f.eventId, i, f.credentialId],
      );
      await c.query(
        `INSERT INTO verification_logs (id, institution_id, credential_id, result) VALUES ($1,$2,$3,'VERIFIED')`,
        [f.verificationLogId, i, f.credentialId],
      );
      await c.query(
        `INSERT INTO audit_logs (id, institution_id, seq, action, prev_hash, entry_hash)
         VALUES ($1,$2,1,'test.seed','genesis',$3)`,
        [f.auditLogId, i, `test-entry-hash-${f.tag}`],
      );
      await c.query(
        `INSERT INTO audit_head_hashes (id, institution_id, day, head_hash, signature, signer_kid)
         VALUES ($1,$2,'2026-11-24',$3,'test-sig',$4)`,
        [f.headHashId, i, `test-head-${f.tag}`, f.kid],
      );
      await c.query(
        `INSERT INTO audit_head_timestamps (id, head_id, institution_id, state, ots_proof) VALUES ($1,$2,$3,'PENDING','\\x00')`,
        [f.headTimestampId, f.headHashId, i],
      );
      await c.query(`INSERT INTO import_batches (id, institution_id, filename) VALUES ($1,$2,'test.csv')`, [f.batchId, i]);
      await c.query(
        `INSERT INTO import_rows (id, institution_id, batch_id, row_number, data) VALUES ($1,$2,$3,1,'{}')`,
        [f.rowId, i, f.batchId],
      );
    }
    await c.query('COMMIT');
  } catch (e) {
    await c.query('ROLLBACK').catch(() => undefined);
    throw e;
  }
}

/**
 * A valid INSERT for any tenant table that writes a NEW row owned by `target`, referencing only
 * `target`'s own parent rows. Under another tenant's scope the only thing wrong with it is the tenant,
 * so a refusal proves RLS/grants rather than an unrelated constraint.
 */
export function insertForTenant(
  table: TenantTable,
  target: TenantFixture,
  newId: string,
): { sql: string; params: unknown[] } {
  const t = target;
  const x = newId.slice(-6);
  switch (table) {
    case 'institutions':
      return { sql: `INSERT INTO institutions (id, name, slug, updated_at) VALUES ($1,'x',$2,now())`, params: [newId, `slug-${x}`] };
    case 'institution_keys':
      return {
        sql: `INSERT INTO institution_keys (id, institution_id, kid, public_key, encrypted_private_key, status)
              VALUES ($1,$2,$3,'p','e','RETIRED')`,
        params: [newId, t.institutionId, `kid-${x}`],
      };
    case 'users':
      return {
        sql: `INSERT INTO users (id, institution_id, email, name, role, updated_at)
              VALUES ($1,$2,$3,'x','INSTITUTION_ADMIN',now())`,
        params: [newId, t.institutionId, `u-${x}@example.test`],
      };
    case 'sessions':
      return {
        sql: `INSERT INTO sessions (id, institution_id, user_id, token_hash, expires_at) VALUES ($1,$2,$3,$4,now())`,
        params: [newId, t.institutionId, t.userId, `th-${x}`],
      };
    case 'invites':
      return {
        sql: `INSERT INTO invites (id, institution_id, email, token_hash, expires_at) VALUES ($1,$2,$3,$4,now())`,
        params: [newId, t.institutionId, `i-${x}@example.test`, `th-${x}`],
      };
    case 'password_resets':
      return {
        sql: `INSERT INTO password_resets (id, institution_id, user_id, token_hash, expires_at) VALUES ($1,$2,$3,$4,now())`,
        params: [newId, t.institutionId, t.userId, `th-${x}`],
      };
    case 'credential_types':
      return {
        sql: `INSERT INTO credential_types (id, institution_id, code, name, kind, updated_at)
              VALUES ($1,$2,$3,'x','ID_CARD',now())`,
        params: [newId, t.institutionId, `C-${x}`],
      };
    case 'credential_holders':
      return {
        sql: `INSERT INTO credential_holders (id, institution_id, full_name, updated_at) VALUES ($1,$2,'x',now())`,
        params: [newId, t.institutionId],
      };
    case 'credentials':
      return {
        sql: `INSERT INTO credentials (id, institution_id, holder_id, type_id, credential_number, status,
                payload, data_hash, issuer_kid, signature, verification_token, holder_token_hash, updated_at)
              VALUES ($1,$2,$3,$4,$5,'DRAFT','{}','h',$6,'s',$7,$8,now())`,
        params: [newId, t.institutionId, t.holderId, t.typeId, `N-${x}`, t.kid, `vt-${x}`, `ht-${x}`],
      };
    case 'credential_events':
      return {
        sql: `INSERT INTO credential_events (id, institution_id, credential_id, type) VALUES ($1,$2,$3,'SUSPENDED')`,
        params: [newId, t.institutionId, t.credentialId],
      };
    case 'verification_logs':
      return {
        sql: `INSERT INTO verification_logs (id, institution_id, result) VALUES ($1,$2,'VERIFIED')`,
        params: [newId, t.institutionId],
      };
    case 'audit_logs':
      return {
        sql: `INSERT INTO audit_logs (id, institution_id, seq, action, prev_hash, entry_hash) VALUES ($1,$2,2,'x',$3,$4)`,
        params: [newId, t.institutionId, `test-entry-hash-${t.tag}`, `e-${x}`],
      };
    case 'audit_head_hashes':
      return {
        sql: `INSERT INTO audit_head_hashes (id, institution_id, day, head_hash, signature, signer_kid)
              VALUES ($1,$2,'2026-11-25','h','s',$3)`,
        params: [newId, t.institutionId, t.kid],
      };
    case 'audit_head_timestamps':
      return {
        sql: `INSERT INTO audit_head_timestamps (id, head_id, institution_id, state, ots_proof)
              VALUES ($1,$2,$3,'COMPLETE','\\x00')`,
        params: [newId, t.headHashId, t.institutionId],
      };
    case 'import_batches':
      return { sql: `INSERT INTO import_batches (id, institution_id) VALUES ($1,$2)`, params: [newId, t.institutionId] };
    case 'import_rows':
      return {
        sql: `INSERT INTO import_rows (id, institution_id, batch_id, row_number, data) VALUES ($1,$2,$3,2,'{}')`,
        params: [newId, t.institutionId, t.batchId],
      };
  }
}

/** A column igaro_app may UPDATE on each table (undefined: the app role may not update the table at all). */
export const MUTABLE_ASSIGNMENT: Record<TenantTable, string | undefined> = {
  institutions: `card_title = 'pwned'`,
  institution_keys: `status = 'RETIRED'`,
  users: `name = 'pwned'`,
  sessions: `expires_at = now() + interval '2 days'`,
  invites: `used_at = now()`,
  password_resets: `used_at = now()`,
  credential_types: `name = 'pwned'`,
  credential_holders: `full_name = 'pwned'`,
  credentials: `anchor_status = 'PENDING'`,
  credential_events: `anchored_at = now()`,
  verification_logs: undefined,
  audit_logs: undefined,
  audit_head_hashes: undefined,
  audit_head_timestamps: undefined,
  import_batches: `total_rows = 999`,
  import_rows: `error = 'pwned'`,
};
