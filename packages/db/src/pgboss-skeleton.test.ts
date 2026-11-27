// T-051 (ADR 0038): the migration creates the pg-boss schema skeleton for the owner. The pg-boss tables and the API's
// enqueue-only grants are proven in apps/worker (pgboss-setup.integration.test.ts), which needs pg-boss itself.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createHarness, hasDatabase, type Harness } from './testing/harness.js';

describe.skipIf(!hasDatabase)('pgboss schema skeleton migration (needs Postgres at DATABASE_URL)', () => {
  let h: Harness;
  beforeAll(async () => {
    h = await createHarness('t051s');
  }, 60000);
  afterAll(async () => {
    await h?.close();
  });

  const one = async (sql: string, params: unknown[] = []): Promise<unknown> =>
    (await h.owner.query(sql, params)).rows[0] as unknown;

  it('creates the schema, closed to PUBLIC', async () => {
    expect(await one(`SELECT nspname FROM pg_namespace WHERE nspname = 'pgboss'`)).toEqual({ nspname: 'pgboss' });
    expect(await one(`SELECT has_schema_privilege('public', 'pgboss', 'USAGE') AS u`)).toEqual({ u: false });
    expect(await one(`SELECT has_schema_privilege('public', 'pgboss', 'CREATE') AS c`)).toEqual({ c: false });
  });

  it('igaro_app may use it but not create in it; igaro_worker may do both', async () => {
    expect(await one(`SELECT has_schema_privilege('igaro_app', 'pgboss', 'USAGE') AS u, has_schema_privilege('igaro_app', 'pgboss', 'CREATE') AS c`)).toEqual({ u: true, c: false });
    expect(await one(`SELECT has_schema_privilege('igaro_worker', 'pgboss', 'USAGE') AS u, has_schema_privilege('igaro_worker', 'pgboss', 'CREATE') AS c`)).toEqual({ u: true, c: true });
  });

  it('later tables, sequences and functions from the owner default to igaro_worker only', async () => {
    const rows = (
      await h.owner.query(
        `SELECT d.defaclobjtype AS kind, d.defaclacl::text AS acl
           FROM pg_default_acl d JOIN pg_namespace n ON n.oid = d.defaclnamespace
          WHERE n.nspname = 'pgboss' AND d.defaclrole = (SELECT oid FROM pg_roles WHERE rolname = current_user)
          ORDER BY 1`,
      )
    ).rows as { kind: string; acl: string }[];
    expect(rows.map((r) => r.kind)).toEqual(['S', 'f', 'r']);
    for (const r of rows) {
      expect(r.acl).toContain('igaro_worker=');
      expect(r.acl).not.toContain('igaro_app=');
    }
  });
});
