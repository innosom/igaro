// T-050: runtime role startup check. Needs Postgres at DATABASE_URL (skipped otherwise).
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { assertRuntimeRole, checkRuntimeRole, RuntimeRoleError } from './role-check.js';
import { createHarness, hasDatabase, type Harness } from './testing/harness.js';

describe.skipIf(!hasDatabase)('runtime role check', () => {
  let h: Harness;
  beforeAll(async () => {
    h = await createHarness('t050');
  });
  afterAll(async () => {
    await h.close();
  });

  // Run fn inside a transaction that is always rolled back, after the setup statements.
  const as = async <T>(setup: string[], fn: () => Promise<T>): Promise<T> => {
    await h.owner.query('BEGIN');
    try {
      for (const s of setup) await h.owner.query(s);
      return await fn();
    } finally {
      await h.owner.query('ROLLBACK');
    }
  };

  it('accepts igaro_app', async () => {
    const r = await as(['SET LOCAL ROLE igaro_app'], () => checkRuntimeRole(h.owner));
    expect(r).toEqual({ role: 'igaro_app', problems: [] });
  });

  it('flags a superuser', async () => {
    const r = await checkRuntimeRole(h.owner);
    expect(r.problems).toContain('role is a superuser');
  });

  it('flags BYPASSRLS', async () => {
    const r = await as(
      ['CREATE ROLE t050_bypass NOLOGIN NOSUPERUSER BYPASSRLS', 'SET LOCAL ROLE t050_bypass'],
      () => checkRuntimeRole(h.owner),
    );
    expect(r.problems).toEqual(['role has BYPASSRLS']);
  });

  it('flags a table owner', async () => {
    const r = await as(
      [
        'CREATE ROLE t050_owner NOLOGIN NOSUPERUSER NOBYPASSRLS',
        'ALTER TABLE credentials OWNER TO t050_owner',
        // Without USAGE the schema is skipped on the search path and current_schema() is NULL.
        `GRANT USAGE ON SCHEMA ${(await h.owner.query<{ s: string }>('SELECT current_schema() AS s')).rows[0]!.s} TO t050_owner`,
        'SET LOCAL ROLE t050_owner',
      ],
      () => checkRuntimeRole(h.owner),
    );
    expect(r.problems).toEqual(['role owns tenant tables']);
  });

  it('production refuses an unsafe role; development warns; safe role passes', async () => {
    const warns: string[] = [];
    const warn = (m: string) => warns.push(m);
    await expect(assertRuntimeRole(h.owner, { nodeEnv: 'production', warn })).rejects.toBeInstanceOf(
      RuntimeRoleError,
    );
    await assertRuntimeRole(h.owner, { nodeEnv: 'development', warn });
    expect(warns).toHaveLength(1);
    await as(['SET LOCAL ROLE igaro_app'], () => assertRuntimeRole(h.owner, { nodeEnv: 'production', warn }));
    expect(warns).toHaveLength(1);
  });
});
