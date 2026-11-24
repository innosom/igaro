// Seed tests (T-007). DB part skipped when DATABASE_URL is unset; runs in scratch schemas.
//
// The DB tests run the seed as a throw-away NOSUPERUSER NOBYPASSRLS role that OWNS every table in
// the scratch schema (via SET ROLE). Table owners are subject to RLS because every table is
// FORCE ROW LEVEL SECURITY, so this proves the seed sets the scopes the policies need. If the
// connecting role may not create roles, the tests fall back to the connecting role (which is
// usually a superuser and bypasses RLS); the first DB test records which mode ran.
import { randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { verify } from '@node-rs/argon2';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ARGON2ID_PARAMS,
  loadSeedConfig,
  runSeed,
  TEST_ONLY_DEFAULT_PASSWORD,
  type SeedConfig,
} from './seed.js';

const url = process.env.DATABASE_URL;
const migrationsDir = new URL('../prisma/migrations/', import.meta.url);
const STRONG = 'a-long-enough-secret-1';

describe('loadSeedConfig', () => {
  it('allows the test-only default only for development, test or SEED_ALLOW_TEST_PASSWORD=1', () => {
    for (const env of [
      { NODE_ENV: 'development' },
      { NODE_ENV: 'test' },
      { SEED_ALLOW_TEST_PASSWORD: '1' },
    ]) {
      const c = loadSeedConfig(env);
      expect(c.platformAdminPassword).toBe(TEST_ONLY_DEFAULT_PASSWORD);
      expect(c.eauAdminPassword).toBe(TEST_ONLY_DEFAULT_PASSWORD);
    }
  });

  it('requires strong explicit passwords when NODE_ENV is unset, unknown or production', () => {
    for (const NODE_ENV of [undefined, 'staging', 'production']) {
      expect(() => loadSeedConfig({ NODE_ENV })).toThrow(/must be set/);
      expect(() => loadSeedConfig({ NODE_ENV, SEED_ADMIN_PASSWORD: 'short' })).toThrow(/at least/);
      expect(() =>
        loadSeedConfig({ NODE_ENV, SEED_ADMIN_PASSWORD: TEST_ONLY_DEFAULT_PASSWORD }),
      ).toThrow(/test-only default/);
    }
  });

  it('refuses the default in production even with SEED_ALLOW_TEST_PASSWORD=1', () => {
    expect(() =>
      loadSeedConfig({ NODE_ENV: 'production', SEED_ALLOW_TEST_PASSWORD: '1' }),
    ).toThrow();
  });

  it('checks the EAU admin password too when the demo is seeded', () => {
    expect(() =>
      loadSeedConfig({
        NODE_ENV: 'staging',
        SEED_ADMIN_PASSWORD: STRONG,
        SEED_EAU_ADMIN_PASSWORD: TEST_ONLY_DEFAULT_PASSWORD,
      }),
    ).toThrow(/SEED_EAU_ADMIN_PASSWORD/);
  });

  it('never echoes the password in the error message', () => {
    expect(() =>
      loadSeedConfig({ NODE_ENV: 'production', SEED_ADMIN_PASSWORD: 'zq9x-tiny' }),
    ).toThrow(/^(?!.*zq9x-tiny)/s);
  });

  it('production seeds only the platform admin unless SEED_DEMO=1', () => {
    const p = loadSeedConfig({ NODE_ENV: 'production', SEED_ADMIN_PASSWORD: STRONG });
    expect(p.production).toBe(true);
    expect(p.demo).toBe(false);
    const d = loadSeedConfig({
      NODE_ENV: 'production',
      SEED_ADMIN_PASSWORD: STRONG,
      SEED_DEMO: '1',
    });
    expect(d.demo).toBe(true);
    expect(d.eauAdminPassword).toBe(STRONG);
    expect(loadSeedConfig({ NODE_ENV: 'test' }).demo).toBe(true);
  });

  it('rejects identical platform and EAU admin emails (case-insensitive)', () => {
    expect(() =>
      loadSeedConfig({
        NODE_ENV: 'test',
        SEED_ADMIN_EMAIL: 'Same@Example.test',
        SEED_EAU_ADMIN_EMAIL: 'same@example.test',
      }),
    ).toThrow(/must differ/);
  });

  it('exports Argon2id parameters', () => {
    expect(ARGON2ID_PARAMS.algorithm).toBe(2);
    expect(ARGON2ID_PARAMS.memoryCost).toBeGreaterThanOrEqual(19456);
  });
});

describe.skipIf(!url)('runSeed (needs Postgres at DATABASE_URL)', () => {
  const suffix = randomBytes(4).toString('hex');
  const role = `t007_owner_${suffix}`;
  const schemas: string[] = [];
  let c: pg.Client;
  let restricted = false;

  const config: SeedConfig = {
    production: false,
    demo: true,
    platformAdminEmail: 'platform-admin@igaro.test',
    platformAdminPassword: 'seed-test-password-1',
    eauAdminEmail: 'admin@eau.test',
    eauAdminPassword: 'seed-test-password-2',
  };

  /** Apply all migrations in a new scratch schema, then hand it to the restricted role. */
  async function newSchema(name: string): Promise<void> {
    schemas.push(name);
    await c.query(`CREATE SCHEMA "${name}"`);
    await c.query(`SET search_path TO "${name}"`);
    const dirs = readdirSync(migrationsDir, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => d.name)
      .sort();
    for (const d of dirs) {
      await c.query(readFileSync(new URL(`${d}/migration.sql`, migrationsDir), 'utf8'));
    }
    if (!restricted) return;
    await c.query(`ALTER SCHEMA "${name}" OWNER TO "${role}"`);
    await c.query(`
      DO $$ DECLARE r record; BEGIN
        FOR r IN SELECT c.oid::regclass AS o FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                 WHERE n.nspname = '${name}' AND c.relkind IN ('r','p') LOOP
          EXECUTE format('ALTER TABLE %s OWNER TO "${role}"', r.o);
        END LOOP;
        FOR r IN SELECT p.oid::regprocedure AS o FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                 WHERE n.nspname = '${name}' LOOP
          EXECUTE format('ALTER FUNCTION %s OWNER TO "${role}"', r.o);
        END LOOP;
        FOR r IN SELECT t.oid::regtype AS o FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
                 WHERE n.nspname = '${name}' AND t.typtype = 'e' LOOP
          EXECUTE format('ALTER TYPE %s OWNER TO "${role}"', r.o);
        END LOOP;
      END $$`);
    await c.query(`SET ROLE "${role}"`);
  }

  const scoped = async <T>(fn: () => Promise<T>): Promise<T> => {
    await c.query('BEGIN');
    try {
      await c.query("SELECT set_config('app.is_platform_admin', 'true', true)");
      return await fn();
    } finally {
      await c.query('ROLLBACK');
    }
  };
  const count = (table: string) =>
    scoped(async () =>
      Number((await c.query<{ n: string }>(`SELECT count(*) AS n FROM ${table}`)).rows[0]?.n),
    );

  beforeAll(async () => {
    c = new pg.Client({ connectionString: url });
    await c.connect();
    try {
      await c.query(`CREATE ROLE "${role}" NOSUPERUSER NOBYPASSRLS NOLOGIN`);
      await c.query(`GRANT "${role}" TO CURRENT_USER`);
      restricted = true;
    } catch {
      restricted = false;
    }
    await newSchema(`t007_${suffix}`);
  });

  afterAll(async () => {
    if (!c) return;
    await c.query('RESET ROLE');
    await c.query('RESET search_path');
    for (const s of schemas) await c.query(`DROP SCHEMA IF EXISTS "${s}" CASCADE`);
    if (restricted) {
      await c.query(`DROP OWNED BY "${role}"`);
      await c.query(`DROP ROLE IF EXISTS "${role}"`);
    }
    await c.end();
  });

  it('runs as a NOSUPERUSER NOBYPASSRLS owner when the connecting role may create roles', async () => {
    if (!restricted) {
      console.warn(
        'T-007: cannot create roles; seed ran as the connecting role (RLS may be bypassed)',
      );
      return;
    }
    const r = await c.query<{ rolsuper: boolean; rolbypassrls: boolean; u: string }>(
      'SELECT rolsuper, rolbypassrls, current_user AS u FROM pg_roles WHERE rolname = current_user',
    );
    expect(r.rows[0]).toEqual({ rolsuper: false, rolbypassrls: false, u: role });
  });

  it('seeds everything on first run and nothing on the second (idempotent)', async () => {
    const first = await runSeed(c, config);
    expect(first.created).toEqual({ users: 2, institutions: 1, credentialTypes: 2, holders: 3 });
    const counts = async () => [
      await count('institutions'),
      await count('users'),
      await count('credential_types'),
      await count('credential_holders'),
    ];
    expect(await counts()).toEqual([1, 2, 2, 3]);

    const second = await runSeed(c, config);
    expect(second.institutionId).toBe(first.institutionId);
    expect(second.created).toEqual({ users: 0, institutions: 0, credentialTypes: 0, holders: 0 });
    expect(await counts()).toEqual([1, 2, 2, 3]);
  });

  it('creates the platform admin and EAU admin with Argon2id hashes', async () => {
    const rows = await scoped(
      async () =>
        (
          await c.query<{
            email: string;
            role: string;
            institution_id: string | null;
            password_hash: string;
            status: string;
          }>('SELECT email, role, institution_id, password_hash, status FROM users')
        ).rows,
    );
    const byEmail = Object.fromEntries(rows.map((u) => [u.email, u]));
    const pa = byEmail['platform-admin@igaro.test'];
    const ea = byEmail['admin@eau.test'];
    expect(pa?.role).toBe('PLATFORM_ADMIN');
    expect(pa?.institution_id).toBeNull();
    expect(ea?.role).toBe('INSTITUTION_ADMIN');
    expect(ea?.institution_id).not.toBeNull();
    for (const u of [pa, ea]) {
      expect(u?.status).toBe('ACTIVE');
      expect(u?.password_hash.startsWith('$argon2id$')).toBe(true);
    }
    expect(await verify(pa!.password_hash, config.platformAdminPassword)).toBe(true);
    expect(await verify(ea!.password_hash, config.eauAdminPassword)).toBe(true);
    expect(await verify(pa!.password_hash, config.eauAdminPassword)).toBe(false);
  });

  it('does not rotate existing passwords on re-run', async () => {
    await runSeed(c, { ...config, platformAdminPassword: 'a-different-password-9' });
    const hashRow = await scoped(
      async () =>
        (
          await c.query<{ password_hash: string }>(
            "SELECT password_hash FROM users WHERE email = 'platform-admin@igaro.test'",
          )
        ).rows[0],
    );
    expect(await verify(hashRow!.password_hash, config.platformAdminPassword)).toBe(true);
  });

  it('creates the EAU institution and both credential type templates with attributes', async () => {
    const { inst, types, keys } = await scoped(async () => ({
      inst: await c.query<{ name: string; slug: string; status: string }>(
        'SELECT name, slug, status FROM institutions',
      ),
      types: await c.query<{
        code: string;
        kind: string;
        validity_days: number | null;
        attribute_schema: { key: string; required: boolean }[];
      }>('SELECT code, kind, validity_days, attribute_schema FROM credential_types ORDER BY code'),
      keys: await c.query('SELECT 1 FROM institution_keys'),
    }));

    expect(inst.rows).toEqual([{ name: 'East Africa University', slug: 'eau', status: 'ACTIVE' }]);
    expect(types.rows.map((t) => [t.code, t.kind])).toEqual([
      ['CERTIFICATE', 'CERTIFICATE'],
      ['STUDENT_ID', 'ID_CARD'],
    ]);
    const cert = types.rows[0]!;
    const sid = types.rows[1]!;
    expect(sid.validity_days).toBe(365);
    expect(sid.attribute_schema.map((a) => a.key)).toEqual(['program', 'faculty', 'yearOfStudy']);
    expect(sid.attribute_schema.find((a) => a.key === 'program')?.required).toBe(true);
    expect(cert.attribute_schema.map((a) => a.key)).toEqual([
      'title',
      'program',
      'grade',
      'awardDate',
    ]);
    // Signing keys are explicitly not the seed's job (T-014/T-015).
    expect(keys.rowCount).toBe(0);
  });

  it('with demo disabled (production default) creates only the platform admin', async () => {
    await c.query('RESET ROLE');
    await newSchema(`t007p_${suffix}`);
    const res = await runSeed(c, { ...config, production: true, demo: false });
    expect(res).toEqual({
      institutionId: null,
      created: { users: 1, institutions: 0, credentialTypes: 0, holders: 0 },
    });
    expect(await count('users')).toBe(1);
    expect(await count('institutions')).toBe(0);
    expect(await count('credential_types')).toBe(0);
    expect(await count('credential_holders')).toBe(0);
  });
});
