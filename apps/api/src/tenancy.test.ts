// Integration tests for the tenant-scoped data-access layer (T-008). Skipped when DATABASE_URL is
// unset. Applies every migration into a scratch schema (same approach as packages/db) and connects
// the API pool as the restricted igaro_app role so RLS is actually enforced.
import { randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import type { FastifyInstance } from 'fastify';
import { buildApp } from './app.js';
import { Db, type PlatformSession, type TenantSession } from './db.js';
import { NotFoundError } from './errors.js';
import { HolderRepository } from './repositories.js';

const url = process.env.DATABASE_URL;
const migrationsDir = new URL('../../../packages/db/prisma/migrations/', import.meta.url);

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const HA = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const HB = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

const tenantA: TenantSession = { kind: 'tenant', userId: HA, institutionId: A };
const tenantB: TenantSession = { kind: 'tenant', userId: HB, institutionId: B };
const platform: PlatformSession = { kind: 'platform', userId: HA };

describe.skipIf(!url)('tenant-scoped data access (needs Postgres at DATABASE_URL)', () => {
  const schema = `t008_${randomBytes(4).toString('hex')}`;
  let owner: pg.Client;
  let db: Db;

  beforeAll(async () => {
    owner = new pg.Client({ connectionString: url });
    await owner.connect();
    await owner.query(`CREATE SCHEMA "${schema}"`);
    await owner.query(`SET search_path TO "${schema}"`);
    const dirs = readdirSync(migrationsDir, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => d.name)
      .sort();
    for (const d of dirs) {
      await owner.query(readFileSync(new URL(`${d}/migration.sql`, migrationsDir), 'utf8'));
    }
    await owner.query(`GRANT USAGE ON SCHEMA "${schema}" TO igaro_app`);

    await owner.query('BEGIN');
    await owner.query(`SELECT set_config('app.is_platform_admin','true',true)`);
    for (const [inst, slug] of [
      [A, 'a'],
      [B, 'b'],
    ] as const) {
      await owner.query(
        `INSERT INTO institutions (id, name, slug, updated_at) VALUES ($1,$2,$2,now())`,
        [inst, slug],
      );
    }
    for (const [inst, h, name] of [
      [A, HA, 'Holder A'],
      [B, HB, 'Holder B'],
    ] as const) {
      await owner.query(`SELECT set_config('app.institution_id',$1,true)`, [inst]);
      await owner.query(
        `INSERT INTO credential_holders (id, institution_id, full_name, updated_at)
         VALUES ($1,$2,$3,now())`,
        [h, inst, name],
      );
    }
    await owner.query('COMMIT');

    // The API pool: same URL, but every connection runs as igaro_app inside the scratch schema.
    // (igaro_app is NOLOGIN, so the owner connection assumes it via the startup `role` option.)
    db = new Db({
      connectionString: url!,
      max: 4,
      poolConfig: { options: `-c search_path=${schema} -c role=igaro_app` },
    });
  });

  afterAll(async () => {
    await db?.close();
    if (!owner) return;
    await owner.query('ROLLBACK').catch(() => undefined);
    await owner.query('RESET search_path');
    await owner.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    await owner.end();
  });

  it('runs as a role that does not bypass RLS', async () => {
    const r = await db.withTenant(tenantA, (c) =>
      c.query(`SELECT current_user AS u, rolsuper, rolbypassrls
                 FROM pg_roles WHERE rolname = current_user`),
    );
    expect(r.rows[0]).toEqual({ u: 'igaro_app', rolsuper: false, rolbypassrls: false });
  });

  it('withTenant sets the institution from the session and it does not leak after commit', async () => {
    const inside = await db.withTenant(tenantA, async (c) => {
      const r = await c.query(
        `SELECT current_setting('app.institution_id', true) AS inst,
                current_setting('app.is_platform_admin', true) AS pa`,
      );
      return r.rows[0] as { inst: string; pa: string | null };
    });
    expect(inside.inst).toBe(A);
    expect(inside.pa ?? '').toBe('');
    // set_config(..., true) is transaction-local: the pooled connection is clean afterwards.
    const after = await db.pool.query(`SELECT current_setting('app.institution_id', true) AS inst`);
    expect(after.rows[0].inst ?? '').toBe('');
  });

  it('sets app.is_platform_admin only for a platform session', async () => {
    const pa = await db.withTenant(platform, async (c) => {
      const r = await c.query(`SELECT current_setting('app.is_platform_admin', true) AS pa`);
      return r.rows[0].pa as string;
    });
    expect(pa).toBe('true');
  });

  it('RLS: tenant A sees only its own rows, even with an unfiltered query', async () => {
    const rows = await db.withTenant(tenantA, async (c) => {
      const r = await c.query(`SELECT id, institution_id FROM credential_holders`);
      return r.rows as { id: string; institution_id: string }[];
    });
    expect(rows).toEqual([{ id: HA, institution_id: A }]);
    const other = await db.withTenant(tenantA, (c) =>
      c.query(`SELECT 1 FROM credential_holders WHERE id = $1`, [HB]),
    );
    expect(other.rowCount).toBe(0);
  });

  it('RLS: with no scope, nothing is visible and cross-tenant inserts are refused', async () => {
    const none = await db.pool.query(`SELECT 1 FROM credential_holders`);
    expect(none.rowCount).toBe(0);
    await expect(
      db.withTenant(tenantA, (c) =>
        c.query(
          `INSERT INTO credential_holders (id, institution_id, full_name, updated_at)
           VALUES (gen_random_uuid(), $1, 'evil', now())`,
          [B],
        ),
      ),
    ).rejects.toMatchObject({ code: '42501' });
  });

  it('rolls back on error', async () => {
    await expect(
      db.withTenant(tenantA, async (c) => {
        await c.query(
          `INSERT INTO credential_holders (id, institution_id, full_name, updated_at)
           VALUES (gen_random_uuid(), app_institution_id(), 'temp', now())`,
        );
        throw new Error('abort');
      }),
    ).rejects.toThrow('abort');
    const rows = await new HolderRepository(db, tenantA).list();
    expect(rows.map((h) => h.fullName)).toEqual(['Holder A']);
  });

  it('rejects malformed session institution ids before touching the database', async () => {
    await expect(
      db.withTenant({ ...tenantA, institutionId: "x'; DROP TABLE users;--" }, async () => 1),
    ).rejects.toThrow(TypeError);
  });

  describe('HolderRepository', () => {
    it('returns own holders and 404s on another tenant id or malformed id', async () => {
      const repo = new HolderRepository(db, tenantA);
      expect((await repo.getById(HA)).fullName).toBe('Holder A');
      expect((await repo.list()).map((h) => h.id)).toEqual([HA]);
      await expect(repo.getById(HB)).rejects.toBeInstanceOf(NotFoundError);
      await expect(repo.getById('not-a-uuid')).rejects.toBeInstanceOf(NotFoundError);
      const b = new HolderRepository(db, tenantB);
      await expect(b.getById(HA)).rejects.toMatchObject({ statusCode: 404, code: 'NOT_FOUND' });
    });

    it('the session institution wins over anything request-supplied', async () => {
      const app: FastifyInstance = await buildApp({ config: { logLevel: 'silent' }, db });
      // The route authenticates (here: fixed session for tenant A) and ignores client-supplied tenancy.
      app.get('/api/v1/_test/holders/:id', async (req) => {
        const session = tenantA;
        const { id } = req.params as { id: string };
        return new HolderRepository(app.db!, session).getById(id);
      });
      try {
        const ok = await app.inject({ method: 'GET', url: `/api/v1/_test/holders/${HA}` });
        expect(ok.statusCode).toBe(200);
        // Attempts to select tenant B via header, query or body are ignored; B's holder stays 404.
        const res = await app.inject({
          method: 'GET',
          url: `/api/v1/_test/holders/${HB}?institution_id=${B}&institutionId=${B}`,
          headers: { 'x-institution-id': B },
        });
        expect(res.statusCode).toBe(404);
        expect(res.json()).toEqual({ error: { code: 'NOT_FOUND', message: 'Not found' } });
      } finally {
        await app.close();
      }
    });

    it('a platform session is read-only: reads holders, cannot insert holders or credentials', async () => {
      const seen = await db.withTenant(platform, (c) =>
        c.query(`SELECT id FROM credential_holders`),
      );
      expect(seen.rows.map((r) => r.id).sort()).toEqual([HA, HB]);
      await expect(
        db.withTenant(platform, (c) =>
          c.query(
            `INSERT INTO credential_holders (id, institution_id, full_name, updated_at)
             VALUES (gen_random_uuid(), $1, 'x', now())`,
            [A],
          ),
        ),
      ).rejects.toMatchObject({ code: '42501' });
      await expect(
        db.withTenant(platform, (c) =>
          c.query(
            `INSERT INTO credentials (id, institution_id, holder_id, type_id, credential_number, status,
               payload, data_hash, issuer_kid, signature, verification_token, holder_token_hash, updated_at)
             VALUES (gen_random_uuid(), $1, $2, gen_random_uuid(), 'N-1', 'DRAFT', '{}', 'h', 'k', 's',
               'vt', 'ht', now())`,
            [A, HA],
          ),
        ),
      ).rejects.toMatchObject({ code: '42501' });
    });

    it('a platform session never carries a tenant scope, even if one is smuggled in', async () => {
      const smuggled = { ...platform, institutionId: A } as unknown as PlatformSession;
      const inst = await db.withTenant(smuggled, async (c) => {
        const r = await c.query(`SELECT current_setting('app.institution_id', true) AS i`);
        return r.rows[0].i as string | null;
      });
      expect(inst ?? '').toBe('');
    });
  });
});
