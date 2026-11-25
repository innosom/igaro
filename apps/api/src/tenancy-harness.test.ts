// T-012: API-level cross-tenant check built on the shared harness (@igaro/db/testing).
// White paper section 15: "cross-tenant reads/writes return 404". No holder route exists yet
// (T-0xx), so a stand-in route with the production wiring (tenant session -> repository ->
// NotFoundError -> 404 envelope) is used; later tasks replace it with the real endpoints and should
// reuse this harness. Skipped when DATABASE_URL is unset. Test values only.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createHarness, hasDatabase, databaseUrl, type Harness } from '@igaro/db/testing';
import { buildApp } from './app.js';
import { Db, type TenantSession } from './db.js';
import { HolderRepository } from './repositories.js';

describe.skipIf(!hasDatabase)('API cross-tenant 404 via the shared harness (needs Postgres at DATABASE_URL)', () => {
  let h: Harness;
  let db: Db;
  let sessionA: TenantSession;
  let sessionB: TenantSession;

  beforeAll(async () => {
    h = await createHarness('t012api');
    sessionA = { kind: 'tenant', userId: h.A.userId, institutionId: h.A.institutionId };
    sessionB = { kind: 'tenant', userId: h.B.userId, institutionId: h.B.institutionId };
    db = new Db({ connectionString: databaseUrl!, max: 4, poolConfig: { options: h.appConnectionOptions } });
  });

  afterAll(async () => {
    await db?.close();
    await h?.close();
  });

  it("each tenant's session reads its own holder and gets 404 for the other tenant's, both directions", async () => {
    const app = await buildApp({ config: { logLevel: 'silent' }, db });
    // Stand-in for GET /api/v1/holders/:id; the session comes from a test header naming the tenant.
    app.get('/api/v1/_test/holders/:id', async (req) => {
      const who = req.headers['x-test-tenant'] === 'B' ? sessionB : sessionA;
      return new HolderRepository(app.db!, who).getById((req.params as { id: string }).id);
    });
    try {
      const get = (tenant: 'A' | 'B', id: string) =>
        app.inject({ method: 'GET', url: `/api/v1/_test/holders/${id}`, headers: { 'x-test-tenant': tenant } });
      expect((await get('A', h.A.holderId)).statusCode).toBe(200);
      expect((await get('B', h.B.holderId)).statusCode).toBe(200);
      for (const [tenant, id] of [
        ['A', h.B.holderId],
        ['B', h.A.holderId],
      ] as const) {
        const res = await get(tenant, id);
        expect(res.statusCode, `${tenant} -> other`).toBe(404);
        expect(res.json()).toEqual({ error: { code: 'NOT_FOUND', message: 'Not found' } });
      }
      // The 404 is indistinguishable from a holder that does not exist at all.
      const missing = await get('A', h.uid());
      expect(missing.statusCode).toBe(404);
      expect(missing.json()).toEqual({ error: { code: 'NOT_FOUND', message: 'Not found' } });
    } finally {
      await app.close();
    }
  });

  it('repository list never includes the other tenant, and the data is unchanged afterwards', async () => {
    const before = await h.snapshot('credential_holders');
    expect((await new HolderRepository(db, sessionA).list()).map((x) => x.id)).toEqual([h.A.holderId]);
    expect((await new HolderRepository(db, sessionB).list()).map((x) => x.id)).toEqual([h.B.holderId]);
    expect(await h.snapshot('credential_holders')).toEqual(before);
  });
});
