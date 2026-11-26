// T-012: cross-tenant isolation on EVERY tenant table, driven by the shared harness
// (src/testing/harness.ts). White paper section 15 criterion: "Institution B's session cannot read or
// write Institution A's data" (W1 acceptance: RLS returns zero rows; audit tables are append-only).
// Skipped when DATABASE_URL is unset. Test values only.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  MUTABLE_ASSIGNMENT,
  TENANT_TABLES,
  createHarness,
  hasDatabase,
  insertForTenant,
  tenantColumn,
  type Harness,
  type TenantFixture,
  type TenantTable,
} from './testing/harness.js';

describe.skipIf(!hasDatabase)('cross-tenant isolation on every table (needs Postgres at DATABASE_URL)', () => {
  let h: Harness;
  let before: Record<string, string[]>;

  const allSnapshots = async (): Promise<Record<string, string[]>> =>
    {
      const out: Record<string, string[]> = {};
      for (const t of TENANT_TABLES) out[t] = await h.snapshot(t); // sequential: one shared connection
      return out;
    };

  beforeAll(async () => {
    h = await createHarness('t012');
    before = await allSnapshots();
  });

  afterAll(async () => {
    await h?.close();
  });

  // [viewer, other] in both directions: A attacking B and B attacking A.
  const directions = (): Array<[string, TenantFixture, TenantFixture]> => [
    ['A -> B', h.A, h.B],
    ['B -> A', h.B, h.A],
  ];

  it('the seed has exactly one row per tenant table per tenant', async () => {
    for (const t of TENANT_TABLES) {
      const rows = await h.snapshot(t);
      expect(rows.length, t).toBe(2);
    }
  });

  describe('SELECT', () => {
    for (const table of TENANT_TABLES) {
      it(`${table}: a tenant sees only its own row; the other tenant's rows are zero`, async () => {
        for (const [label, me, other] of directions()) {
          await h.asTenant(me.institutionId, async (c) => {
            const all = await c.query(`SELECT id FROM "${table}"`);
            expect(all.rows.map((r) => r.id), `${label} unfiltered`).toEqual([me.rowIds[table]]);
            const byId = await c.query(`SELECT 1 FROM "${table}" WHERE id = $1`, [other.rowIds[table]]);
            expect(byId.rowCount, `${label} by id`).toBe(0);
            const byTenant = await c.query(`SELECT 1 FROM "${table}" WHERE ${tenantColumn(table)} = $1`, [
              other.institutionId,
            ]);
            expect(byTenant.rowCount, `${label} by tenant column`).toBe(0);
            const count = await c.query(`SELECT count(*)::int AS n FROM "${table}"`);
            expect(count.rows[0].n, `${label} count`).toBe(1);
          });
        }
      });

      it(`${table}: a connection with no scope sees zero rows`, async () => {
        await h.asAnonymous(async (c) => {
          expect((await c.query(`SELECT 1 FROM "${table}"`)).rowCount).toBe(0);
        });
      });
    }

    it('a scope for an institution that does not exist sees nothing anywhere', async () => {
      await h.asTenant(h.uid(), async (c) => {
        for (const t of TENANT_TABLES) {
          expect((await c.query(`SELECT 1 FROM "${t}"`)).rowCount, t).toBe(0);
        }
      });
    });
  });

  describe('INSERT', () => {
    for (const table of TENANT_TABLES) {
      it(`${table}: inserting a row owned by the other tenant is refused (42501)`, async () => {
        for (const [label, me, other] of directions()) {
          await h.asTenant(me.institutionId, async (c) => {
            const { sql, params } = insertForTenant(table, other, h.uid());
            // sessions/password_resets also validate the user against the session's institution in a
            // BEFORE trigger, which cannot see the other tenant's user under RLS and raises 23503 first.
            // Either way the row is refused; the final snapshot test proves nothing was written.
            const accepted = table === 'sessions' || table === 'password_resets' ? ['42501', '23503'] : ['42501'];
            expect(accepted, `${label}`).toContain(await h.code(() => c.query(sql, params)));
          });
        }
      });
    }

    it('control: the same statements succeed for the own tenant where the app role may insert', async () => {
      // institutions (platform only) and institution_keys (platform only) are refused for tenants by design.
      // audit_head_hashes is written only by the worker role (T-028, ADR 0019), never by igaro_app.
      const tenantInsertable = TENANT_TABLES.filter(
        (t) =>
          t !== 'institutions' && t !== 'institution_keys' && t !== 'audit_head_hashes' && t !== 'audit_head_timestamps',
      );
      for (const table of tenantInsertable) {
        await h.asTenant(h.A.institutionId, async (c) => {
          const { sql, params } = insertForTenant(table, h.A, h.uid());
          expect(await h.code(() => c.query(sql, params)), table).toBeUndefined();
        });
      }
      for (const table of ['institutions', 'institution_keys', 'audit_head_hashes', 'audit_head_timestamps'] as const) {
        await h.asTenant(h.A.institutionId, async (c) => {
          const { sql, params } = insertForTenant(table, h.A, h.uid());
          expect(await h.code(() => c.query(sql, params)), table).toBe('42501');
        });
      }
    });

    it('a row cannot be created for the other tenant even when a tenant id is also smuggled via platform setting', async () => {
      // is_platform_admin='true' alone must not let a tenant session write other tenants' tenant data.
      await h.asApp({ 'app.institution_id': h.A.institutionId, 'app.is_platform_admin': 'true' }, async (c) => {
        const { sql, params } = insertForTenant('credential_holders', h.B, h.uid());
        expect(await h.code(() => c.query(sql, params))).toBe('42501');
      });
    });
  });

  describe('UPDATE', () => {
    for (const table of TENANT_TABLES) {
      it(`${table}: updating the other tenant's row is refused or changes zero rows`, async () => {
        for (const [label, me, other] of directions()) {
          await h.asTenant(me.institutionId, async (c) => {
            const set = MUTABLE_ASSIGNMENT[table] ?? `id = id`;
            let affected: number | null = null;
            const code = await h.code(async () => {
              affected = (await c.query(`UPDATE "${table}" SET ${set} WHERE id = $1`, [other.rowIds[table]])).rowCount;
            });
            if (code === undefined) expect(affected, `${label} rowCount`).toBe(0);
            else expect(code, `${label}`).toBe('42501');
            // An unfiltered UPDATE must not reach the other tenant either.
            let all: number | null = null;
            const code2 = await h.code(async () => {
              all = (await c.query(`UPDATE "${table}" SET ${set} WHERE ${tenantColumn(table)} = $1`, [other.institutionId]))
                .rowCount;
            });
            if (code2 === undefined) expect(all, `${label} by tenant column`).toBe(0);
            else expect(code2, `${label} by tenant column`).toBe('42501');
          });
        }
      });
    }

    it('tables with no UPDATE grant for the app role are refused even on the own row', async () => {
      for (const table of ['verification_logs', 'audit_logs', 'audit_head_hashes'] as const) {
        await h.asTenant(h.A.institutionId, async (c) => {
          expect(
            await h.code(() => c.query(`UPDATE "${table}" SET id = id WHERE id = $1`, [h.A.rowIds[table]])),
            table,
          ).toBe('42501');
        });
      }
    });
  });

  describe('DELETE', () => {
    for (const table of TENANT_TABLES) {
      it(`${table}: deleting the other tenant's row is refused or deletes zero rows`, async () => {
        for (const [label, me, other] of directions()) {
          await h.asTenant(me.institutionId, async (c) => {
            for (const [sql, params] of [
              [`DELETE FROM "${table}" WHERE id = $1`, [other.rowIds[table]]],
              [`DELETE FROM "${table}" WHERE ${tenantColumn(table)} = $1`, [other.institutionId]],
            ] as Array<[string, unknown[]]>) {
              let affected: number | null = null;
              const code = await h.code(async () => {
                affected = (await c.query(sql, params)).rowCount;
              });
              if (code === undefined) expect(affected, `${label}: ${sql}`).toBe(0);
              else expect(code, `${label}: ${sql}`).toBe('42501');
            }
          });
        }
      });
    }
  });

  describe('append-only tables (W1: UPDATE/DELETE on audit_logs refused for the app role)', () => {
    for (const table of ['audit_logs', 'audit_head_hashes'] as const) {
      it(`${table}: UPDATE and DELETE of the tenant's OWN rows are refused for igaro_app`, async () => {
        await h.asTenant(h.A.institutionId, async (c) => {
          const col = table === 'audit_logs' ? 'entry_hash' : 'head_hash';
          expect(await h.code(() => c.query(`UPDATE "${table}" SET ${col} = 'x' WHERE id = $1`, [h.A.rowIds[table]]))).toBe('42501');
          expect(await h.code(() => c.query(`DELETE FROM "${table}" WHERE id = $1`, [h.A.rowIds[table]]))).toBe('42501');
        });
        await h.asPlatform(async (c) => {
          expect(await h.code(() => c.query(`UPDATE "${table}" SET id = id`))).toBe('42501');
          expect(await h.code(() => c.query(`DELETE FROM "${table}"`))).toBe('42501');
        });
      });
    }
  });

  describe('after everything above', () => {
    it('no table changed: every refused or zero-row statement left the data untouched', async () => {
      const after = await allSnapshots();
      for (const t of TENANT_TABLES as readonly TenantTable[]) {
        expect(after[t], t).toEqual(before[t]);
      }
    });
  });
});
