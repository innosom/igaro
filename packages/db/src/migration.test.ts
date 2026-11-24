// Integration tests for the init migration (T-005). Skipped when DATABASE_URL is unset.
// Everything runs in a scratch schema that is dropped afterwards; the global role `igaro_app`
// is created idempotently by the migration and left in place.
import { readdirSync, readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';

const url = process.env.DATABASE_URL;
const migrationsDir = new URL('../prisma/migrations/', import.meta.url);

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';

const TENANT_TABLES = [
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
  'import_batches',
  'import_rows',
];

let n = 0;
const uid = (): string => {
  n += 1;
  return `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
};

describe.skipIf(!url)('init migration (needs Postgres at DATABASE_URL)', () => {
  const schema = `t005_${randomBytes(4).toString('hex')}`;
  let c: pg.Client;

  /** Run fn in a transaction with the given settings, optionally as igaro_app. Always rolls back. */
  async function scoped<T>(
    settings: Record<string, string>,
    asApp: boolean,
    fn: () => Promise<T>,
  ): Promise<T> {
    await c.query('BEGIN');
    try {
      for (const [k, v] of Object.entries(settings)) {
        await c.query('SELECT set_config($1, $2, true)', [k, v]);
      }
      if (asApp) await c.query('SET LOCAL ROLE igaro_app');
      return await fn();
    } finally {
      await c.query('ROLLBACK');
    }
  }

  const asTenant = <T>(id: string, fn: () => Promise<T>) =>
    scoped({ 'app.institution_id': id }, true, fn);
  // Scope used for fixtures and constraint tests, run as the connecting (owner) role. Note that
  // superusers bypass RLS even with FORCE; the explicit scope settings keep these statements valid
  // for a non-superuser owner too. Only the `asApp` paths above actually prove RLS.
  const asOwner = <T>(fn: () => Promise<T>) =>
    scoped({ 'app.is_platform_admin': 'true', 'app.institution_id': A }, false, fn);

  async function code(fn: () => Promise<unknown>): Promise<string | undefined> {
    await c.query('SAVEPOINT s');
    try {
      await fn();
      await c.query('RELEASE SAVEPOINT s');
      return undefined;
    } catch (e) {
      await c.query('ROLLBACK TO SAVEPOINT s');
      return (e as { code?: string }).code ?? String(e);
    }
  }

  async function expectCode(sql: string, params: unknown[], expected: string): Promise<void> {
    await c.query('BEGIN');
    try {
      await c.query('SELECT set_config($1, $2, true)', ['app.is_platform_admin', 'true']);
      await c.query('SELECT set_config($1, $2, true)', ['app.institution_id', A]);
      const got = await code(() => c.query(sql, params));
      expect(got, sql).toBe(expected);
    } finally {
      await c.query('ROLLBACK');
    }
  }

  const insInstitution = (id: string, slug: string) =>
    c.query(
      `INSERT INTO institutions (id, name, slug, updated_at) VALUES ($1, $2, $3, now())`,
      [id, slug, slug],
    );
  const insKey = (id: string, inst: string, kid: string, status = 'ACTIVE') =>
    c.query(
      `INSERT INTO institution_keys (id, institution_id, kid, public_key, encrypted_private_key, status)
       VALUES ($1, $2, $3, 'pub', 'enc', $4)`,
      [id, inst, kid, status],
    );
  const insHolder = (id: string, inst: string, name: string) =>
    c.query(
      `INSERT INTO credential_holders (id, institution_id, full_name, updated_at) VALUES ($1, $2, $3, now())`,
      [id, inst, name],
    );
  const insType = (id: string, inst: string, codeStr: string) =>
    c.query(
      `INSERT INTO credential_types (id, institution_id, code, name, kind, updated_at)
       VALUES ($1, $2, $3, $3, 'ID_CARD', now())`,
      [id, inst, codeStr],
    );
  const insCredential = (
    id: string,
    inst: string,
    holder: string,
    type: string,
    kid: string,
    num: string,
    extra: { status?: string; supersededBy?: string | null; vtoken?: string } = {},
  ) =>
    c.query(
      `INSERT INTO credentials (id, institution_id, holder_id, type_id, credential_number, status,
         payload, data_hash, issuer_kid, signature, verification_token, holder_token_hash,
         superseded_by, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,'{}','h',$7,'sig',$8,$9,$10, now())`,
      [
        id,
        inst,
        holder,
        type,
        num,
        extra.status ?? 'ACTIVE',
        kid,
        extra.vtoken ?? `vt-${num}`,
        `ht-${num}`,
        extra.supersededBy ?? null,
      ],
    );

  // Fixture ids
  const ids = {
    keyA: uid(), keyB: uid(), holderA: uid(), holderB: uid(),
    typeA: uid(), typeB: uid(), credA: uid(), credB: uid(),
    userA: uid(), userB: uid(), platformUser: uid(),
  };

  beforeAll(async () => {
    c = new pg.Client({ connectionString: url });
    await c.connect();
    await c.query(`CREATE SCHEMA "${schema}"`);
    await c.query(`SET search_path TO "${schema}"`);
    const dirs = readdirSync(migrationsDir, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => d.name)
      .sort();
    for (const d of dirs) {
      await c.query(readFileSync(new URL(`${d}/migration.sql`, migrationsDir), 'utf8'));
    }
    // Fixtures: two tenants, each with key/holder/type/credential/user.
    await c.query('BEGIN');
    await c.query(`SELECT set_config('app.is_platform_admin','true',true)`);
    for (const [inst, slug, k, h, t, cr, u, kid] of [
      [A, 'a', ids.keyA, ids.holderA, ids.typeA, ids.credA, ids.userA, 'kid-a'],
      [B, 'b', ids.keyB, ids.holderB, ids.typeB, ids.credB, ids.userB, 'kid-b'],
    ] as const) {
      await insInstitution(inst, slug);
      await insKey(k, inst, kid);
      await c.query(`SELECT set_config('app.institution_id', $1, true)`, [inst]);
      await insHolder(h, inst, `Holder ${slug}`);
      await insType(t, inst, 'STUDENT_ID');
      await insCredential(cr, inst, h, t, kid, `NUM-${slug}`);
      await c.query(
        `INSERT INTO users (id, institution_id, email, name, role, updated_at)
         VALUES ($1,$2,$3,'x','INSTITUTION_ADMIN', now())`,
        [u, inst, `admin-${slug}@example.test`],
      );
    }
    await c.query(
      `INSERT INTO users (id, institution_id, email, name, role, updated_at)
       VALUES ($1, NULL, 'root@example.test', 'root', 'PLATFORM_ADMIN', now())`,
      [ids.platformUser],
    );
    await c.query('COMMIT');
  });

  afterAll(async () => {
    if (!c) return;
    await c.query('ROLLBACK').catch(() => undefined);
    await c.query('RESET search_path');
    await c.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    await c.end();
  });

  describe('role and RLS configuration', () => {
    it('igaro_app is not superuser, cannot log in until an operator sets a password, and does not bypass RLS', async () => {
      const r = await c.query(
        `SELECT rolsuper, rolbypassrls, rolcanlogin, rolcreatedb, rolcreaterole
           FROM pg_roles WHERE rolname = 'igaro_app'`,
      );
      expect(r.rows[0]).toMatchObject({
        rolsuper: false,
        rolbypassrls: false,
        rolcanlogin: false,
        rolcreatedb: false,
        rolcreaterole: false,
      });
    });

    it('every foreign key is ON UPDATE RESTRICT/NO ACTION; audit and verification institution FKs are ON DELETE RESTRICT', async () => {
      const r = await c.query(
        `SELECT conname, conrelid::regclass::text AS tbl, confupdtype, confdeltype
           FROM pg_constraint WHERE contype = 'f' AND connamespace = $1::regnamespace`,
        [schema],
      );
      expect(r.rows.length).toBeGreaterThan(20);
      for (const row of r.rows) {
        expect(['r', 'a'], row.conname).toContain(row.confupdtype);
        // SET NULL / SET DEFAULT on delete are never used; CASCADE only for sessions/resets->users and import_rows->batch.
        expect(['n', 'd'], row.conname).not.toContain(row.confdeltype);
      }
      for (const name of [
        'audit_logs_institution_id_fkey',
        'audit_head_hashes_institution_id_fkey',
        'verification_logs_institution_id_fkey',
      ]) {
        expect(r.rows.find((x) => x.conname === name)?.confdeltype, name).toBe('r');
      }
    });

    it('enables and forces RLS on every tenant table', async () => {
      const r = await c.query(
        `SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class
          WHERE relnamespace = $1::regnamespace AND relkind = 'r'`,
        [schema],
      );
      const byName = new Map(r.rows.map((x) => [x.relname as string, x]));
      for (const t of TENANT_TABLES) {
        expect(byName.get(t), t).toMatchObject({ relrowsecurity: true, relforcerowsecurity: true });
      }
      expect(r.rows.length).toBe(TENANT_TABLES.length);
    });
  });

  describe('tenant isolation as igaro_app', () => {
    it('tenant A sees only its own rows', async () => {
      await asTenant(A, async () => {
        for (const t of ['credentials', 'credential_holders', 'credential_types', 'institution_keys', 'users']) {
          const r = await c.query(`SELECT DISTINCT institution_id FROM ${t}`);
          expect(r.rows.map((x) => x.institution_id), t).toEqual([A]);
        }
        const inst = await c.query('SELECT id FROM institutions');
        expect(inst.rows.map((x) => x.id)).toEqual([A]);
      });
    });

    it('no scope or empty scope sees nothing', async () => {
      await scoped({}, true, async () => {
        expect((await c.query('SELECT 1 FROM credentials')).rowCount).toBe(0);
        expect((await c.query('SELECT 1 FROM institutions')).rowCount).toBe(0);
      });
      await scoped({ 'app.institution_id': '', 'app.is_platform_admin': '' }, true, async () => {
        expect((await c.query('SELECT 1 FROM credentials')).rowCount).toBe(0);
      });
    });

    it('cross-tenant read by id returns zero rows and update/delete touch nothing', async () => {
      await asTenant(A, async () => {
        expect((await c.query('SELECT 1 FROM credentials WHERE id = $1', [ids.credB])).rowCount).toBe(0);
        const u = await c.query(`UPDATE credential_holders SET full_name = 'pwn' WHERE id = $1`, [ids.holderB]);
        expect(u.rowCount).toBe(0);
        const d = await c.query('DELETE FROM credential_types WHERE id = $1', [ids.typeB]);
        expect(d.rowCount).toBe(0);
      });
    });

    it('cannot insert a row for another tenant (RLS violation)', async () => {
      await asTenant(A, async () => {
        const got = await code(() => insHolder(uid(), B, 'evil'));
        expect(got).toBe('42501');
      });
    });

    it('cannot move a row to another tenant by updating institution_id', async () => {
      await asTenant(A, async () => {
        const got = await code(() =>
          c.query('UPDATE credential_holders SET institution_id = $1 WHERE id = $2', [B, ids.holderA]),
        );
        expect(got).toBe('42501');
      });
    });

    it('tenant scope cannot see the platform admin user', async () => {
      await asTenant(A, async () => {
        const r = await c.query(`SELECT 1 FROM users WHERE id = $1`, [ids.platformUser]);
        expect(r.rowCount).toBe(0);
      });
    });

    it('platform scope reads all tenants but cannot write credentials', async () => {
      await scoped({ 'app.is_platform_admin': 'true' }, true, async () => {
        expect((await c.query('SELECT 1 FROM institutions')).rowCount).toBe(2);
        expect((await c.query('SELECT 1 FROM credentials')).rowCount).toBe(2);
        expect((await c.query('SELECT 1 FROM users')).rowCount).toBe(3);
        const got = await code(() => insHolder(uid(), A, 'platform wrote a holder'));
        expect(got).toBe('42501');
      });
    });

    it('narrow lookup settings expose exactly one row', async () => {
      await scoped({ 'app.verification_token': 'vt-NUM-b' }, true, async () => {
        const r = await c.query('SELECT id FROM credentials');
        expect(r.rows.map((x) => x.id)).toEqual([ids.credB]);
      });
      await scoped({ 'app.institution_slug': 'a' }, true, async () => {
        const r = await c.query('SELECT id FROM institutions');
        expect(r.rows.map((x) => x.id)).toEqual([A]);
      });
      await scoped({ 'app.login_email': 'admin-b@example.test' }, true, async () => {
        const r = await c.query('SELECT id FROM users');
        expect(r.rows.map((x) => x.id)).toEqual([ids.userB]);
      });
    });

    it('verification_logs: public path may insert unknown-credential rows but not read them', async () => {
      await scoped({}, true, async () => {
        await c.query(`INSERT INTO verification_logs (id, result) VALUES ($1, 'NOT_FOUND')`, [uid()]);
        expect((await c.query('SELECT 1 FROM verification_logs')).rowCount).toBe(0);
        const got = await code(() =>
          c.query(`INSERT INTO verification_logs (id, institution_id, result) VALUES ($1, $2, 'VERIFIED')`, [uid(), A]),
        );
        expect(got).toBe('42501');
      });
    });
  });

  describe('grants for igaro_app', () => {
    it('refuses UPDATE and DELETE on audit_logs (no grant)', async () => {
      await asTenant(A, async () => {
        expect(await code(() => c.query(`UPDATE audit_logs SET action = 'x'`))).toBe('42501');
      });
      await asTenant(A, async () => {
        expect(await code(() => c.query('DELETE FROM audit_logs'))).toBe('42501');
      });
    });

    it('refuses UPDATE/DELETE on audit_head_hashes, credential_events, verification_logs', async () => {
      for (const sql of [
        `UPDATE audit_head_hashes SET head_hash = 'x'`,
        'DELETE FROM audit_head_hashes',
        `UPDATE credential_events SET anchored_at = now()`,
        'DELETE FROM credential_events',
        `UPDATE verification_logs SET result = 'VERIFIED'`,
        'DELETE FROM verification_logs',
      ]) {
        await asTenant(A, async () => {
          expect(await code(() => c.query(sql)), sql).toBe('42501');
        });
      }
    });

    it('refuses DELETE on credentials', async () => {
      await asTenant(A, async () => {
        expect(await code(() => c.query('DELETE FROM credentials'))).toBe('42501');
      });
    });

    it('allows INSERT and SELECT on audit_logs for the own tenant only', async () => {
      await asTenant(A, async () => {
        await c.query(
          `INSERT INTO audit_logs (id, institution_id, seq, action, prev_hash, entry_hash) VALUES ($1,$2,1,'t','p','e')`,
          [uid(), A],
        );
        expect((await c.query('SELECT 1 FROM audit_logs')).rowCount).toBe(1);
        const got = await code(() =>
          c.query(
            `INSERT INTO audit_logs (id, institution_id, seq, action, prev_hash, entry_hash) VALUES ($1,$2,1,'t','p2','e2')`,
            [uid(), B],
          ),
        );
        expect(got).toBe('42501');
      });
    });
  });

  describe('column-level UPDATE grants (H1)', () => {
    it('refuses UPDATE of identity columns on every table', async () => {
      const cases: Array<[string, string, unknown[]]> = [
        ['institutions', `UPDATE institutions SET id = $1`, [uid()]],
        ['institutions', `UPDATE institutions SET slug = 'zzz'`, []],
        ['institution_keys', `UPDATE institution_keys SET kid = 'zzz'`, []],
        ['institution_keys', `UPDATE institution_keys SET institution_id = $1`, [B]],
        ['users', `UPDATE users SET institution_id = $1`, [B]],
        ['users', `UPDATE users SET email = 'x@example.test'`, []],
        ['users', `UPDATE users SET role = 'PLATFORM_ADMIN'`, []],
        ['sessions', `UPDATE sessions SET user_id = $1`, [ids.userA]],
        ['invites', `UPDATE invites SET institution_id = $1`, [B]],
        ['credential_types', `UPDATE credential_types SET code = 'x'`, []],
        ['credential_holders', `UPDATE credential_holders SET institution_id = $1`, [B]],
        ['credentials', `UPDATE credentials SET payload = '{"a":1}'`, []],
        ['credentials', `UPDATE credentials SET signature = 'x'`, []],
        ['credentials', `UPDATE credentials SET data_hash = 'x'`, []],
        ['credentials', `UPDATE credentials SET issuer_kid = 'x'`, []],
        ['credentials', `UPDATE credentials SET verification_token = 'x'`, []],
        ['credentials', `UPDATE credentials SET credential_number = 'x'`, []],
        ['credentials', `UPDATE credentials SET institution_id = $1`, [B]],
        ['import_rows', `UPDATE import_rows SET institution_id = $1`, [B]],
      ];
      for (const [table, sql, params] of cases) {
        await scoped({ 'app.is_platform_admin': 'true', 'app.institution_id': A }, true, async () => {
          expect(await code(() => c.query(sql, params)), `${table}: ${sql}`).toBe('42501');
        });
      }
    });

    it('allows UPDATE of mutable columns', async () => {
      await asTenant(A, async () => {
        const u = await c.query(`UPDATE credential_holders SET full_name = 'Renamed' WHERE id = $1`, [ids.holderA]);
        expect(u.rowCount).toBe(1);
        const s = await c.query(`UPDATE credentials SET status = 'SUSPENDED' WHERE id = $1`, [ids.credA]);
        expect(s.rowCount).toBe(1);
        const i = await c.query(`UPDATE institutions SET card_title = 'Card' WHERE id = $1`, [A]);
        expect(i.rowCount).toBe(1);
      });
    });

    it('the app role has no TRUNCATE', async () => {
      await asTenant(A, async () => {
        expect(await code(() => c.query('TRUNCATE credentials'))).toBe('42501');
      });
    });
  });

  describe('key and institution status are platform-scope only (H2)', () => {
    const asPlatform = <T>(fn: () => Promise<T>) =>
      scoped({ 'app.is_platform_admin': 'true' }, true, fn);

    it('tenant scope cannot change institutions.status', async () => {
      await asTenant(A, async () => {
        expect(
          await code(() => c.query(`UPDATE institutions SET status = 'SUSPENDED' WHERE id = $1`, [A])),
        ).toBe('42501');
      });
      await asPlatform(async () => {
        const r = await c.query(`UPDATE institutions SET status = 'SUSPENDED' WHERE id = $1`, [A]);
        expect(r.rowCount).toBe(1);
      });
    });

    it('tenant scope cannot update or insert institution_keys', async () => {
      await asTenant(A, async () => {
        const r = await c.query(`UPDATE institution_keys SET status = 'RETIRED' WHERE id = $1`, [ids.keyA]);
        expect(r.rowCount).toBe(0);
        expect((await c.query('SELECT 1 FROM institution_keys')).rowCount).toBe(1);
        expect(
          await code(() =>
            c.query(
              `INSERT INTO institution_keys (id, institution_id, kid, public_key, encrypted_private_key, status)
               VALUES ($1,$2,'kid-evil','p','e','RETIRED')`,
              [uid(), A],
            ),
          ),
        ).toBe('42501');
      });
    });

    it('platform scope may insert keys and change status/retired_at only', async () => {
      await asPlatform(async () => {
        const r = await c.query(
          `UPDATE institution_keys SET status = 'RETIRED', retired_at = now() WHERE id = $1`,
          [ids.keyA],
        );
        expect(r.rowCount).toBe(1);
        await c.query(
          `INSERT INTO institution_keys (id, institution_id, kid, public_key, encrypted_private_key)
           VALUES ($1,$2,'kid-a-new','p','e')`,
          [uid(), A],
        );
        for (const col of ['kid', 'public_key', 'encrypted_private_key', 'algorithm', 'institution_id']) {
          const val = col === 'institution_id' ? B : 'x';
          expect(
            await code(() => c.query(`UPDATE institution_keys SET ${col} = $1`, [val])),
            col,
          ).toBe('42501');
        }
        expect(await code(() => c.query('DELETE FROM institution_keys'))).toBe('42501');
      });
    });

    it('COMPROMISED is a final key status', async () => {
      await asPlatform(async () => {
        const id = uid();
        await c.query(
          `INSERT INTO institution_keys (id, institution_id, kid, public_key, encrypted_private_key, status)
           VALUES ($1,$2,'kid-comp','p','e','COMPROMISED')`,
          [id, A],
        );
        for (const s of ['ACTIVE', 'RETIRED']) {
          expect(
            await code(() => c.query(`UPDATE institution_keys SET status = $1 WHERE id = $2`, [s, id])),
            s,
          ).toBe('23514');
        }
      });
    });
  });

  describe('constraints', () => {
    it('users: role/institution coupling and lowercase email', async () => {
      const ins = `INSERT INTO users (id, institution_id, email, name, role, updated_at) VALUES ($1,$2,$3,'n',$4, now())`;
      await expectCode(ins, [uid(), A, 'p@example.test', 'PLATFORM_ADMIN'], '23514');
      await expectCode(ins, [uid(), null, 't@example.test', 'INSTITUTION_ADMIN'], '23514');
      await expectCode(ins, [uid(), A, 'Upper@example.test', 'INSTITUTION_ADMIN'], '23514');
      await expectCode(ins, [uid(), A, 'admin-a@example.test', 'INSTITUTION_ADMIN'], '23505');
    });

    it('invites and holders: lowercase email', async () => {
      await expectCode(
        `INSERT INTO invites (id, institution_id, email, token_hash, expires_at) VALUES ($1,$2,'A@B.test','th',now())`,
        [uid(), A],
        '23514',
      );
      await expectCode(
        `INSERT INTO credential_holders (id, institution_id, full_name, email, updated_at) VALUES ($1,$2,'n','A@B.test', now())`,
        [uid(), A],
        '23514',
      );
    });

    it('institutions: hex colours', async () => {
      for (const col of ['primary_color', 'secondary_color']) {
        for (const bad of ['red', '#12345', '#12345g', '123456']) {
          await expectCode(
            `INSERT INTO institutions (id, name, slug, ${col}, updated_at) VALUES ($1,'n',$2,$3, now())`,
            [uid(), `s-${uid()}`, bad],
            '23514',
          );
        }
      }
    });

    it('institution_keys: only one ACTIVE key per institution', async () => {
      await expectCode(
        `INSERT INTO institution_keys (id, institution_id, kid, public_key, encrypted_private_key, status)
         VALUES ($1,$2,'kid-a2','p','e','ACTIVE')`,
        [uid(), A],
        '23505',
      );
      await asOwner(async () => {
        await insKey(uid(), A, 'kid-a-retired', 'RETIRED');
        await insKey(uid(), A, 'kid-a-retired2', 'RETIRED');
      });
    });

    it('credentials: superseded_by iff SUPERSEDED, composite tenant FKs, unique tokens', async () => {
      const insert = (status: string, sup: string | null, holder = ids.holderA, vt?: string) =>
        insCredential(uid(), A, holder, ids.typeA, 'kid-a', `N-${uid()}`, {
          status,
          supersededBy: sup,
          ...(vt ? { vtoken: vt } : {}),
        });
      const run = async (fn: () => Promise<unknown>) => {
        await c.query('BEGIN');
        try {
          await c.query(`SELECT set_config('app.is_platform_admin','true',true)`);
          await c.query(`SELECT set_config('app.institution_id',$1,true)`, [A]);
          return await code(fn);
        } finally {
          await c.query('ROLLBACK');
        }
      };
      expect(await run(() => insert('ACTIVE', ids.credA))).toBe('23514');
      expect(await run(() => insert('SUPERSEDED', null))).toBe('23514');
      expect(await run(() => insert('SUPERSEDED', ids.credA))).toBeUndefined();
      // holder belonging to tenant B cannot be referenced by a tenant A credential
      expect(await run(() => insert('ACTIVE', null, ids.holderB))).toBe('23503');
      expect(await run(() => insert('ACTIVE', null, ids.holderA, 'vt-NUM-a'))).toBe('23505');
      // issuer key of tenant B cannot sign for tenant A
      expect(
        await run(() =>
          insCredential(uid(), A, ids.holderA, ids.typeA, 'kid-b', `N-${uid()}`),
        ),
      ).toBe('23503');
    });

    it('audit_logs / audit_head_hashes: NULLS NOT DISTINCT chain uniqueness', async () => {
      const ins = `INSERT INTO audit_logs (id, institution_id, seq, action, prev_hash, entry_hash) VALUES ($1,NULL,$2,'t',$3,$4)`;
      await c.query('BEGIN');
      try {
        await c.query(`SELECT set_config('app.is_platform_admin','true',true)`);
        await c.query(ins, [uid(), 1, 'genesis', 'e1']);
        expect(await code(() => c.query(ins, [uid(), 1, 'x', 'e2']))).toBe('23505'); // same seq
        expect(await code(() => c.query(ins, [uid(), 2, 'genesis', 'e3']))).toBe('23505'); // fork
        expect(await code(() => c.query(ins, [uid(), 2, 'e1', 'e4']))).toBeUndefined();
        const head = `INSERT INTO audit_head_hashes (id, institution_id, day, head_hash, signature, signer_kid) VALUES ($1,NULL,'2026-11-24','h','s','k')`;
        await c.query(head, [uid()]);
        expect(await code(() => c.query(head, [uid()]))).toBe('23505');
      } finally {
        await c.query('ROLLBACK');
      }
    });

    it('audit_head_hashes: signer_kid is required', async () => {
      await expectCode(
        `INSERT INTO audit_head_hashes (id, institution_id, day, head_hash, signature) VALUES ($1,$2,'2026-11-24','h','s')`,
        [uid(), A],
        '23502',
      );
    });

    it('sessions / password_resets: institution_id must match the user', async () => {
      const ins = (table: string, inst: string | null, user: string) =>
        c.query(
          `INSERT INTO ${table} (id, institution_id, user_id, token_hash, expires_at) VALUES ($1,$2,$3,$4, now())`,
          [uid(), inst, user, `th-${uid()}`],
        );
      for (const table of ['sessions', 'password_resets']) {
        await c.query('BEGIN');
        try {
          await c.query(`SELECT set_config('app.is_platform_admin','true',true)`);
          expect(await code(() => ins(table, null, ids.userA)), table).toBe('23514');
          expect(await code(() => ins(table, B, ids.userA)), table).toBe('23514');
          expect(await code(() => ins(table, A, ids.platformUser)), table).toBe('23514');
          expect(await code(() => ins(table, A, uid())), table).toBe('23503');
          expect(await code(() => ins(table, A, ids.userA)), table).toBeUndefined();
          expect(await code(() => ins(table, null, ids.platformUser)), table).toBeUndefined();
        } finally {
          await c.query('ROLLBACK');
        }
      }
    });
  });
});
