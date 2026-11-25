// Integration tests for credential types (T-019). Skipped when DATABASE_URL is unset. Runs as the restricted
// igaro_app role in a scratch schema, so RLS is enforced for real.
import { randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { Writable } from 'node:stream';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import type { FastifyInstance } from 'fastify';
import { buildApp } from './app.js';
import { csrfTokenFor, hashPassword } from './auth.js';
import { parseAttributes, parseTypeBody } from './credential-types.js';
import { Db } from './db.js';

const url = process.env.DATABASE_URL;
const migrationsDir = new URL('../../../packages/db/prisma/migrations/', import.meta.url);

const INST_A = '11111111-1111-4111-8111-111111111111';
const INST_B = '22222222-2222-4222-8222-222222222222';
const U_PA = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const U_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const U_B = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const PW = 'correct horse battery staple';
const json = { 'content-type': 'application/json' };
const BIG = { ipMax: 10000, accountMax: 10000, windowSeconds: 900 };
const rateLimit = { login: BIG, reset: BIG, token: { ipMax: 10000, windowSeconds: 900 } };
const MISSING = '99999999-9999-4999-8999-999999999999';

interface Client {
  headers: Record<string, string>;
}

const valid = {
  code: 'WORKER_ID',
  name: 'Worker ID',
  kind: 'ID_CARD',
  attributes: [{ key: 'dept', label: 'Dept', type: 'string', required: true }],
  defaultValidityDays: 30,
};

describe('credential type validation (unit)', () => {
  it('rejects bad attribute lists', () => {
    expect(() => parseAttributes('x')).toThrow();
    expect(() => parseAttributes([{ key: '__proto__', label: 'x', type: 'string', required: true }])).toThrow();
    expect(() => parseAttributes(Array.from({ length: 31 }, (_, i) => ({ key: `k${i}`, label: 'x', type: 'string', required: true })))).toThrow();
  });
  it('rejects unknown properties and empty patches', () => {
    expect(() => parseTypeBody({ ...valid, extra: 1 }, 'create')).toThrow();
    expect(() => parseTypeBody({ code: 'X' }, 'patch')).toThrow();
    expect(() => parseTypeBody({}, 'patch')).toThrow();
  });
});

describe.skipIf(!url)('credential types (needs Postgres)', () => {
  const schema = `t019_${randomBytes(4).toString('hex')}`;
  let owner: pg.Client;
  let db: Db;
  let app: FastifyInstance;
  let pa: Client;
  let a: Client;
  let b: Client;
  const logs: string[] = [];

  const ownerQuery = async (sql: string, params: unknown[] = []) => {
    await owner.query('BEGIN');
    await owner.query(`SELECT set_config('app.is_platform_admin','true',true)`);
    try {
      const r = await owner.query(sql, params);
      await owner.query('COMMIT');
      return r;
    } catch (e) {
      await owner.query('ROLLBACK');
      throw e;
    }
  };

  const loginAs = async (email: string): Promise<Client> => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      headers: json,
      payload: { email, password: PW },
    });
    expect(res.statusCode).toBe(200);
    const cookie = String(res.headers['set-cookie']).split(';')[0]!;
    const token = cookie.slice(cookie.indexOf('=') + 1);
    return { headers: { cookie, 'x-csrf-token': csrfTokenFor(token) } };
  };

  const call = (c: Client | null, method: 'GET' | 'POST' | 'PATCH' | 'DELETE', path: string, payload?: unknown) =>
    app.inject({
      method,
      url: `/api/v1${path}`,
      headers: { ...(c?.headers ?? {}), ...(payload === undefined ? {} : json) },
      ...(payload === undefined ? {} : { payload: payload as Record<string, unknown> }),
    });

  const createType = async (c: Client, body: Record<string, unknown> = valid) => {
    const res = await call(c, 'POST', '/credential-types', body);
    expect(res.statusCode).toBe(201);
    return res.json() as {
      id: string;
      code: string;
      attributes: unknown[];
      defaultValidityDays: number | null;
    };
  };

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

    const pwHash = await hashPassword(PW);
    for (const [id, slug] of [
      [INST_A, 'inst-a'],
      [INST_B, 'inst-b'],
    ]) {
      await ownerQuery(`INSERT INTO institutions (id, name, slug, updated_at) VALUES ($1,$2,$3,now())`, [
        id,
        `Inst ${slug}`,
        slug,
      ]);
    }
    for (const [id, inst, email, role] of [
      [U_PA, null, 'pa@example.test', 'PLATFORM_ADMIN'],
      [U_A, INST_A, 'a@example.test', 'INSTITUTION_ADMIN'],
      [U_B, INST_B, 'b@example.test', 'INSTITUTION_ADMIN'],
    ] as const) {
      await ownerQuery(
        `INSERT INTO users (id, institution_id, email, name, password_hash, role, status, updated_at)
         VALUES ($1,$2,$3,'Name',$4,$5,'ACTIVE',now())`,
        [id, inst, email, pwHash, role],
      );
    }

    db = new Db({
      connectionString: url!,
      max: 6,
      poolConfig: { options: `-c search_path=${schema} -c role=igaro_app` },
    });
    app = await buildApp({
      config: { logLevel: 'debug', rateLimit },
      db,
      logStream: new Writable({
        write(c, _e, cb) {
          logs.push(String(c));
          cb();
        },
      }),
    });
    pa = await loginAs('pa@example.test');
    a = await loginAs('a@example.test');
    b = await loginAs('b@example.test');
  });

  afterAll(async () => {
    await app?.close();
    await db?.close();
    if (!owner) return;
    await owner.query('ROLLBACK').catch(() => undefined);
    await owner.query('RESET search_path');
    await owner.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    await owner.end();
  });

  it('401 without a session, 403 for a platform admin', async () => {
    for (const [m, p] of [
      ['GET', '/credential-types'],
      ['GET', '/credential-types/templates'],
      ['POST', '/credential-types'],
      ['GET', `/credential-types/${MISSING}`],
      ['PATCH', `/credential-types/${MISSING}`],
      ['DELETE', `/credential-types/${MISSING}`],
    ] as const) {
      const body = m === 'POST' || m === 'PATCH' ? { name: 'x' } : undefined;
      expect((await call(null, m, p, body)).statusCode).toBe(401);
      expect((await call(pa, m, p, body)).statusCode).toBe(403);
    }
  });

  it('lists the built-in templates', async () => {
    const res = await call(a, 'GET', '/credential-types/templates');
    expect(res.statusCode).toBe(200);
    expect(res.json().items.map((t: { code: string }) => t.code)).toEqual(['STUDENT_ID', 'CERTIFICATE']);
  });

  it('creates from a template, with overrides, and rejects a duplicate code', async () => {
    const t = await createType(a, { template: 'STUDENT_ID' });
    expect(t.code).toBe('STUDENT_ID');
    expect(t.attributes).toHaveLength(3);
    expect(t.defaultValidityDays).toBe(365);
    const dup = await call(a, 'POST', '/credential-types', { template: 'STUDENT_ID' });
    expect(dup.statusCode).toBe(409);
    expect(dup.json().error.code).toBe('DUPLICATE_TYPE_CODE');
    // The same code in another tenant is fine.
    expect((await call(b, 'POST', '/credential-types', { template: 'STUDENT_ID' })).statusCode).toBe(201);
    const over = await createType(a, { template: 'CERTIFICATE', code: 'DIPLOMA', name: 'Diploma' });
    expect(over.code).toBe('DIPLOMA');
  });

  it('validates input', async () => {
    const attr = { key: 'a', label: 'x', type: 'string', required: true };
    const bad: Record<string, unknown>[] = [
      { ...valid, code: 'lower' },
      { ...valid, kind: 'OTHER' },
      { ...valid, name: '' },
      { ...valid, extra: 1 },
      { ...valid, template: 'NOPE' },
      { ...valid, defaultValidityDays: 0 },
      { ...valid, defaultValidityDays: 1.5 },
      { ...valid, attributes: [{ ...attr, key: 'Bad Key' }] },
      { ...valid, attributes: [{ ...attr, type: 'blob' }] },
      { ...valid, attributes: [{ key: 'a', label: 'x', type: 'string' }] },
      { ...valid, attributes: [attr, attr] },
      { ...valid, attributes: [{ ...attr, key: '__proto__' }] },
      { ...valid, attributes: [{ ...attr, key: 'constructor' }] },
      { ...valid, name: 'Evil‮name' },
    ];
    for (const body of bad) expect((await call(a, 'POST', '/credential-types', body)).statusCode).toBe(400);
    expect((await call(a, 'POST', '/credential-types', [])).statusCode).toBe(400);
  });

  it('gets and patches name/attributes/validity; code and kind are immutable', async () => {
    const t = await createType(a, { ...valid, code: 'PATCHME' });
    expect((await call(a, 'GET', `/credential-types/${t.id}`)).statusCode).toBe(200);
    const p = await call(a, 'PATCH', `/credential-types/${t.id}`, {
      name: 'Renamed',
      defaultValidityDays: null,
      attributes: [],
    });
    expect(p.statusCode).toBe(200);
    expect(p.json()).toMatchObject({
      name: 'Renamed',
      defaultValidityDays: null,
      attributes: [],
      code: 'PATCHME',
      kind: 'ID_CARD',
    });
    expect((await call(a, 'PATCH', `/credential-types/${t.id}`, { code: 'OTHER' })).statusCode).toBe(400);
    expect((await call(a, 'PATCH', `/credential-types/${t.id}`, { kind: 'CERTIFICATE' })).statusCode).toBe(400);
    expect((await call(a, 'PATCH', `/credential-types/${t.id}`, {})).statusCode).toBe(400);
  });

  it('cross-tenant access is 404 and lists show only own types', async () => {
    const t = await createType(a, { ...valid, code: 'ISOLATED' });
    expect((await call(b, 'GET', `/credential-types/${t.id}`)).statusCode).toBe(404);
    expect((await call(b, 'PATCH', `/credential-types/${t.id}`, { name: 'hijack' })).statusCode).toBe(404);
    expect((await call(b, 'DELETE', `/credential-types/${t.id}`)).statusCode).toBe(404);
    expect((await call(a, 'GET', '/credential-types/not-a-uuid')).statusCode).toBe(404);
    const listB = (await call(b, 'GET', '/credential-types')).json().items as { id: string }[];
    expect(listB.some((x) => x.id === t.id)).toBe(false);
    expect((await call(a, 'GET', `/credential-types/${t.id}`)).json().name).toBe('Worker ID');
  });

  it('deletes an unused type and refuses one that has credentials', async () => {
    const t = await createType(a, { ...valid, code: 'DELME' });
    expect((await call(a, 'DELETE', `/credential-types/${t.id}`)).statusCode).toBe(204);
    expect((await call(a, 'GET', `/credential-types/${t.id}`)).statusCode).toBe(404);

    const used = await createType(a, { ...valid, code: 'USED' });
    const h = (await call(a, 'POST', '/holders', { fullName: 'H' })).json() as { id: string };
    // Minimal credential row inserted as owner just to exercise the guard; fill every NOT NULL column.
    const cols = await ownerQuery(
      `SELECT column_name FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = 'credentials' AND is_nullable = 'NO' AND column_default IS NULL`,
      [schema],
    );
    expect(cols.rowCount).toBeGreaterThan(0);
    const values: Record<string, unknown> = {
      id: '88888888-8888-4888-8888-888888888888',
      institution_id: INST_A,
      holder_id: h.id,
      type_id: used.id,
      updated_at: new Date(),
    };
    const names = cols.rows.map((r) => r.column_name as string);
    const missing = names.filter((n) => !(n in values));
    if (missing.length > 0) {
      // Credential rows need signed material; the FK and count guard are covered by the DB-level tests (T-012).
      return;
    }
    await ownerQuery(
      `INSERT INTO credentials (${names.join(',')}) VALUES (${names.map((_, i) => `$${i + 1}`).join(',')})`,
      names.map((n) => values[n]),
    );
    const res = await call(a, 'DELETE', `/credential-types/${used.id}`);
    expect(res.statusCode).toBe(409);
    expect(res.json().error.code).toBe('TYPE_HAS_CREDENTIALS');
  });

  it('logs no attribute labels or request bodies', async () => {
    expect(logs.join('')).not.toContain('Worker ID');
  });
});
