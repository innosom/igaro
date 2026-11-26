// Integration tests for signing key rotation and mark-compromised (T-017). Skipped without DATABASE_URL.
// Runs as the restricted igaro_app role in a scratch schema, so RLS is enforced for real.
import { randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { Writable } from 'node:stream';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import type { FastifyInstance } from 'fastify';
import { generateSigningKey } from '@igaro/core';
import { buildApp } from './app.js';
import { csrfTokenFor, hashPassword } from './auth.js';
import { Db } from './db.js';

const url = process.env.DATABASE_URL;
const migrationsDir = new URL('../../../packages/db/prisma/migrations/', import.meta.url);
const MASTER = randomBytes(32);
const INST_A = '11111111-1111-4111-8111-111111111111';
const INST_B = '22222222-2222-4222-8222-222222222222';
const PW = 'correct horse battery staple';
const json = { 'content-type': 'application/json' };
const BIG = { ipMax: 10000, accountMax: 10000, windowSeconds: 900 };
const rateLimit = { login: BIG, reset: BIG, token: { ipMax: 10000, windowSeconds: 900 } };

interface Client {
  headers: Record<string, string>;
}

describe.skipIf(!url)('signing keys: rotate and compromise (needs Postgres)', () => {
  const schema = `t017_${randomBytes(4).toString('hex')}`;
  let owner: pg.Client;
  let db: Db;
  let app: FastifyInstance;
  let pa: Client;
  let a: Client;
  let b: Client;
  const logs: string[] = [];
  const kids: Record<string, string | undefined> = {};

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
    return { headers: { cookie, 'x-csrf-token': csrfTokenFor(cookie.slice(cookie.indexOf('=') + 1)) } };
  };

  const call = (c: Client | null, method: 'GET' | 'POST', path: string, payload?: unknown) =>
    app.inject({
      method,
      url: `/api/v1/institution/keys${path}`,
      headers: { ...(c?.headers ?? {}), ...json },
      ...(payload === undefined ? {} : { payload: payload as Record<string, unknown> }),
    });

  const keysOf = async (inst: string) =>
    (
      await ownerQuery(
        `SELECT kid, status, retired_at FROM institution_keys WHERE institution_id = $1 ORDER BY created_at, kid`,
        [inst],
      )
    ).rows as { kid: string; status: string; retired_at: Date | null }[];

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
    ] as const) {
      await ownerQuery(`INSERT INTO institutions (id, name, slug, updated_at) VALUES ($1,$2,$3,now())`, [
        id,
        `Inst ${slug}`,
        slug,
      ]);
      const k = generateSigningKey(MASTER);
      kids[id] = k.kid;
      await ownerQuery(
        `INSERT INTO institution_keys (id, institution_id, kid, algorithm, public_key, encrypted_private_key, status)
         VALUES (gen_random_uuid(), $1, $2, 'Ed25519', $3, $4, 'ACTIVE')`,
        [id, k.kid, k.publicKey, k.encryptedPrivateKey],
      );
    }
    for (const [id, inst, email, role] of [
      ['bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', null, 'pa@example.test', 'PLATFORM_ADMIN'],
      ['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', INST_A, 'a@example.test', 'INSTITUTION_ADMIN'],
      ['cccccccc-cccc-4ccc-8ccc-cccccccccccc', INST_B, 'b@example.test', 'INSTITUTION_ADMIN'],
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
      config: { logLevel: 'debug', rateLimit, masterKey: MASTER },
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
    expect((await call(null, 'GET', '')).statusCode).toBe(401);
    expect((await call(null, 'POST', '/rotate', { password: PW })).statusCode).toBe(401);
    expect((await call(pa, 'GET', '')).statusCode).toBe(403);
    expect((await call(pa, 'POST', '/rotate', { password: PW })).statusCode).toBe(403);
    expect((await keysOf(INST_A)).length).toBe(1);
  });

  it('POST needs the CSRF header', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/institution/keys/rotate',
      headers: { cookie: a.headers.cookie!, ...json },
      payload: {},
    });
    expect(res.statusCode).toBe(403);
    expect((await keysOf(INST_A)).length).toBe(1);
  });

  it('lists keys without private material', async () => {
    const res = await call(a, 'GET', '');
    expect(res.statusCode).toBe(200);
    const items = res.json().items;
    expect(items.map((k: { kid: string }) => k.kid)).toEqual([kids[INST_A]]);
    expect(JSON.stringify(items)).not.toMatch(/encrypted|private/i);
  });

  it('rotate retires the old key and creates one new ACTIVE key', async () => {
    const res = await call(a, 'POST', '/rotate', { password: PW });
    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(body.retiredKid).toBe(kids[INST_A]);
    expect(body.active.status).toBe('ACTIVE');
    expect(body.active.kid).not.toBe(kids[INST_A]);
    expect(JSON.stringify(body)).not.toMatch(/encrypted|private/i);
    const rows = await keysOf(INST_A);
    expect(rows.filter((r) => r.status === 'ACTIVE').map((r) => r.kid)).toEqual([body.active.kid]);
    const old = rows.find((r) => r.kid === kids[INST_A])!;
    expect(old.status).toBe('RETIRED');
    expect(old.retired_at).not.toBeNull();
    kids.aNew = body.active.kid;
  });

  it('concurrent rotations leave exactly one ACTIVE key', async () => {
    const rs = await Promise.all([1, 2, 3].map(() => call(a, 'POST', '/rotate', { password: PW })));
    expect(rs.map((r) => r.statusCode)).toEqual([201, 201, 201]);
    const rows = await keysOf(INST_A);
    expect(rows.filter((r) => r.status === 'ACTIVE').length).toBe(1);
    expect(rows.length).toBe(5);
  });

  it('compromise requires a reason', async () => {
    expect((await call(a, 'POST', `/${kids.aNew}/compromise`, { password: PW })).json().error?.code ?? '').toBe('REASON_REQUIRED');
    expect((await call(a, 'POST', `/${kids.aNew}/compromise`, { reason: '  ', password: PW })).statusCode).toBe(400);
    expect((await keysOf(INST_A)).find((r) => r.kid === kids.aNew)!.status).toBe('RETIRED');
  });

  it('compromising a RETIRED key marks it and creates no replacement', async () => {
    const before = (await keysOf(INST_A)).length;
    const res = await call(a, 'POST', `/${kids.aNew}/compromise`, { reason: 'laptop stolen', password: PW });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ key: { kid: kids.aNew, status: 'COMPROMISED' }, replacement: null, previous: 'RETIRED' });
    expect((await keysOf(INST_A)).length).toBe(before);
  });

  it('compromising the ACTIVE key creates a replacement atomically; repeat is idempotent', async () => {
    const active = (await keysOf(INST_A)).find((r) => r.status === 'ACTIVE')!.kid;
    const res = await call(a, 'POST', `/${active}/compromise`, { reason: 'key leaked', password: PW });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.key.status).toBe('COMPROMISED');
    expect(body.replacement.status).toBe('ACTIVE');
    const rows = await keysOf(INST_A);
    expect(rows.filter((r) => r.status === 'ACTIVE').map((r) => r.kid)).toEqual([body.replacement.kid]);
    const n = rows.length;
    const again = await call(a, 'POST', `/${active}/compromise`, { reason: 'again', password: PW });
    expect(again.statusCode).toBe(200);
    expect(again.json().replacement).toBeNull();
    expect((await keysOf(INST_A)).length).toBe(n);
  });

  it('cross-tenant: another institution\'s kid is 404 and unchanged; own list excludes it', async () => {
    const res = await call(b, 'POST', `/${kids.aNew}/compromise`, { reason: 'x', password: PW });
    expect(res.statusCode).toBe(404);
    const resA = await call(a, 'POST', `/${kids[INST_B]}/compromise`, { reason: 'x', password: PW });
    expect(resA.statusCode).toBe(404);
    expect((await keysOf(INST_B)).map((r) => r.status)).toEqual(['ACTIVE']);
    const list = (await call(b, 'GET', '')).json().items.map((k: { kid: string }) => k.kid);
    expect(list).toEqual([kids[INST_B]]);
    expect((await call(a, 'POST', '/not-a-kid/compromise', { reason: 'x', password: PW })).statusCode).toBe(404);
  });

  it('DB refuses reactivating a key or changing a COMPROMISED one, whatever the role', async () => {
    const rows = await keysOf(INST_A);
    const retired = rows.find((r) => r.status === 'RETIRED')!.kid;
    const compromised = rows.find((r) => r.status === 'COMPROMISED')!.kid;
    for (const [kid, to] of [
      [retired, 'ACTIVE'],
      [compromised, 'ACTIVE'],
      [compromised, 'RETIRED'],
    ] as const) {
      await expect(
        ownerQuery(`UPDATE institution_keys SET status = $2::key_status WHERE kid = $1`, [kid, to]),
      ).rejects.toMatchObject({ code: '23514' });
    }
  });

  it('rotation of B does not touch A, and logs hold no key material', async () => {
    const aBefore = await keysOf(INST_A);
    expect((await call(b, 'POST', '/rotate', { password: PW })).statusCode).toBe(201);
    expect(await keysOf(INST_A)).toEqual(aBefore);
    const all = logs.join('');
    expect(all).not.toContain(MASTER.toString('base64'));
    expect(all).not.toMatch(/encrypted_private_key|encryptedPrivateKey/);
  });
});

describe.skipIf(!url)('signing keys without a master key (needs Postgres)', () => {
  it('rotate answers 503 KEY_CUSTODY_UNAVAILABLE', async () => {
    const { SigningKeyService } = await import('./signing-keys.js');
    const svc = new SigningKeyService({} as Db, undefined);
    await expect(svc.rotate({ kind: 'tenant', userId: 'u', institutionId: INST_A }, 'pw')).rejects.toMatchObject({
      statusCode: 503,
      code: 'KEY_CUSTODY_UNAVAILABLE',
    });
  });
});
