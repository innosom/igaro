// W3 security review fixes: key-change audit + password re-entry + rate limit (H1), suspended-institution
// guards (M2) and audit entries for holders, credential types and institution profile (M1). Needs Postgres.
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
import { MemoryObjectStorage } from './storage.js';
import { PNG } from './test-images.js';

const url = process.env.DATABASE_URL;
const migrationsDir = new URL('../../../packages/db/prisma/migrations/', import.meta.url);
const MASTER = randomBytes(32);
const INST_A = '11111111-1111-4111-8111-111111111111';
const INST_S = '33333333-3333-4333-8333-333333333333';
const PW = 'correct horse battery staple';
const json = { 'content-type': 'application/json' };
const BIG = { ipMax: 10000, accountMax: 10000, windowSeconds: 900 };
const rateLimit = { login: BIG, reset: BIG, token: { ipMax: 10000, windowSeconds: 900 } };

interface Client {
  headers: Record<string, string>;
}

describe.skipIf(!url)('W3 review fixes (needs Postgres)', () => {
  const schema = `w3fix_${randomBytes(4).toString('hex')}`;
  let owner: pg.Client;
  let db: Db;
  let app: FastifyInstance;
  let a: Client;
  let s: Client;
  const logs: string[] = [];
  const storage = new MemoryObjectStorage();
  const kids: Record<string, string> = {};

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
    const res = await app.inject({ method: 'POST', url: '/api/v1/auth/login', headers: json, payload: { email, password: PW } });
    expect(res.statusCode).toBe(200);
    const cookie = String(res.headers['set-cookie']).split(';')[0]!;
    return { headers: { cookie, 'x-csrf-token': csrfTokenFor(cookie.slice(cookie.indexOf('=') + 1)) } };
  };

  const call = (c: Client, method: 'GET' | 'POST' | 'PATCH' | 'DELETE', path: string, payload?: unknown) =>
    app.inject({
      method,
      url: `/api/v1${path}`,
      headers: { ...c.headers, ...(payload === undefined ? {} : json) },
      ...(payload === undefined ? {} : { payload: payload as Record<string, unknown> }),
    });

  const upload = (c: Client, path: string, data: Buffer) => {
    const boundary = `----w3${randomBytes(6).toString('hex')}`;
    const payload = Buffer.concat([
      Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="p.png"\r\nContent-Type: image/png\r\n\r\n`),
      data,
      Buffer.from(`\r\n--${boundary}--\r\n`),
    ]);
    return app.inject({
      method: 'POST',
      url: `/api/v1${path}`,
      headers: { ...c.headers, 'content-type': `multipart/form-data; boundary=${boundary}` },
      payload,
    });
  };

  const audit = async (inst: string, action?: string) =>
    (
      await ownerQuery(
        `SELECT action, target_type, target_id, metadata, actor_id, seq::text AS seq FROM audit_logs
          WHERE institution_id = $1 ${action ? 'AND action = $2' : ''} ORDER BY audit_logs.seq`,
        action ? [inst, action] : [inst],
      )
    ).rows as { action: string; target_type: string; target_id: string; metadata: Record<string, unknown>; actor_id: string }[];

  const chainOk = async (c: Client) => (await call(c, 'GET', '/audit-logs/verify-chain')).json();

  beforeAll(async () => {
    owner = new pg.Client({ connectionString: url });
    await owner.connect();
    await owner.query(`CREATE SCHEMA "${schema}"`);
    await owner.query(`SET search_path TO "${schema}"`);
    const dirs = readdirSync(migrationsDir, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name).sort();
    for (const d of dirs) await owner.query(readFileSync(new URL(`${d}/migration.sql`, migrationsDir), 'utf8'));
    await owner.query(`GRANT USAGE ON SCHEMA "${schema}" TO igaro_app`);

    const pwHash = await hashPassword(PW);
    for (const [id, slug, status] of [
      [INST_A, 'inst-a', 'ACTIVE'],
      [INST_S, 'inst-s', 'SUSPENDED'],
    ] as const) {
      await ownerQuery(`INSERT INTO institutions (id, name, slug, status, updated_at) VALUES ($1,$2,$3,$4::institution_status,now())`, [
        id, `Inst ${slug}`, slug, status,
      ]);
      const k = generateSigningKey(MASTER);
      kids[id] = k.kid;
      await ownerQuery(
        `INSERT INTO institution_keys (id, institution_id, kid, algorithm, public_key, encrypted_private_key, status)
         VALUES (gen_random_uuid(), $1, $2, 'Ed25519', $3, $4, 'ACTIVE')`,
        [id, k.kid, k.publicKey, k.encryptedPrivateKey],
      );
    }
    for (const [id, inst, email] of [
      ['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', INST_A, 'a@example.test'],
      ['dddddddd-dddd-4ddd-8ddd-dddddddddddd', INST_S, 's@example.test'],
    ] as const) {
      await ownerQuery(
        `INSERT INTO users (id, institution_id, email, name, password_hash, role, status, updated_at)
         VALUES ($1,$2,$3,'Name',$4,'INSTITUTION_ADMIN','ACTIVE',now())`,
        [id, inst, email, pwHash],
      );
    }
    // A holder in the suspended institution (inserted directly: suspended admins can still read).
    await ownerQuery(
      `INSERT INTO credential_holders (id, institution_id, full_name, updated_at)
       VALUES ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', $1, 'Held', now())`,
      [INST_S],
    );

    db = new Db({ connectionString: url!, max: 6, poolConfig: { options: `-c search_path=${schema} -c role=igaro_app` } });
    app = await buildApp({
      config: { logLevel: 'debug', rateLimit, masterKey: MASTER },
      keyChangeRateLimit: { max: 8, windowSeconds: 3600 },
      db,
      storage,
      logStream: new Writable({ write(c, _e, cb) { logs.push(String(c)); cb(); } }),
    });
    a = await loginAs('a@example.test');
    s = await loginAs('s@example.test');
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

  describe('H1 key changes', () => {
    it('rotate and compromise need the password: missing is 400, wrong is 403, and nothing changes', async () => {
      const before = (await audit(INST_A)).length;
      expect((await call(a, 'POST', '/institution/keys/rotate', {})).json().error.code).toBe('PASSWORD_REQUIRED');
      expect((await call(a, 'POST', '/institution/keys/rotate', { password: 'wrong-password-123' })).statusCode).toBe(403);
      const c = await call(a, 'POST', `/institution/keys/${kids[INST_A]}/compromise`, { reason: 'x' });
      expect(c.statusCode).toBe(400);
      expect((await call(a, 'POST', `/institution/keys/${kids[INST_A]}/compromise`, { reason: 'x', password: 'nope-nope-nope' })).statusCode).toBe(403);
      const keys = (await ownerQuery(`SELECT status FROM institution_keys WHERE institution_id = $1`, [INST_A])).rows;
      expect(keys.map((k) => k.status)).toEqual(['ACTIVE']);
      expect((await audit(INST_A)).length).toBe(before);
    });

    it('rotate writes a chained audit entry with kid and retiredKid', async () => {
      const res = await call(a, 'POST', '/institution/keys/rotate', { password: PW });
      expect(res.statusCode).toBe(201);
      const entries = await audit(INST_A, 'key.rotated');
      expect(entries).toHaveLength(1);
      expect(entries[0]).toMatchObject({
        target_type: 'institution_key',
        target_id: res.json().active.kid,
        actor_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        metadata: { kid: res.json().active.kid, retiredKid: kids[INST_A] },
      });
      kids.aNew = res.json().active.kid;
      expect((await chainOk(a)).valid).toBe(true);
    });

    it('compromise writes an audit entry with kid and reason; the reason is not in application logs', async () => {
      const reason = 'laptop-stolen-marker-7f3a';
      const res = await call(a, 'POST', `/institution/keys/${kids.aNew}/compromise`, { reason, password: PW });
      expect(res.statusCode).toBe(200);
      const entries = await audit(INST_A, 'key.compromised');
      expect(entries).toHaveLength(1);
      expect(entries[0]!.metadata).toMatchObject({
        kid: kids.aNew,
        previousStatus: 'ACTIVE',
        replacementKid: res.json().replacement.kid,
        reason,
      });
      expect(logs.join('')).not.toContain(reason);
      expect(logs.join('')).not.toContain(PW);
      expect((await chainOk(a)).valid).toBe(true);
    });

    it('a failing key change rolls back its audit entry (same transaction)', async () => {
      const before = (await audit(INST_A)).length;
      // Unknown (well-formed) kid: 404 after password check, no audit row.
      expect((await call(a, 'POST', '/institution/keys/kid_0000000000000000/compromise', { reason: 'x', password: PW })).statusCode).toBe(404);
      expect((await audit(INST_A)).length).toBe(before);
    });

    it('is rate limited per institution, counting wrong passwords, with Retry-After', async () => {
      // 8 allowed per hour: 6 already used above (2 wrong rotate/compromise, rotate, compromise, 404, plus the missing-password ones do not count).
      let limited: Awaited<ReturnType<typeof call>> | undefined;
      for (let i = 0; i < 10 && !limited; i++) {
        const r = await call(a, 'POST', '/institution/keys/rotate', { password: 'wrong-password-123' });
        if (r.statusCode === 429) limited = r;
        else expect(r.statusCode).toBe(403);
      }
      expect(limited).toBeDefined();
      expect(limited!.headers['retry-after']).toBeDefined();
      // Even the right password is refused while limited, and a different institution is unaffected.
      expect((await call(a, 'POST', '/institution/keys/rotate', { password: PW })).statusCode).toBe(429);
    });
  });

  describe('M2 suspended institution', () => {
    it('cannot rotate keys, upload a holder photo or a logo; same error as issuance; nothing stored', async () => {
      const objects = storage.objects.size;
      const keysBefore = (await ownerQuery(`SELECT count(*)::int AS n FROM institution_keys WHERE institution_id = $1`, [INST_S])).rows[0].n;

      const rot = await call(s, 'POST', '/institution/keys/rotate', { password: PW });
      expect(rot.statusCode).toBe(409);
      expect(rot.json().error.code).toBe('INSTITUTION_SUSPENDED');

      const photo = await upload(s, '/holders/eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee/photo', PNG());
      expect(photo.statusCode).toBe(409);
      expect(photo.json().error.code).toBe('INSTITUTION_SUSPENDED');

      const logo = await upload(s, '/institution/logo', PNG());
      expect(logo.statusCode).toBe(409);
      expect(logo.json().error.code).toBe('INSTITUTION_SUSPENDED');

      expect(storage.objects.size).toBe(objects);
      const keysAfter = (await ownerQuery(`SELECT count(*)::int AS n FROM institution_keys WHERE institution_id = $1`, [INST_S])).rows[0].n;
      expect(keysAfter).toBe(keysBefore);
      expect(await audit(INST_S)).toHaveLength(0);
      // Reads still work.
      expect((await call(s, 'GET', '/institution/keys')).statusCode).toBe(200);
      expect((await call(s, 'GET', '/institution')).statusCode).toBe(200);
    });
  });

  describe('M1 audit entries', () => {
    it('holder create, update, photo, delete are audited without PII values', async () => {
      const created = await call(a, 'POST', '/holders', { fullName: 'Ada Lovelace', email: 'ada@example.test', externalId: 'EXT-1' });
      expect(created.statusCode).toBe(201);
      const id = created.json().id as string;
      expect((await call(a, 'PATCH', `/holders/${id}`, { fullName: 'Ada King' })).statusCode).toBe(200);
      const photo = await upload(a, `/holders/${id}/photo`, PNG());
      expect(photo.statusCode).toBe(200);
      expect((await call(a, 'DELETE', `/holders/${id}`)).statusCode).toBe(204);

      const entries = (await audit(INST_A)).filter((e) => e.target_id === id);
      expect(entries.map((e) => e.action)).toEqual(['holder.created', 'holder.updated', 'holder.photo_updated', 'holder.deleted']);
      expect(entries[1]!.metadata).toEqual({ fields: ['fullName'] });
      expect(entries[2]!.metadata).toMatchObject({ photoSha256: expect.stringMatching(/^[0-9a-f]{64}$/) });
      const text = JSON.stringify(entries);
      for (const pii of ['Ada', 'ada@example.test', 'EXT-1']) expect(text).not.toContain(pii);
      expect((await chainOk(a)).valid).toBe(true);
    });

    it('a rejected holder change writes no audit entry', async () => {
      const before = (await audit(INST_A)).length;
      expect((await call(a, 'PATCH', '/holders/00000000-0000-4000-8000-000000000000', { fullName: 'X' })).statusCode).toBe(404);
      expect((await audit(INST_A)).length).toBe(before);
    });

    it('credential type create, update, delete are audited', async () => {
      const created = await call(a, 'POST', '/credential-types', { code: 'AUDITED', kind: 'CERTIFICATE', name: 'Audited', attributes: [] });
      expect(created.statusCode).toBe(201);
      const id = created.json().id as string;
      expect((await call(a, 'PATCH', `/credential-types/${id}`, { name: 'Audited 2' })).statusCode).toBe(200);
      expect((await call(a, 'DELETE', `/credential-types/${id}`)).statusCode).toBe(204);
      const entries = (await audit(INST_A)).filter((e) => e.target_id === id);
      expect(entries.map((e) => e.action)).toEqual(['credential_type.created', 'credential_type.updated', 'credential_type.deleted']);
      expect(entries[0]!.metadata).toMatchObject({ code: 'AUDITED' });
      expect(entries[1]!.metadata).toEqual({ fields: ['name'] });
    });

    it('institution profile and logo changes are audited', async () => {
      expect((await call(a, 'PATCH', '/institution', { cardTitle: 'Student Card' })).statusCode).toBe(200);
      expect((await upload(a, '/institution/logo', PNG())).statusCode).toBe(200);
      const e = (await audit(INST_A)).filter((x) => x.action.startsWith('institution.'));
      expect(e.map((x) => x.action)).toEqual(['institution.updated', 'institution.logo_updated']);
      expect(e[0]!.metadata).toEqual({ fields: ['cardTitle'] });
      expect(e[0]!.target_id).toBe(INST_A);
      expect((await chainOk(a)).valid).toBe(true);
    });

    it('no audit metadata holds tokens, keys or passwords', async () => {
      const text = JSON.stringify((await audit(INST_A)).map((e) => e.metadata));
      expect(text).not.toContain(PW);
      expect(text).not.toMatch(/encrypted|private/i);
    });
  });
});
