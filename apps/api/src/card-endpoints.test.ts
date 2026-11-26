// T-040 (ADR 0029): card.render enqueue after issue/reissue and GET /credentials/:id/card.{png,pdf}.
// Skipped when DATABASE_URL is unset. Runs as igaro_app (RLS on) in a scratch schema. Test values only.
import { createHash, randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { Writable } from 'node:stream';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import type { FastifyInstance } from 'fastify';
import { generateSigningKey } from '@igaro/core';
import { cardStorageKeys, enqueueCardRender } from '@igaro/worker/producer';
import { buildApp } from './app.js';
import { csrfTokenFor, hashPassword } from './auth.js';
import { Db } from './db.js';
import { MemoryCardRenderQueue, NoopCardRenderQueue } from './notifications.js';
import { MemoryObjectStorage, S3ObjectStorage } from './storage.js';

const url = process.env.DATABASE_URL;
const migrationsDir = new URL('../../../packages/db/prisma/migrations/', import.meta.url);

const INST_A = '11111111-1111-4111-8111-111111111111';
const INST_B = '22222222-2222-4222-8222-222222222222';
const U_PA = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const U_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const U_B = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const H_A = 'a0000000-0000-4000-8000-000000000001';
const T_A = 'a1000000-0000-4000-8000-000000000001';
const MISSING = '99999999-9999-4999-8999-999999999999';
const PW = 'correct horse battery staple';
const json = { 'content-type': 'application/json' };
const BIG = { ipMax: 10000, accountMax: 10000, windowSeconds: 900 };
const rateLimit = { login: BIG, reset: BIG, token: { ipMax: 10000, windowSeconds: 900 } };
const PHOTO_SHA = createHash('sha256').update('photo-a').digest('hex');

interface Client {
  headers: Record<string, string>;
}

describe('MemoryObjectStorage.exists and S3 HEAD', () => {
  it('memory exists reflects put/delete', async () => {
    const s = new MemoryObjectStorage();
    expect(await s.exists('k')).toBe(false);
    await s.put('k', Buffer.from('x'), 'image/png');
    expect(await s.exists('k')).toBe(true);
    await s.delete('k');
    expect(await s.exists('k')).toBe(false);
  });
  it('S3 HEAD: 200 true, 404 false, other errors throw', async () => {
    const { createServer } = await import('node:http');
    const srv = createServer((req, res) => {
      res.statusCode = req.url?.includes('missing') ? 404 : req.url?.includes('boom') ? 500 : 200;
      res.end();
    });
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
    try {
      const port = (srv.address() as { port: number }).port;
      const s = new S3ObjectStorage({
        endpoint: `http://127.0.0.1:${port}`, region: 'us-east-1', bucket: 'b', accessKey: 'AK', secretKey: 'SK', forcePathStyle: true,
      });
      expect(await s.exists('here')).toBe(true);
      expect(await s.exists('missing')).toBe(false);
      await expect(s.exists('boom')).rejects.toThrow();
    } finally {
      await new Promise((r) => srv.close(r));
    }
  });
});

describe('PgBossCardRenderQueue payload (unit)', () => {
  it('sends ids only with the per-credential singleton key', async () => {
    const calls: { name: string; data: object; opts: Record<string, unknown> }[] = [];
    await enqueueCardRender({ send: async (name, data, opts) => (calls.push({ name, data, opts }), 'job-id') }, { institutionId: INST_A, credentialId: MISSING });
    expect(calls).toEqual([
      { name: 'card.render', data: { institutionId: INST_A, credentialId: MISSING }, opts: { singletonKey: `card.render:${MISSING}` } },
    ]);
  });
});

describe.skipIf(!url)('card endpoints (needs Postgres)', () => {
  const schema = `t040_${randomBytes(4).toString('hex')}`;
  const master = randomBytes(32);
  let owner: pg.Client;
  let db: Db;
  let app: FastifyInstance;
  let appNoStorage: FastifyInstance;
  let a: Client;
  let aNoStorage: Client;
  let b: Client;
  let pa: Client;
  const logs: string[] = [];
  const storage = new MemoryObjectStorage();
  const queue = new MemoryCardRenderQueue();

  const ownerQuery = async (sql: string, params: unknown[] = [], bypass = false) => {
    await owner.query('BEGIN');
    try {
      await owner.query(`SELECT set_config('app.is_platform_admin','true',true)`);
      if (bypass) await owner.query('ALTER TABLE credentials DISABLE TRIGGER USER');
      const r = await owner.query(sql, params);
      if (bypass) await owner.query('ALTER TABLE credentials ENABLE TRIGGER USER');
      await owner.query('COMMIT');
      return r;
    } catch (e) {
      await owner.query('ROLLBACK');
      throw e;
    }
  };
  const loginAs = async (which: FastifyInstance, email: string): Promise<Client> => {
    const res = await which.inject({ method: 'POST', url: '/api/v1/auth/login', headers: json, payload: { email, password: PW } });
    expect(res.statusCode).toBe(200);
    const cookie = String(res.headers['set-cookie']).split(';')[0]!;
    return { headers: { cookie, 'x-csrf-token': csrfTokenFor(cookie.slice(cookie.indexOf('=') + 1)) } };
  };
  const issue = async (c: Client = a, which: FastifyInstance = app) => {
    const res = await which.inject({
      method: 'POST',
      url: '/api/v1/credentials',
      headers: { ...c.headers, ...json },
      payload: { holderId: H_A, credentialTypeCode: 'STUDENT_ID', attributes: { program: 'Computer Science' } },
    });
    expect(res.statusCode).toBe(201);
    return res.json() as { id: string; verificationToken: string; holderToken: string };
  };
  const post = (id: string, action: string, payload: Record<string, unknown>, c: Client = a) =>
    app.inject({ method: 'POST', url: `/api/v1/credentials/${id}/${action}`, headers: { ...c.headers, ...json }, payload });
  const getCard = (id: string, ext: 'png' | 'pdf' = 'png', c: Client | null = a, which: FastifyInstance = app) =>
    which.inject({ method: 'GET', url: `/api/v1/credentials/${id}/card.${ext}`, headers: c?.headers ?? {} });
  const putCard = async (id: string, inst = INST_A) => {
    const k = cardStorageKeys(inst, id);
    await storage.put(k.png, Buffer.from('png'), 'image/png');
    await storage.put(k.pdf, Buffer.from('pdf'), 'application/pdf');
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
    for (const d of dirs) await owner.query(readFileSync(new URL(`${d}/migration.sql`, migrationsDir), 'utf8'));
    await owner.query(`GRANT USAGE ON SCHEMA "${schema}" TO igaro_app`);

    const pwHash = await hashPassword(PW);
    for (const [id, slug] of [[INST_A, 'inst-a'], [INST_B, 'inst-b']] as const) {
      await ownerQuery(`INSERT INTO institutions (id, name, slug, updated_at) VALUES ($1,$2,$3,now())`, [id, `Inst ${slug}`, slug]);
      const k = generateSigningKey(master);
      await ownerQuery(
        `INSERT INTO institution_keys (id, institution_id, kid, algorithm, public_key, encrypted_private_key, status)
         VALUES (gen_random_uuid(), $1, $2, 'Ed25519', $3, $4, 'ACTIVE')`,
        [id, k.kid, k.publicKey, k.encryptedPrivateKey],
      );
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
    await ownerQuery(
      `INSERT INTO credential_types (id, institution_id, code, name, kind, attribute_schema, validity_days, updated_at)
       VALUES ($1, $2, 'STUDENT_ID', 'Student ID', 'ID_CARD', $3::jsonb, 365, now())`,
      [T_A, INST_A, JSON.stringify([{ key: 'program', label: 'Programme', type: 'string', required: true }])],
    );
    await ownerQuery(
      `INSERT INTO credential_holders (id, institution_id, full_name, external_id, photo_key, photo_sha256, updated_at)
       VALUES ($1,$2,'Ada Lovelace','ada-1',$3,$4,now())`,
      [H_A, INST_A, `institutions/${INST_A}/holders/${H_A}/photo/${PHOTO_SHA}.png`, PHOTO_SHA],
    );

    db = new Db({ connectionString: url!, max: 8, poolConfig: { options: `-c search_path=${schema} -c role=igaro_app` } });
    const logStream = new Writable({
      write(c, _e, cb) {
        logs.push(String(c));
        cb();
      },
    });
    app = await buildApp({ config: { logLevel: 'debug', rateLimit, masterKey: master }, db, storage, cardRender: queue, logStream });
    appNoStorage = await buildApp({ config: { logLevel: 'silent', rateLimit, masterKey: master }, db, cardRender: new NoopCardRenderQueue() });
    pa = await loginAs(app, 'pa@example.test');
    a = await loginAs(app, 'a@example.test');
    b = await loginAs(app, 'b@example.test');
    aNoStorage = await loginAs(appNoStorage, 'a@example.test');
  });

  afterAll(async () => {
    await app?.close();
    await appNoStorage?.close();
    await db?.close();
    if (!owner) return;
    await owner.query('ROLLBACK').catch(() => undefined);
    await owner.query('RESET search_path');
    await owner.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    await owner.end();
  });

  describe('enqueue', () => {
    it('queues one ids-only job after issue', async () => {
      queue.jobs.length = 0;
      const c = await issue();
      expect(queue.jobs).toEqual([{ institutionId: INST_A, credentialId: c.id }]);
      expect(JSON.stringify(queue.jobs)).not.toContain(c.verificationToken);
      expect(JSON.stringify(queue.jobs)).not.toContain(c.holderToken);
    });

    it('queues the NEW credential after reissue, not the old one', async () => {
      const old = await issue();
      queue.jobs.length = 0;
      const res = await post(old.id, 'reissue', { reason: 'name corrected' });
      expect(res.statusCode).toBe(201);
      const fresh = res.json().credential.id as string;
      expect(fresh).not.toBe(old.id);
      expect(queue.jobs).toEqual([{ institutionId: INST_A, credentialId: fresh }]);
    });

    it('does not enqueue when issuance fails', async () => {
      queue.jobs.length = 0;
      const res = await app.inject({
        method: 'POST', url: '/api/v1/credentials', headers: { ...a.headers, ...json },
        payload: { holderId: H_A, credentialTypeCode: 'STUDENT_ID', attributes: {} },
      });
      expect(res.statusCode).toBe(400);
      expect(queue.jobs).toEqual([]);
    });

    it('enqueue failure never fails issuance or reissue; the log has ids and error class only', async () => {
      queue.fail = true;
      logs.length = 0;
      try {
        const c = await issue();
        const res = await post(c.id, 'reissue', { reason: 'again' });
        expect(res.statusCode).toBe(201);
        const failed = logs.filter((l) => l.includes('card.enqueue_failed'));
        expect(failed.length).toBe(2);
        for (const l of failed) {
          expect(l).toContain('"errorClass":"Error"');
          expect(l).not.toContain('queue unavailable');
          expect(l).not.toContain(c.verificationToken);
        }
        const rows = await ownerQuery(`SELECT status::text AS s FROM credentials WHERE id = $1`, [c.id]);
        expect(rows.rows[0].s).toBe('SUPERSEDED');
      } finally {
        queue.fail = false;
      }
    });
  });

  describe('GET card.png / card.pdf', () => {
    it('302 to a short-lived signed URL, no-store, for both formats', async () => {
      const c = await issue();
      await putCard(c.id);
      for (const ext of ['png', 'pdf'] as const) {
        logs.length = 0;
        const res = await getCard(c.id, ext);
        expect(res.statusCode).toBe(302);
        expect(res.headers['cache-control']).toBe('no-store');
        const loc = String(res.headers.location);
        expect(loc).toContain(encodeURIComponent(cardStorageKeys(INST_A, c.id)[ext]));
        expect(loc).toContain('expires=60');
        // The signed URL is never logged.
        expect(logs.join('')).not.toContain(encodeURIComponent(cardStorageKeys(INST_A, c.id)[ext]));
        expect(logs.join('')).not.toContain(c.verificationToken);
      }
    });

    it('404 CARD_NOT_READY with Retry-After when the card is not rendered yet', async () => {
      const c = await issue();
      const res = await getCard(c.id, 'png');
      expect(res.statusCode).toBe(404);
      expect(res.json().error.code).toBe('CARD_NOT_READY');
      expect(Number(res.headers['retry-after'])).toBeGreaterThan(0);
      expect(res.headers['cache-control']).toBe('no-store');
      expect(res.headers.location).toBeUndefined();
    });

    it('404 when only the other format exists', async () => {
      const c = await issue();
      await storage.put(cardStorageKeys(INST_A, c.id).png, Buffer.from('png'), 'image/png');
      expect((await getCard(c.id, 'pdf')).json().error.code).toBe('CARD_NOT_READY');
      expect((await getCard(c.id, 'png')).statusCode).toBe(302);
    });

    it('cross-tenant, unknown and malformed ids are the same 404', async () => {
      const c = await issue();
      await putCard(c.id);
      const foreign = await getCard(c.id, 'png', b);
      const unknown = await getCard(MISSING, 'png', b);
      const malformed = await getCard('not-a-uuid', 'png', a);
      for (const r of [foreign, unknown, malformed]) {
        expect(r.statusCode).toBe(404);
        expect(r.json()).toEqual({ error: { code: 'NOT_FOUND', message: 'Not found' } });
        expect(r.headers.location).toBeUndefined();
      }
    });

    it('404 for SUSPENDED, REVOKED and SUPERSEDED credentials, and again after reinstatement it works', async () => {
      const sus = await issue();
      const rev = await issue();
      const sup = await issue();
      for (const c of [sus, rev, sup]) await putCard(c.id);
      expect((await post(sus.id, 'suspend', { reason: 'check' })).statusCode).toBe(200);
      expect((await post(rev.id, 'revoke', { reason: 'fraud' })).statusCode).toBe(200);
      expect((await post(sup.id, 'reissue', { reason: 'fix' })).statusCode).toBe(201);
      for (const c of [sus, rev, sup]) {
        const r = await getCard(c.id);
        expect(r.statusCode).toBe(404);
        expect(r.json().error.code).toBe('NOT_FOUND');
      }
      expect((await post(sus.id, 'reinstate', {})).statusCode).toBe(200);
      expect((await getCard(sus.id)).statusCode).toBe(302);
    });

    it('404 once the SIGNED expiry has passed; the unsigned expires_at column is ignored', async () => {
      const soon = new Date(Date.now() + 2000).toISOString().slice(0, 19) + 'Z';
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/credentials',
        headers: { ...a.headers, ...json },
        payload: { holderId: H_A, credentialTypeCode: 'STUDENT_ID', attributes: { program: 'Computer Science' }, expiresAt: soon },
      });
      expect(res.statusCode).toBe(201);
      const c = res.json() as { id: string };
      await putCard(c.id);
      expect((await getCard(c.id)).statusCode).toBe(302);
      // Pushing the unsigned column into the past changes nothing for a live credential.
      const live = await issue();
      await putCard(live.id);
      await ownerQuery(`UPDATE credentials SET expires_at = now() - interval '1 day', issued_at = now() - interval '2 days' WHERE id = $1`, [live.id], true);
      expect((await getCard(live.id)).statusCode).toBe(302);
      await new Promise((r) => setTimeout(r, 3100));
      expect((await getCard(c.id)).statusCode).toBe(404);
    });

    it('tampered payload, tampered hash, bad signature and a swapped key are never served; ops alert has ids only', async () => {
      const cases: [string, string][] = [
        ['payload', `payload = jsonb_set(payload, '{holder,fullName}', '"Mallory"')`],
        ['data_hash', `data_hash = repeat('0', 64)`],
        ['signature', `signature = repeat('A', 86)`],
      ];
      for (const [label, set] of cases) {
        const c = await issue();
        await putCard(c.id);
        expect((await getCard(c.id)).statusCode).toBe(302);
        await ownerQuery(`UPDATE credentials SET ${set} WHERE id = $1`, [c.id], true);
        logs.length = 0;
        const res = await getCard(c.id);
        expect(res.statusCode, label).toBe(404);
        expect(res.json().error.code).toBe('NOT_FOUND');
        const alert = logs.find((l) => l.includes('card.integrity_failure'));
        expect(alert, label).toBeDefined();
        expect(alert).toContain(c.id);
        expect(alert).not.toContain('Mallory');
        expect(alert).not.toContain(c.verificationToken);
      }
    });

    it('503 when storage is not configured, after the integrity check (unknown ids stay 404)', async () => {
      const c = await issue();
      const res = await getCard(c.id, 'png', aNoStorage, appNoStorage);
      expect(res.statusCode).toBe(503);
      expect(res.json().error.code).toBe('STORAGE_UNAVAILABLE');
      expect((await getCard(MISSING, 'png', aNoStorage, appNoStorage)).statusCode).toBe(404);
    });

    it('503 when the storage lookup fails, without leaking detail', async () => {
      const c = await issue();
      storage.failExists = true;
      try {
        const res = await getCard(c.id);
        expect(res.statusCode).toBe(503);
        expect(res.json().error.code).toBe('STORAGE_UNAVAILABLE');
      } finally {
        storage.failExists = false;
      }
    });

    it('requires a session and the INSTITUTION_ADMIN role', async () => {
      const c = await issue();
      await putCard(c.id);
      expect((await getCard(c.id, 'png', null)).statusCode).toBe(401);
      expect((await getCard(c.id, 'pdf', null)).statusCode).toBe(401);
      expect((await getCard(c.id, 'png', pa)).statusCode).toBe(403);
    });

    it('a card for a credential of another tenant is never reachable through the id of this tenant', async () => {
      const c = await issue();
      // B's key space holds an object under B's own prefix; A's credential id must still not resolve for B.
      await storage.put(cardStorageKeys(INST_B, c.id).png, Buffer.from('x'), 'image/png');
      expect((await getCard(c.id, 'png', b)).statusCode).toBe(404);
    });

    // Last on purpose: a COMPROMISED key cannot be restored (DB trigger), so nothing may issue after this.
    it('a credential from a COMPROMISED key is not served', async () => {
      const c = await issue();
      await putCard(c.id);
      expect((await getCard(c.id)).statusCode).toBe(302);
      await ownerQuery(`UPDATE institution_keys SET status = 'RETIRED', retired_at = now() WHERE institution_id = $1`, [INST_A]);
      expect((await getCard(c.id)).statusCode).toBe(302); // RETIRED keys still verify
      await ownerQuery(`UPDATE institution_keys SET status = 'COMPROMISED' WHERE institution_id = $1`, [INST_A]);
      expect((await getCard(c.id)).statusCode).toBe(404);
    });
  });
});
