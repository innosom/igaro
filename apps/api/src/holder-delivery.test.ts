// T-041 (ADR 0030): email.deliver enqueue after issue/reissue, and DELIVERY_PAYLOAD_KEY config.
// Integration part skipped when DATABASE_URL is unset. Runs as igaro_app (RLS on) in a scratch schema. Test values only.
import { createHash, randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { Writable } from 'node:stream';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import type { FastifyInstance } from 'fastify';
import { generateSigningKey } from '@igaro/core';
import { openHolderDelivery, sealHolderDelivery } from '@igaro/worker/producer';
import { buildApp } from './app.js';
import { csrfTokenFor, hashPassword } from './auth.js';
import { ConfigError, loadConfig } from './config.js';
import { Db } from './db.js';
import { MemoryHolderDeliveryQueue } from './notifications.js';

const url = process.env.DATABASE_URL;
const migrationsDir = new URL('../../../packages/db/prisma/migrations/', import.meta.url);

const INST_A = '11111111-1111-4111-8111-111111111111';
const INST_B = '22222222-2222-4222-8222-222222222222';
const U_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const U_B = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const H_MAIL = 'a0000000-0000-4000-8000-000000000001';
const H_NOMAIL = 'a0000000-0000-4000-8000-000000000002';
const H_OTHER = 'b0000000-0000-4000-8000-000000000001';
const T_A = 'a1000000-0000-4000-8000-000000000001';
const T_B = 'b1000000-0000-4000-8000-000000000001';
const PW = 'correct horse battery staple';
const json = { 'content-type': 'application/json' };
const BIG = { ipMax: 10000, accountMax: 10000, windowSeconds: 900 };
const rateLimit = { login: BIG, reset: BIG, token: { ipMax: 10000, windowSeconds: 900 } };
const PHOTO_SHA = createHash('sha256').update('photo-a').digest('hex');
const HOLDER_EMAIL = 'ada@holders.test';

describe('DELIVERY_PAYLOAD_KEY config', () => {
  const good = { APP_DATABASE_URL: 'postgresql://igaro_app:s3cret-pw@127.0.0.1:5432/igaro', NODE_ENV: 'test' };
  const k = randomBytes(32).toString('base64');
  it('is optional outside production and parsed as 32 bytes', () => {
    expect(loadConfig(good).deliveryPayloadKey).toBeUndefined();
    expect(loadConfig({ ...good, DELIVERY_PAYLOAD_KEY: k }).deliveryPayloadKey?.toString('base64')).toBe(k);
  });
  it('rejects bad, placeholder and MASTER_KEY-equal values without echoing them', () => {
    for (const env of [
      { DELIVERY_PAYLOAD_KEY: 'short' },
      { DELIVERY_PAYLOAD_KEY: 'replace-me' },
      { DELIVERY_PAYLOAD_KEY: randomBytes(16).toString('base64') },
      { DELIVERY_PAYLOAD_KEY: k, MASTER_KEY: k },
    ]) {
      try {
        loadConfig({ ...good, ...env });
        throw new Error('should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(ConfigError);
        expect((e as Error).message).not.toContain(env.DELIVERY_PAYLOAD_KEY);
      }
    }
  });
});

describe('sealed job is readable only with the shared key', () => {
  it('round-trips through the shared contract', () => {
    const key = randomBytes(32);
    const job = { institutionId: INST_A, credentialId: H_MAIL.replace(/^a/, 'c'), to: HOLDER_EMAIL, holderToken: randomBytes(16).toString('base64url') };
    expect(openHolderDelivery(sealHolderDelivery(job, key), key)).toEqual(job);
  });
});

interface Client {
  headers: Record<string, string>;
}

describe.skipIf(!url)('holder delivery enqueue (needs Postgres)', () => {
  const schema = `t041_${randomBytes(4).toString('hex')}`;
  const master = randomBytes(32);
  let owner: pg.Client;
  let db: Db;
  let app: FastifyInstance;
  let a: Client;
  let b: Client;
  const logs: string[] = [];
  const queue = new MemoryHolderDeliveryQueue();

  const ownerQuery = async (sql: string, params: unknown[] = []) => {
    await owner.query('BEGIN');
    try {
      await owner.query(`SELECT set_config('app.is_platform_admin','true',true)`);
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
  const issueFor = (holderId: string, c: Client = a, typeCode = 'STUDENT_ID') =>
    app.inject({
      method: 'POST',
      url: '/api/v1/credentials',
      headers: { ...c.headers, ...json },
      payload: { holderId, credentialTypeCode: typeCode, attributes: { program: 'Computer Science' } },
    });
  const issue = async (holderId = H_MAIL) => {
    const res = await issueFor(holderId);
    expect(res.statusCode).toBe(201);
    return res.json() as { id: string; verificationToken: string; holderToken: string };
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
    for (const [id, inst, email] of [[U_A, INST_A, 'a@example.test'], [U_B, INST_B, 'b@example.test']] as const) {
      await ownerQuery(
        `INSERT INTO users (id, institution_id, email, name, password_hash, role, status, updated_at)
         VALUES ($1,$2,$3,'Name',$4,'INSTITUTION_ADMIN','ACTIVE',now())`,
        [id, inst, email, pwHash],
      );
    }
    for (const [tid, inst] of [[T_A, INST_A], [T_B, INST_B]] as const) {
      await ownerQuery(
        `INSERT INTO credential_types (id, institution_id, code, name, kind, attribute_schema, validity_days, updated_at)
         VALUES ($1, $2, 'STUDENT_ID', 'Student ID', 'ID_CARD', $3::jsonb, 365, now())`,
        [tid, inst, JSON.stringify([{ key: 'program', label: 'Programme', type: 'string', required: true }])],
      );
    }
    for (const [hid, inst, name, ext, email] of [
      [H_MAIL, INST_A, 'Ada Lovelace', 'ada-1', HOLDER_EMAIL],
      [H_NOMAIL, INST_A, 'No Mail', 'nm-1', null],
      [H_OTHER, INST_B, 'Other Tenant', 'ot-1', 'other@holders.test'],
    ] as const) {
      await ownerQuery(
        `INSERT INTO credential_holders (id, institution_id, full_name, external_id, email, photo_key, photo_sha256, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,now())`,
        [hid, inst, name, ext, email, `institutions/${inst}/holders/${hid}/photo/${PHOTO_SHA}.png`, PHOTO_SHA],
      );
    }

    db = new Db({ connectionString: url!, max: 8, poolConfig: { options: `-c search_path=${schema} -c role=igaro_app` } });
    const logStream = new Writable({
      write(c, _e, cb) {
        logs.push(String(c));
        cb();
      },
    });
    app = await buildApp({ config: { logLevel: 'debug', rateLimit, masterKey: master }, db, holderDelivery: queue, logStream });
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

  it('queues one delivery with the raw token and the holder email after issuance', async () => {
    queue.jobs.length = 0;
    const c = await issue();
    expect(queue.jobs).toEqual([{ institutionId: INST_A, credentialId: c.id, to: HOLDER_EMAIL, holderToken: c.holderToken }]);
  });

  it('the queued token is the one whose hash is stored (the link will open the holder view)', async () => {
    queue.jobs.length = 0;
    const c = await issue();
    const hash = createHash('sha256').update(queue.jobs[0]!.holderToken, 'utf8').digest('hex');
    const r = await ownerQuery(`SELECT holder_token_hash AS h FROM credentials WHERE id = $1`, [c.id]);
    expect(r.rows[0].h).toBe(hash);
  });

  it('queues the NEW credential with its new token after reissue', async () => {
    const old = await issue();
    queue.jobs.length = 0;
    const res = await app.inject({
      method: 'POST', url: `/api/v1/credentials/${old.id}/reissue`, headers: { ...a.headers, ...json }, payload: { reason: 'name corrected' },
    });
    expect(res.statusCode).toBe(201);
    const fresh = res.json().credential as { id: string; holderToken: string };
    expect(queue.jobs).toEqual([{ institutionId: INST_A, credentialId: fresh.id, to: HOLDER_EMAIL, holderToken: fresh.holderToken }]);
    expect(fresh.holderToken).not.toBe(old.holderToken);
  });

  it('queues nothing for a holder without an email, and says so without the address', async () => {
    queue.jobs.length = 0;
    logs.length = 0;
    await issue(H_NOMAIL);
    expect(queue.jobs).toEqual([]);
    expect(logs.join('')).toContain('delivery.skipped_no_email');
  });

  it('queues nothing when issuance fails or the holder belongs to another tenant (404)', async () => {
    queue.jobs.length = 0;
    expect((await issueFor(H_MAIL, a, 'NO_SUCH_TYPE')).statusCode).toBe(404);
    expect((await issueFor(H_OTHER, a)).statusCode).toBe(404);
    expect((await issueFor(H_MAIL, b)).statusCode).toBe(404);
    expect(queue.jobs).toEqual([]);
  });

  it('a queue failure never fails issuance or reissue; the log has ids and the error class only', async () => {
    queue.fail = true;
    logs.length = 0;
    try {
      const c = await issue();
      const res = await app.inject({
        method: 'POST', url: `/api/v1/credentials/${c.id}/reissue`, headers: { ...a.headers, ...json }, payload: { reason: 'again' },
      });
      expect(res.statusCode).toBe(201);
      const failed = logs.filter((l) => l.includes('delivery.enqueue_failed'));
      expect(failed.length).toBe(2);
      for (const l of failed) {
        expect(l).toContain('"errorClass":"Error"');
        expect(l).not.toContain('queue unavailable');
      }
      const rows = await ownerQuery(`SELECT status::text AS s FROM credentials WHERE id = $1`, [c.id]);
      expect(rows.rows[0].s).toBe('SUPERSEDED');
    } finally {
      queue.fail = false;
    }
  });

  it('never logs the holder token, the holder email or the sealed payload', async () => {
    logs.length = 0;
    queue.jobs.length = 0;
    const c = await issue();
    const out = logs.join('');
    expect(out).not.toContain(c.holderToken);
    expect(out).not.toContain(HOLDER_EMAIL);
    expect(out).not.toContain(c.verificationToken);
  });
});
