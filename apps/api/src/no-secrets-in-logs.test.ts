// T-048 / white paper s15 last criterion: "No private key, salt or token appears in any log." (invariant 9, ADR 0002)
// One scenario drives every flow that handles a secret (invite, login, failed login, issue, verify, key rotation, password
// reset, 5-row CSV+ZIP import through the real worker consumer) with API logging at debug and the worker's logger captured,
// then scans everything written for each secret value the test generated. Skipped when DATABASE_URL is unset.
// All values are generated test values; nothing here is a real credential.
import { createHash, randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { Writable } from 'node:stream';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import type { FastifyInstance } from 'fastify';
import { unwrapPrivateKey } from '@igaro/core';
import { runImportBatch, ImportApiError, type ImportApi, type ImportBatchDeps } from '@igaro/worker';
import { buildApp } from './app.js';
import { csrfTokenFor, hashPassword } from './auth.js';
import { Db } from './db.js';
import { MemoryAccountMailQueue, MemoryCardRenderQueue, MemoryHolderDeliveryQueue, MemoryImportBatchQueue } from './notifications.js';
import { MemoryObjectStorage } from './storage.js';
import { JPEG } from './test-images.js';
import { makeZip } from './test-zip.js';

const url = process.env.DATABASE_URL;
const migrationsDir = new URL('../../../packages/db/prisma/migrations/', import.meta.url);

const U_PA = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const PA_PW = 'platform admin test passphrase 1';
const IA_PW = 'institution admin test passphrase 2';
const NEW_PW = 'institution admin new passphrase 3';
const WRONG_PW = 'definitely the wrong passphrase 4';
const INTERNAL = randomBytes(32).toString('base64url');
const json = { 'content-type': 'application/json' };
const BIG = { ipMax: 100000, accountMax: 100000, windowSeconds: 900 };
const rateLimit = { login: BIG, reset: BIG, token: { ipMax: 100000, windowSeconds: 900 } };

/** Every encoding a secret could plausibly be logged in. Short values (< 8 chars) are refused: they would match by chance. */
const variants = (label: string, v: string | Buffer): [string, string][] => {
  const b = Buffer.isBuffer(v) ? v : Buffer.from(v, 'utf8');
  const out: [string, string][] = [[label, Buffer.isBuffer(v) ? '' : v], [`${label} (hex)`, b.toString('hex')], [`${label} (base64)`, b.toString('base64')], [`${label} (base64url)`, b.toString('base64url')]];
  return out.filter(([, s]) => s.length >= 8);
};
/** Returns the labels of the secrets found in the text (never the secret values themselves, so a failure does not leak them). */
const scan = (text: string, secrets: [string, string][]): string[] => [...new Set(secrets.filter(([, s]) => text.includes(s)).map(([l]) => l))];

interface Client {
  headers: Record<string, string>;
  cookieValue: string;
}

describe.skipIf(!url)('no secret reaches any log across issue, verify, login, import and reset (needs Postgres)', () => {
  const schema = `t048_${randomBytes(4).toString('hex')}`;
  const master = randomBytes(32);
  const apiLogs: string[] = [];
  const workerLogs: string[] = [];
  const secrets: [string, string][] = [];
  const mail = new MemoryAccountMailQueue();
  const cards = new MemoryCardRenderQueue();
  const delivery = new MemoryHolderDeliveryQueue();
  const batches = new MemoryImportBatchQueue();
  const storage = new MemoryObjectStorage();
  let owner: pg.Client;
  let db: Db;
  let app: FastifyInstance;
  const add = (label: string, v: string | Buffer | undefined | null) => {
    if (v) secrets.push(...variants(label, v));
  };

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
  const call = (method: 'GET' | 'POST', path: string, c: Pick<Client, 'headers'> | null, payload?: unknown) =>
    app.inject({ method, url: `/api/v1${path}`, headers: { ...(c?.headers ?? {}), ...(payload === undefined ? {} : json) }, ...(payload === undefined ? {} : { payload: payload as Record<string, unknown> }) });
  const login = async (email: string, password: string): Promise<Client> => {
    const res = await call('POST', '/auth/login', null, { email, password });
    expect(res.statusCode).toBe(200);
    const cookie = String(res.headers['set-cookie']).split(';')[0]!;
    const cookieValue = cookie.slice(cookie.indexOf('=') + 1);
    const csrf = csrfTokenFor(cookieValue);
    add('session token', cookieValue);
    add('csrf token', csrf);
    return { headers: { cookie, 'x-csrf-token': csrf }, cookieValue };
  };

  beforeAll(async () => {
    owner = new pg.Client({ connectionString: url });
    await owner.connect();
    await owner.query(`CREATE SCHEMA "${schema}"`);
    await owner.query(`SET search_path TO "${schema}"`);
    const dirs = readdirSync(migrationsDir, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name).sort();
    for (const d of dirs) await owner.query(readFileSync(new URL(`${d}/migration.sql`, migrationsDir), 'utf8'));
    await owner.query(`GRANT USAGE ON SCHEMA "${schema}" TO igaro_app`);
    await ownerQuery(
      `INSERT INTO users (id, institution_id, email, name, password_hash, role, status, updated_at) VALUES ($1,NULL,'pa@example.test','Platform Admin',$2,'PLATFORM_ADMIN','ACTIVE',now())`,
      [U_PA, await hashPassword(PA_PW)],
    );
    db = new Db({ connectionString: url!, max: 8, poolConfig: { options: `-c search_path=${schema} -c role=igaro_app` } });
    const logStream = new Writable({ write(c, _e, cb) { apiLogs.push(String(c)); cb(); } });
    app = await buildApp({
      config: { logLevel: 'trace', rateLimit, masterKey: master, internalApiToken: INTERNAL },
      db, storage, logStream, accountMail: mail, cardRender: cards, holderDelivery: delivery, importBatch: batches,
      importRateLimit: { max: 100000, windowSeconds: 3600 },
    });
    add('master key', master);
    add('internal API token', INTERNAL);
    for (const [l, p] of [['platform password', PA_PW], ['admin password', IA_PW], ['new password', NEW_PW], ['wrong password', WRONG_PW]] as const) add(l, p);
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

  it('scanner self-check: finds a planted secret in every encoding and never reports a value', () => {
    const s = variants('planted', randomBytes(32));
    for (const [label, enc] of s) expect(scan(`line ${enc} end`, s)).toContain(label);
    expect(scan('nothing here', s)).toEqual([]);
    expect(variants('short', 'abc')).toEqual([]);
  });

  it('flows: invite, login, failed login, issue, verify, key rotation, reset, import', async () => {
    // --- invite: platform admin creates an institution; the invite token travels only in the mail job.
    const pa = await login('pa@example.test', PA_PW);
    const created = await call('POST', '/institutions', pa, { name: 'Log Test University', slug: 'log-test', adminEmail: 'admin@example.test' });
    expect(created.statusCode).toBe(201);
    const instId = created.json().institution.id as string;
    const invite = mail.jobs.find((j) => j.kind === 'INVITE');
    expect(invite).toBeDefined();
    add('invite token', invite!.token);
    const accepted = await call('POST', '/auth/invites/accept', null, { token: invite!.token, password: IA_PW, name: 'Inst Admin' });
    expect(accepted.statusCode).toBe(204);

    // --- login, failed login (password never echoed), session cookie + csrf registered by login().
    expect((await call('POST', '/auth/login', null, { email: 'admin@example.test', password: WRONG_PW })).statusCode).toBe(401);
    expect((await call('POST', '/auth/login', null, { email: 'nobody@example.test', password: WRONG_PW })).statusCode).toBe(401);
    const a = await login('admin@example.test', IA_PW);
    expect((await call('GET', '/auth/me', a)).statusCode).toBe(200);

    // --- seed a type and holders under the new institution (owner connection), then issue through the API.
    await ownerQuery(
      `INSERT INTO credential_types (id, institution_id, code, name, kind, attribute_schema, validity_days, updated_at)
       VALUES (gen_random_uuid(), $1, 'STUDENT_ID', 'Student ID', 'ID_CARD', $2::jsonb, 365, now())`,
      [instId, JSON.stringify([{ key: 'program', label: 'Programme', type: 'string', required: true }])],
    );
    const photoSha = createHash('sha256').update('log-test-photo').digest('hex');
    const holderId = 'a0000000-0000-4000-8000-0000000000aa';
    await ownerQuery(
      `INSERT INTO credential_holders (id, institution_id, full_name, external_id, email, photo_key, photo_sha256, updated_at) VALUES ($1,$2,'Ada Lovelace','ada-1','ada@example.test',$3,$4,now())`,
      [holderId, instId, `institutions/${instId}/holders/${holderId}/photo/${photoSha}.jpg`, photoSha],
    );
    const issued = await call('POST', '/credentials', a, { holderId, credentialTypeCode: 'STUDENT_ID', attributes: { program: 'Computer Science' } });
    expect(issued.statusCode).toBe(201);
    const cred = issued.json();
    add('verification token (issue)', cred.verificationToken);
    add('holder token (issue)', cred.holderToken);
    add('salt (issue)', cred.payload.salt);
    add('signature (issue)', cred.signature);
    expect(delivery.jobs.length).toBeGreaterThan(0);

    // --- verify: found, public JSON, and unknown tokens (a probe must not be echoed either).
    const probe = randomBytes(16).toString('base64url');
    add('probe token', probe);
    expect((await call('GET', `/verify/${cred.verificationToken}`, null)).json().result).toBe('VERIFIED');
    expect((await call('GET', `/verify/${cred.verificationToken}/credential.json`, null)).statusCode).toBe(200);
    expect((await call('GET', `/verify/${probe}`, null)).json().result).toBe('NOT_FOUND');

    // --- key rotation: private keys are unwrapped to sign; none of it may be logged.
    expect((await call('POST', '/institution/keys/rotate', a, { password: IA_PW })).statusCode).toBeLessThan(300);
    const keys = (await ownerQuery(`SELECT kid, encrypted_private_key FROM institution_keys WHERE institution_id = $1`, [instId])).rows as { kid: string; encrypted_private_key: string }[];
    expect(keys.length).toBe(2);
    for (const k of keys) {
      add(`wrapped private key ${k.kid}`, k.encrypted_private_key);
      const der = unwrapPrivateKey(k.encrypted_private_key, master, k.kid).export({ format: 'der', type: 'pkcs8' });
      add(`private key ${k.kid} (pkcs8)`, Buffer.from(der));
      add(`private key ${k.kid} (raw seed)`, Buffer.from(der).subarray(-32));
    }
    const second = await call('POST', '/credentials', a, { holderId, credentialTypeCode: 'STUDENT_ID', attributes: { program: 'Physics' } });
    expect(second.statusCode).toBe(201);
    for (const f of ['verificationToken', 'holderToken'] as const) add(`${f} (second)`, second.json()[f]);
    add('salt (second)', second.json().payload.salt);

    // --- password reset: request and confirm; the token is only in the mail job.
    mail.jobs.length = 0;
    expect((await call('POST', '/auth/password-reset', null, { email: 'admin@example.test' })).statusCode).toBe(202);
    expect((await call('POST', '/auth/password-reset', null, { email: 'unknown@example.test' })).statusCode).toBe(202);
    const reset = mail.jobs.find((j) => j.kind === 'PASSWORD_RESET');
    expect(reset).toBeDefined();
    add('reset token', reset!.token);
    expect((await call('POST', '/auth/password-reset', null, { token: reset!.token, password: NEW_PW })).statusCode).toBe(204);
    expect((await call('POST', '/auth/password-reset', null, { token: reset!.token, password: NEW_PW })).statusCode).toBeGreaterThanOrEqual(400); // replay
    const a2 = await login('admin@example.test', NEW_PW);

    // --- import: dry run, intake, the real worker consumer against the internal endpoints, with its logger captured.
    const ids = ['imp-1', 'imp-2', 'imp-3', 'imp-4', 'imp-5'];
    const csv = ['fullName,externalId,email,credentialType,program,expiresAt', ...ids.map((id, i) => `Import Person ${i},${id},${id}@example.test,STUDENT_ID,Maths,`)].join('\n') + '\n';
    const boundary = `----t048${randomBytes(6).toString('hex')}`;
    const file = (name: string, filename: string, data: Buffer | string) =>
      Buffer.concat([Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"; filename="${filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`), Buffer.from(data), Buffer.from('\r\n')]);
    const payload = Buffer.concat([file('csv', 'p.csv', csv), file('photos', 'p.zip', makeZip(ids.map((id) => ({ name: `${id}.jpg`, data: JPEG() })))), Buffer.from(`--${boundary}--\r\n`)]);
    const headers = { ...a2.headers, 'content-type': `multipart/form-data; boundary=${boundary}` };
    expect((await app.inject({ method: 'POST', url: '/api/v1/credentials/import?dryRun=true', headers, payload })).statusCode).toBe(200);
    const intake = await app.inject({ method: 'POST', url: '/api/v1/credentials/import', headers, payload });
    expect(intake.statusCode).toBe(202);
    const batchId = intake.json().batchId as string;

    const post = (p: string, b: unknown) =>
      app.inject({ method: 'POST', url: `/api/v1/internal/import/batches/${p}`, headers: { ...json, authorization: `Bearer ${INTERNAL}` }, payload: JSON.stringify(b) });
    const send = async <T>(p: string, b: object): Promise<T> => {
      const r = await post(p, b);
      if (r.statusCode !== 200) throw new ImportApiError(r.statusCode);
      return JSON.parse(r.body) as T;
    };
    const api: ImportApi = {
      start: (j) => send(`${j.batchId}/start`, { institutionId: j.institutionId }),
      processRow: (j, row, b) => send(`${j.batchId}/rows/${row}`, { institutionId: j.institutionId, ...b }),
      finish: (j, outcome) => send(`${j.batchId}/finish`, { institutionId: j.institutionId, outcome }),
    };
    const wlog = (o: unknown, m?: string) => void workerLogs.push(JSON.stringify([o, m]));
    const deps: ImportBatchDeps = {
      api,
      storage: {
        get: async (key, max) => {
          const o = storage.objects.get(key);
          if (!o) return null;
          if (o.body.length > max) throw new Error('too large');
          return Buffer.from(o.body);
        },
        put: (key, body, ct) => storage.put(key, body, ct),
        delete: (key) => storage.delete(key),
      },
      logger: Object.fromEntries(['info', 'warn', 'error', 'debug', 'trace', 'fatal'].map((l) => [l, wlog])) as unknown as ImportBatchDeps['logger'],
    };
    const before = delivery.jobs.length;
    await expect(runImportBatch(deps, { institutionId: instId, batchId })).resolves.toBe('completed');
    const imported = delivery.jobs.slice(before);
    expect(imported).toHaveLength(5);
    for (const d of imported) add('holder token (import)', d.holderToken);
    const rows = (await ownerQuery(
      `SELECT c.verification_token, c.payload->>'salt' AS salt FROM import_rows r JOIN credentials c ON c.id = r.credential_id WHERE r.batch_id = $1`, [batchId])).rows as { verification_token: string; salt: string }[];
    expect(rows).toHaveLength(5);
    for (const r of rows) {
      add('verification token (import)', r.verification_token);
      add('salt (import)', r.salt);
    }
    // Fixed-code row errors and a refused internal call must not echo anything either.
    expect((await app.inject({ method: 'POST', url: `/api/v1/internal/import/batches/${batchId}/start`, headers: { ...json, authorization: 'Bearer wrong-wrong-wrong-wrong-wrong-wrong' }, payload: '{}' })).statusCode).toBe(401);

    // --- the scan. Non-vacuous: both sides logged real events, and the secret set is substantial.
    const api_ = apiLogs.join('');
    const wrk = workerLogs.join('');
    expect(api_).toContain('credential issued');
    expect(api_).toContain('institution created');
    expect(api_.length).toBeGreaterThan(2000);
    expect(wrk.length).toBeGreaterThan(0);
    expect(secrets.length).toBeGreaterThan(40);
    expect(scan(api_, secrets)).toEqual([]);
    expect(scan(wrk, secrets)).toEqual([]);
    // Personal data the import carries (names, addresses) stays out too.
    for (const pii of ['Import Person 0', 'imp-1@example.test', 'ada@example.test', 'admin@example.test']) {
      expect(api_).not.toContain(pii);
      expect(wrk).not.toContain(pii);
    }
  }, 120_000);
});
