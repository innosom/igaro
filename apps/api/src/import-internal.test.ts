// T-044 (ADR 0034): internal import endpoints and the real worker consumer (runImportBatch) driven against this API.
// Skipped when DATABASE_URL is unset. Runs as igaro_app (RLS on) in a scratch schema. Test values only.
import { createHash, randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { Writable } from 'node:stream';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import type { FastifyInstance } from 'fastify';
import { generateSigningKey, verifyCredentialIntegrity } from '@igaro/core';
import {
  runImportBatch,
  failImportBatch,
  type ImportApi,
  type ImportBatchDeps,
  ImportApiError,
} from '@igaro/worker';
import { buildApp } from './app.js';
import { csrfTokenFor, hashPassword } from './auth.js';
import { verifyAuditChain } from './audit.js';
import { Db } from './db.js';
import { stripMetadata } from './image.js';
import { MemoryCardRenderQueue, MemoryHolderDeliveryQueue, MemoryImportBatchQueue } from './notifications.js';
import { MemoryObjectStorage } from './storage.js';
import { JPEG, PNG } from './test-images.js';
import { makeZip } from './test-zip.js';

const url = process.env.DATABASE_URL;
const migrationsDir = new URL('../../../packages/db/prisma/migrations/', import.meta.url);

const INST_A = '11111111-1111-4111-8111-111111111111';
const INST_B = '22222222-2222-4222-8222-222222222222';
const U_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const U_B = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const H_A = 'a0000000-0000-4000-8000-000000000001';
const T_A = 'a1000000-0000-4000-8000-000000000001';
const PW = 'correct horse battery staple';
const TOKEN = randomBytes(32).toString('base64url');
const json = { 'content-type': 'application/json' };
const BIG = { ipMax: 100000, accountMax: 100000, windowSeconds: 900 };
const rateLimit = { login: BIG, reset: BIG, token: { ipMax: 100000, windowSeconds: 900 } };
const PHOTO_SHA = createHash('sha256').update('photo-a').digest('hex');
const sha = (b: Buffer | string) => createHash('sha256').update(b).digest('hex');

const EXIF_MARK = 'GPS-SECRET-EXIF';
const withExif = (): Buffer => {
  const data = Buffer.from(EXIF_MARK, 'latin1');
  const seg = Buffer.concat([Buffer.from([0xff, 0xe1, 0x00, 2 + data.length]), data]);
  return JPEG(seg);
};

interface Client {
  headers: Record<string, string>;
}
interface Part {
  name: string;
  filename?: string;
  data: Buffer | string;
}
const multipartBody = (parts: Part[]) => {
  const boundary = `----t044${randomBytes(6).toString('hex')}`;
  const bufs: Buffer[] = [];
  for (const p of parts) {
    bufs.push(
      Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${p.name}"` + (p.filename ? `; filename="${p.filename}"` : '') + `\r\nContent-Type: application/octet-stream\r\n\r\n`),
      Buffer.isBuffer(p.data) ? p.data : Buffer.from(p.data),
      Buffer.from('\r\n'),
    );
  }
  bufs.push(Buffer.from(`--${boundary}--\r\n`));
  return { payload: Buffer.concat(bufs), contentType: `multipart/form-data; boundary=${boundary}` };
};
const HEADER = 'fullName,externalId,email,credentialType,program,expiresAt';
const csvOf = (...rows: string[]) => [HEADER, ...rows].join('\n') + '\n';

describe.skipIf(!url)('internal import endpoints and worker consumer (needs Postgres)', () => {
  const schema = `t044_${randomBytes(4).toString('hex')}`;
  const master = randomBytes(32);
  let owner: pg.Client;
  let db: Db;
  let app: FastifyInstance;
  let noKeyApp: FastifyInstance;
  let noTokenApp: FastifyInstance;
  let a: Client;
  const logs: string[] = [];
  const storage = new MemoryObjectStorage();
  const queue = new MemoryImportBatchQueue();
  const cards = new MemoryCardRenderQueue();
  const delivery = new MemoryHolderDeliveryQueue();
  const body = (r: { body: string }) => JSON.parse(r.body) as Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

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

  const auth = { authorization: `Bearer ${TOKEN}` };
  const post = (u: string, payload: unknown, which: FastifyInstance = app, headers: Record<string, string> = auth) =>
    which.inject({ method: 'POST', url: `/api/v1/internal/import/batches/${u}`, headers: { ...json, ...headers }, payload: JSON.stringify(payload) });

  /** The real worker consumer talks to this API through inject, like HttpImportApi talks over HTTP. */
  const apiFor = (which: FastifyInstance = app): ImportApi => {
    const call = async <T>(path: string, payload: object): Promise<T> => {
      const r = await post(path, payload, which);
      if (r.statusCode !== 200) throw new ImportApiError(r.statusCode);
      return JSON.parse(r.body) as T;
    };
    return {
      start: (j) => call(`${j.batchId}/start`, { institutionId: j.institutionId }),
      processRow: (j, row, b) => call(`${j.batchId}/rows/${row}`, { institutionId: j.institutionId, ...b }),
      finish: (j, outcome) => call(`${j.batchId}/finish`, { institutionId: j.institutionId, outcome }),
    };
  };
  const workerStorage = {
    get: async (key: string, max: number) => {
      const o = storage.objects.get(key);
      if (!o) return null;
      if (o.body.length > max) throw new Error('too large');
      return Buffer.from(o.body);
    },
    put: (key: string, body: Buffer, ct: string) => storage.put(key, body, ct),
    delete: (key: string) => storage.delete(key),
  };
  const workerLogs: string[] = [];
  const deps = (which: FastifyInstance = app): ImportBatchDeps => ({
    api: apiFor(which),
    storage: workerStorage,
    // Minimal logger shape: pino-compatible methods writing to an array.
    logger: Object.fromEntries(['info', 'warn', 'error', 'debug'].map((l) => [l, (o: unknown, m?: string) => workerLogs.push(JSON.stringify([o, m]))])) as unknown as ImportBatchDeps['logger'],
  });

  const loginAs = async (email: string): Promise<Client> => {
    const res = await app.inject({ method: 'POST', url: '/api/v1/auth/login', headers: json, payload: { email, password: PW } });
    expect(res.statusCode).toBe(200);
    const cookie = String(res.headers['set-cookie']).split(';')[0]!;
    return { headers: { cookie, 'x-csrf-token': csrfTokenFor(cookie.slice(cookie.indexOf('=') + 1)) } };
  };
  const intake = async (csv: string, photos?: { name: string; data: Buffer }[], c: Client = a) => {
    const parts: Part[] = [{ name: 'csv', filename: 'people.csv', data: csv }];
    if (photos) parts.push({ name: 'photos', filename: 'p.zip', data: makeZip(photos) });
    const m = multipartBody(parts);
    const res = await app.inject({ method: 'POST', url: '/api/v1/credentials/import', headers: { ...c.headers, 'content-type': m.contentType }, payload: m.payload });
    expect(res.statusCode).toBe(202);
    return body(res).batchId as string;
  };
  const rowStates = async (batchId: string) =>
    (await ownerQuery(`SELECT row_number, status, error, credential_id FROM import_rows WHERE batch_id = $1 ORDER BY row_number`, [batchId])).rows as {
      row_number: number;
      status: string;
      error: string | null;
      credential_id: string | null;
    }[];
  const batchRow = async (batchId: string) => (await ownerQuery(`SELECT * FROM import_batches WHERE id = $1`, [batchId])).rows[0];
  const count = async (table: string) => Number((await ownerQuery(`SELECT count(*)::int AS n FROM ${table}`)).rows[0].n);

  beforeAll(async () => {
    owner = new pg.Client({ connectionString: url });
    await owner.connect();
    await owner.query(`CREATE SCHEMA "${schema}"`);
    await owner.query(`SET search_path TO "${schema}"`);
    const dirs = readdirSync(migrationsDir, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name).sort();
    for (const d of dirs) await owner.query(readFileSync(new URL(`${d}/migration.sql`, migrationsDir), 'utf8'));
    await owner.query(`GRANT USAGE ON SCHEMA "${schema}" TO igaro_app`);

    const pwHash = await hashPassword(PW);
    for (const [id, slug] of [[INST_A, 'inst-a'], [INST_B, 'inst-b']] as const) {
      await ownerQuery(`INSERT INTO institutions (id, name, slug, status, updated_at) VALUES ($1,$2,$3,'ACTIVE',now())`, [id, `Inst ${slug}`, slug]);
      const k = generateSigningKey(master);
      await ownerQuery(
        `INSERT INTO institution_keys (id, institution_id, kid, algorithm, public_key, encrypted_private_key, status)
         VALUES (gen_random_uuid(), $1, $2, 'Ed25519', $3, $4, 'ACTIVE')`,
        [id, k.kid, k.publicKey, k.encryptedPrivateKey],
      );
    }
    for (const [id, inst, email] of [[U_A, INST_A, 'a@example.test'], [U_B, INST_B, 'b@example.test']] as const) {
      await ownerQuery(
        `INSERT INTO users (id, institution_id, email, name, password_hash, role, status, updated_at) VALUES ($1,$2,$3,'Name',$4,'INSTITUTION_ADMIN','ACTIVE',now())`,
        [id, inst, email, pwHash],
      );
    }
    await ownerQuery(
      `INSERT INTO credential_types (id, institution_id, code, name, kind, attribute_schema, validity_days, updated_at)
       VALUES ($1, $2, 'STUDENT_ID', 'Student ID', 'ID_CARD', $3::jsonb, 365, now())`,
      [T_A, INST_A, JSON.stringify([{ key: 'program', label: 'Programme', type: 'string', required: true }])],
    );
    await ownerQuery(
      `INSERT INTO credential_holders (id, institution_id, full_name, external_id, photo_key, photo_sha256, updated_at) VALUES ($1,$2,'Ada Lovelace','ada-1',$3,$4,now())`,
      [H_A, INST_A, `institutions/${INST_A}/holders/${H_A}/photo/${PHOTO_SHA}.jpg`, PHOTO_SHA],
    );

    db = new Db({ connectionString: url!, max: 8, poolConfig: { options: `-c search_path=${schema} -c role=igaro_app` } });
    const logStream = new Writable({ write(c, _e, cb) { logs.push(String(c)); cb(); } });
    app = await buildApp({
      config: { logLevel: 'debug', rateLimit, masterKey: master, internalApiToken: TOKEN },
      db, storage, importBatch: queue, cardRender: cards, holderDelivery: delivery, logStream,
      importRateLimit: { max: 100000, windowSeconds: 3600 },
    });
    noKeyApp = await buildApp({ config: { logLevel: 'silent', rateLimit, internalApiToken: TOKEN }, db, storage });
    noTokenApp = await buildApp({ config: { logLevel: 'silent', rateLimit, masterKey: master }, db, storage });
    a = await loginAs('a@example.test');
  });

  afterAll(async () => {
    await app?.close();
    await noKeyApp?.close();
    await noTokenApp?.close();
    await db?.close();
    if (!owner) return;
    await owner.query('ROLLBACK').catch(() => undefined);
    await owner.query('RESET search_path');
    await owner.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    await owner.end();
  });

  it('refuses a missing or wrong token on every endpoint and registers nothing without a configured token', async () => {
    const id = '99999999-9999-4999-8999-999999999999';
    for (const headers of [{} as Record<string, string>, { authorization: 'Bearer nope' }, { authorization: `Basic ${TOKEN}` }, { authorization: `Bearer ${TOKEN}x` }]) {
      for (const [p, payload] of [[`${id}/start`, { institutionId: INST_A }], [`${id}/rows/1`, { institutionId: INST_A }], [`${id}/finish`, { institutionId: INST_A, outcome: 'complete' }]] as const) {
        const r = await post(p, payload, app, headers);
        expect(r.statusCode).toBe(401);
      }
    }
    expect((await post(`${id}/start`, { institutionId: INST_A }, noTokenApp)).statusCode).toBe(404);
    // A browser session is not a service credential.
    expect((await post(`${id}/start`, { institutionId: INST_A }, app, { ...a.headers })).statusCode).toBe(401);
  });

  it('end to end: the real worker consumer imports rows, tolerates a failing row, and is idempotent', async () => {
    const batchId = await intake(
      csvOf(
        'Grace Hopper,g-1,grace@example.test,STUDENT_ID,Maths,',
        'Alan Turing,g-2,,STUDENT_ID,Logic,2099-01-01T00:00:00Z',
        'Ada Lovelace,ada-1,ada@example.test,STUDENT_ID,Analysis,',
        'Edsger Dijkstra,g-4,edsger@example.test,STUDENT_ID,Algorithms,',
        'Barbara Liskov,g-5,,STUDENT_ID,Types,',
      ),
      [
        { name: 'g-1.jpg', data: withExif() },
        { name: 'g-2.JPEG', data: JPEG() },
        { name: 'g-4.jpg', data: JPEG() },
        { name: 'g-5.jpg', data: JPEG() },
        { name: 'extra-unreferenced.jpg', data: JPEG() },
      ],
    );
    // Drift after intake: g-4's type vanishes (row problem), g-5's name now collides with an existing holder under another name.
    await ownerQuery(`INSERT INTO credential_holders (id, institution_id, full_name, external_id, updated_at) VALUES (gen_random_uuid(), $1, 'Someone Else', 'g-5', now())`, [INST_A]);
    await ownerQuery(`UPDATE import_rows SET data = jsonb_set(data, '{credentialType}', '"GONE"') WHERE batch_id = $1 AND row_number = 4`, [batchId]);

    const before = { creds: await count('credentials'), holders: await count('credential_holders') };
    const cardsBefore = cards.jobs.length;
    const deliveryBefore = delivery.jobs.length;
    const job = { institutionId: INST_A, batchId };
    await expect(runImportBatch(deps(), job)).resolves.toBe('completed');

    const rows = await rowStates(batchId);
    expect(rows.map((r) => r.status)).toEqual(['IMPORTED', 'IMPORTED', 'IMPORTED', 'ERROR', 'ERROR']);
    expect(rows[3]!.error).toBe('CREDENTIAL_TYPE_NOT_FOUND');
    expect(rows[4]!.error).toBe('HOLDER_NAME_MISMATCH');
    expect(rows[3]!.credential_id).toBeNull();
    const batch = await batchRow(batchId);
    expect(batch).toMatchObject({ status: 'COMPLETED', imported_rows: 3, error_rows: 2 });
    expect(batch.completed_at).not.toBeNull();

    // Exactly the three good credentials and two new holders (g-1, g-2); the failed rows rolled back completely.
    expect(await count('credentials')).toBe(before.creds + 3);
    expect(await count('credential_holders')).toBe(before.holders + 2);
    const g4 = await ownerQuery(`SELECT 1 FROM credential_holders WHERE external_id = 'g-4'`);
    expect(g4.rowCount).toBe(0);

    // Photo: metadata stripped, hash of the stored bytes is what the signed payload commits to.
    const g1 = (await ownerQuery(`SELECT h.id, h.photo_key, h.photo_sha256, h.email, c.payload, c.data_hash, c.signature, c.status, k.public_key
                                    FROM credential_holders h JOIN credentials c ON c.holder_id = h.id JOIN institution_keys k ON k.kid = c.issuer_kid
                                   WHERE h.external_id = 'g-1'`)).rows[0];
    const stored = storage.objects.get(g1.photo_key)!.body;
    expect(stored.includes(Buffer.from(EXIF_MARK))).toBe(false);
    expect(sha(stored)).toBe(g1.photo_sha256);
    expect(g1.photo_key).toBe(`institutions/${INST_A}/holders/${g1.id}/photo/${g1.photo_sha256}.jpg`);
    expect(g1.payload.holder.photoSha256).toBe(g1.photo_sha256);
    expect(g1.status).toBe('ACTIVE');
    expect(verifyCredentialIntegrity(g1.payload, g1.data_hash, g1.signature, g1.public_key)).toBe('OK');

    // Existing holder reused (no new holder, photo kept); email filled in only where the holder had none.
    const ada = (await ownerQuery(`SELECT id, photo_sha256, email FROM credential_holders WHERE external_id = 'ada-1'`)).rows;
    expect(ada).toHaveLength(1);
    expect(ada[0]).toMatchObject({ id: H_A, photo_sha256: PHOTO_SHA, email: 'ada@example.test' });
    const adaCred = (await ownerQuery(`SELECT payload FROM credentials WHERE holder_id = $1`, [H_A])).rows[0];
    expect(adaCred.payload.holder.photoSha256).toBe(PHOTO_SHA);

    // Explicit expiry honoured; default validity otherwise.
    const g2 = (await ownerQuery(`SELECT payload FROM credentials c JOIN credential_holders h ON h.id = c.holder_id WHERE h.external_id = 'g-2'`)).rows[0];
    expect(g2.payload.expiresAt).toBe('2099-01-01T00:00:00Z');

    // After commit: card renders for all three, holder emails only for holders with an address (ADR 0030 path).
    expect(cards.jobs.length - cardsBefore).toBe(3);
    const newDelivery = delivery.jobs.slice(deliveryBefore);
    expect(newDelivery.map((d) => d.to).sort()).toEqual(['ada@example.test', 'grace@example.test']);
    expect(newDelivery.every((d) => d.institutionId === INST_A && d.holderToken.length >= 20)).toBe(true);

    // Audit: issuance entries identical to single issuance, plus the batch completion; chain intact.
    const au = await ownerQuery(`SELECT action, count(*)::int AS n FROM audit_logs WHERE institution_id = $1 GROUP BY action`, [INST_A]);
    const byAction = Object.fromEntries(au.rows.map((r) => [r.action, r.n]));
    expect(byAction['credential.issued']).toBeGreaterThanOrEqual(3);
    expect(byAction['import.completed']).toBe(1);
    const chain = await db.withTenant({ kind: 'tenant', userId: U_A, institutionId: INST_A }, (c) => verifyAuditChain(c, INST_A));
    expect(chain.ok).toBe(true);

    // Sources removed; status endpoint shows the per-row results.
    const keys = [`institutions/${INST_A}/imports/${batchId}/source.csv`, `institutions/${INST_A}/imports/${batchId}/photos.zip`];
    expect(keys.some((k) => storage.objects.has(k))).toBe(false);
    const st = body(await app.inject({ method: 'GET', url: `/api/v1/credentials/import/${batchId}`, headers: a.headers }));
    expect(st).toMatchObject({ status: 'COMPLETED', importedRows: 3, errorRows: 2, pendingRows: 0 });
    expect(st.errors).toEqual([{ row: 4, error: 'CREDENTIAL_TYPE_NOT_FOUND' }, { row: 5, error: 'HOLDER_NAME_MISMATCH' }]);

    // Idempotent: running the job again, or hitting a finished row, changes nothing and queues nothing.
    const credsAfter = await count('credentials');
    await expect(runImportBatch(deps(), job)).resolves.toBe('skipped_finished');
    const again = await post(`${batchId}/rows/1`, { institutionId: INST_A });
    expect([again.statusCode, body(again).outcome]).toEqual([200, 'IMPORTED']); // finished row: answered from its state
    expect(await count('credentials')).toBe(credsAfter);
    expect(cards.jobs.length - cardsBefore).toBe(3);
    expect(delivery.jobs.length - deliveryBefore).toBe(2);

    // Nothing secret reached either log: names, addresses, tokens, the photo's metadata.
    const all = logs.join('') + workerLogs.join('');
    for (const secret of ['Grace Hopper', 'grace@example.test', 'ada@example.test', EXIF_MARK, TOKEN, ...newDelivery.map((d) => d.holderToken)]) {
      expect(all).not.toContain(secret);
    }
  });

  it('tolerates and records worker-side photo failures (PNG renamed, missing entry) while good rows go through', async () => {
    const batchId = await intake(
      csvOf('Ok One,p-1,,STUDENT_ID,Maths,', 'Ok Two,p-2,,STUDENT_ID,Maths,'),
      [{ name: 'p-1.jpg', data: JPEG() }, { name: 'p-2.jpg', data: JPEG() }],
    );
    // The archive in storage is swapped for hostile content AFTER intake validated it: the worker must catch it.
    const keys = { zip: `institutions/${INST_A}/imports/${batchId}/photos.zip` };
    const hostile = makeZip([{ name: 'p-1.jpg', data: PNG() }, { name: 'p-2.jpg', data: JPEG() }]);
    storage.objects.set(keys.zip, { body: hostile, contentType: 'application/zip' });
    await runImportBatch(deps(), { institutionId: INST_A, batchId });
    // The tampered archive no longer matches the hash recorded at intake: every zip row fails, none is issued.
    expect((await rowStates(batchId)).map((r) => [r.status, r.error])).toEqual([['ERROR', 'PHOTO_SOURCE_MISMATCH'], ['ERROR', 'PHOTO_SOURCE_MISMATCH']]);
    expect(await batchRow(batchId)).toMatchObject({ status: 'COMPLETED', imported_rows: 0, error_rows: 2 });
    expect((await ownerQuery(`SELECT 1 FROM credential_holders WHERE external_id IN ('p-1','p-2')`)).rowCount).toBe(0);
  });

  it('internal row endpoint validates its body and never trusts the photo it is sent', async () => {
    const batchId = await intake(csvOf('Val One,v-1,,STUDENT_ID,Maths,'), [{ name: 'v-1.jpg', data: JPEG() }]);
    expect((await post(`${batchId}/start`, { institutionId: INST_A })).statusCode).toBe(200);
    const good = stripMetadata(JPEG(), 'image/jpeg')!; // what the worker sends: already stripped
    const photo = (b: Buffer, sum = sha(b)) => ({ sha256: sum, data: b.toString('base64') });
    const cases: [string, unknown][] = [
      ['unknown property', { institutionId: INST_A, extra: 1 }],
      ['no institution', {}],
      ['non-whitelisted failure code', { institutionId: INST_A, fail: 'PWNED' }],
      ['fail and photo', { institutionId: INST_A, fail: 'PHOTO_INVALID', photo: photo(good) }],
      ['hash mismatch', { institutionId: INST_A, photo: photo(good, 'a'.repeat(64)) }],
      ['png', { institutionId: INST_A, photo: photo(PNG()) }],
      ['unstripped metadata', { institutionId: INST_A, photo: photo(withExif()) }],
      ['trailing bytes', { institutionId: INST_A, photo: photo(Buffer.concat([good, Buffer.from('tail')])) }],
      ['extra photo key', { institutionId: INST_A, photo: { ...photo(good), more: 1 } }],
    ];
    for (const [name, payload] of cases) {
      const r = await post(`${batchId}/rows/1`, payload);
      expect([name, r.statusCode]).toEqual([name, 400]);
    }
    expect((await post(`${batchId}/rows/0`, { institutionId: INST_A })).statusCode).toBe(404);
    expect((await post(`${batchId}/rows/1`, { institutionId: 'not-a-uuid' })).statusCode).toBe(400);
    expect((await rowStates(batchId))[0]!.status).toBe('PENDING');
    expect((await ownerQuery(`SELECT 1 FROM credential_holders WHERE external_id = 'v-1'`)).rowCount).toBe(0);

    // A valid call works, and finish refuses to complete a batch that still has pending rows.
    expect((await post(`${batchId}/finish`, { institutionId: INST_A, outcome: 'complete' })).statusCode).toBe(409);
    const ok = await post(`${batchId}/rows/1`, { institutionId: INST_A, photo: photo(good) });
    expect([ok.statusCode, body(ok).outcome]).toEqual([200, 'IMPORTED']);
    expect((await post(`${batchId}/finish`, { institutionId: INST_A, outcome: 'complete' })).statusCode).toBe(200);
    // finish is idempotent
    expect(body(await post(`${batchId}/finish`, { institutionId: INST_A, outcome: 'failed' })).status).toBe('COMPLETED');
  });

  it('a row is refused while the batch is not PROCESSING', async () => {
    const batchId = await intake(csvOf('Wait One,w-1,,STUDENT_ID,Maths,'), [{ name: 'w-1.jpg', data: JPEG() }]);
    const r = await post(`${batchId}/rows/1`, { institutionId: INST_A, fail: 'PHOTO_INVALID' });
    expect(r.statusCode).toBe(409);
    expect((await rowStates(batchId))[0]!.status).toBe('PENDING');
  });

  it('is tenant-scoped: another institution id gets 404 for every call and nothing changes', async () => {
    const batchId = await intake(csvOf('Tenant One,x-1,,STUDENT_ID,Maths,'), [{ name: 'x-1.jpg', data: JPEG() }]);
    const before = await batchRow(batchId);
    for (const [p, payload] of [
      [`${batchId}/start`, { institutionId: INST_B }],
      [`${batchId}/rows/1`, { institutionId: INST_B, fail: 'PHOTO_INVALID' }],
      [`${batchId}/finish`, { institutionId: INST_B, outcome: 'failed' }],
    ] as const) {
      expect((await post(p, payload)).statusCode).toBe(404);
    }
    expect(await batchRow(batchId)).toEqual(before);
    expect((await rowStates(batchId))[0]!.status).toBe('PENDING');
    expect((await post('not-a-uuid/start', { institutionId: INST_A })).statusCode).toBe(404);
  });

  it('a signing outage is transient: the row stays PENDING and succeeds on retry', async () => {
    const batchId = await intake(csvOf('Retry One,r-1,,STUDENT_ID,Maths,'), [{ name: 'r-1.jpg', data: JPEG() }]);
    const job = { institutionId: INST_A, batchId };
    // An API instance without the master key cannot sign: 503, nothing is written, the worker pass throws.
    await expect(runImportBatch(deps(noKeyApp), job)).rejects.toThrow('must be retried');
    expect((await rowStates(batchId))[0]).toMatchObject({ status: 'PENDING', error: null });
    expect(await batchRow(batchId)).toMatchObject({ status: 'PROCESSING' });
    expect((await ownerQuery(`SELECT 1 FROM credential_holders WHERE external_id = 'r-1'`)).rowCount).toBe(0);
    // Back to a healthy API: the retry completes.
    await expect(runImportBatch(deps(), job)).resolves.toBe('completed');
    expect((await rowStates(batchId))[0]!.status).toBe('IMPORTED');
  });

  it('after the last retry the batch is marked FAILED, rows left PENDING, sources deleted', async () => {
    const batchId = await intake(csvOf('Fail One,f-1,,STUDENT_ID,Maths,'), [{ name: 'f-1.jpg', data: JPEG() }]);
    const job = { institutionId: INST_A, batchId };
    await expect(runImportBatch(deps(noKeyApp), job)).rejects.toThrow();
    await failImportBatch(deps(), job);
    expect(await batchRow(batchId)).toMatchObject({ status: 'FAILED', imported_rows: 0, error_rows: 0 });
    expect((await rowStates(batchId))[0]!.status).toBe('PENDING');
    expect(storage.objects.has(`institutions/${INST_A}/imports/${batchId}/photos.zip`)).toBe(false);
    const au = await ownerQuery(`SELECT 1 FROM audit_logs WHERE action = 'import.failed' AND target_id = $1`, [batchId]);
    expect(au.rowCount).toBe(1);
  });

  it('imports 500 holders with photos and an email each', async () => {
    const n = 500;
    const ids = Array.from({ length: n }, (_, i) => `bulk-${String(i).padStart(4, '0')}`);
    const csv = csvOf(...ids.map((id, i) => `Bulk Person ${i},${id},${id}@example.test,STUDENT_ID,Programme ${i % 7},`));
    const batchId = await intake(csv, ids.map((id) => ({ name: `${id}.jpg`, data: withExif() })));
    const deliveryBefore = delivery.jobs.length;
    const cardsBefore = cards.jobs.length;
    const credsBefore = await count('credentials');
    const t0 = Date.now();
    await expect(runImportBatch(deps(), { institutionId: INST_A, batchId })).resolves.toBe('completed');
    const seconds = (Date.now() - t0) / 1000;

    expect(await batchRow(batchId)).toMatchObject({ status: 'COMPLETED', total_rows: n, imported_rows: n, error_rows: 0 });
    expect(await count('credentials')).toBe(credsBefore + n);
    expect(delivery.jobs.length - deliveryBefore).toBe(n);
    expect(cards.jobs.length - cardsBefore).toBe(n);
    const recipients = new Set(delivery.jobs.slice(deliveryBefore).map((d) => d.to));
    expect(recipients.size).toBe(n);
    const tokens = new Set(delivery.jobs.slice(deliveryBefore).map((d) => d.holderToken));
    expect(tokens.size).toBe(n); // one distinct private link per holder

    // Every credential verifies and commits to the stripped photo that is stored.
    const rows = (await ownerQuery(
      `SELECT c.payload, c.data_hash, c.signature, k.public_key, h.photo_key, h.photo_sha256
         FROM import_rows r JOIN credentials c ON c.id = r.credential_id
         JOIN credential_holders h ON h.id = c.holder_id JOIN institution_keys k ON k.kid = c.issuer_kid
        WHERE r.batch_id = $1`, [batchId])).rows;
    expect(rows).toHaveLength(n);
    for (const r of rows) {
      expect(verifyCredentialIntegrity(r.payload, r.data_hash, r.signature, r.public_key)).toBe('OK');
      const bytes = storage.objects.get(r.photo_key)!.body;
      expect(sha(bytes)).toBe(r.photo_sha256);
      expect(r.payload.holder.photoSha256).toBe(r.photo_sha256);
      expect(bytes.includes(Buffer.from(EXIF_MARK))).toBe(false);
    }
    const chain = await db.withTenant({ kind: 'tenant', userId: U_A, institutionId: INST_A }, (c) => verifyAuditChain(c, INST_A));
    expect(chain.ok).toBe(true);
    // Informational: wall-clock for the whole import through the API (signing, DB, audit chain per row).
    console.log(`500-holder import took ${seconds.toFixed(1)}s`);
  }, 600_000);
});
