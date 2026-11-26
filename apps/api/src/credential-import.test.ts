// T-043 (ADR 0033): POST /credentials/import and GET /credentials/import/:id.
// Skipped when DATABASE_URL is unset. Runs as igaro_app (RLS on) in a scratch schema. Test values only.
import { createHash, randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { Writable } from 'node:stream';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import type { FastifyInstance } from 'fastify';
import { generateSigningKey } from '@igaro/core';
import { importStorageKeys, parseImportBatchJobData } from '@igaro/worker/producer';
import { buildApp } from './app.js';
import { csrfTokenFor, hashPassword } from './auth.js';
import { Db } from './db.js';
import { MemoryImportBatchQueue } from './notifications.js';
import { MemoryObjectStorage } from './storage.js';
import { JPEG, PNG } from './test-images.js';
import { makeZip } from './test-zip.js';

const url = process.env.DATABASE_URL;
const migrationsDir = new URL('../../../packages/db/prisma/migrations/', import.meta.url);

const INST_A = '11111111-1111-4111-8111-111111111111';
const INST_B = '22222222-2222-4222-8222-222222222222';
const INST_S = '33333333-3333-4333-8333-333333333333';
const U_PA = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const U_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const U_B = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const U_S = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const H_A = 'a0000000-0000-4000-8000-000000000001';
const T_A = 'a1000000-0000-4000-8000-000000000001';
const MISSING = '99999999-9999-4999-8999-999999999999';
const PW = 'correct horse battery staple';
const json = { 'content-type': 'application/json' };
const BIG = { ipMax: 10000, accountMax: 10000, windowSeconds: 900 };
const rateLimit = { login: BIG, reset: BIG, token: { ipMax: 10000, windowSeconds: 900 } };
const PHOTO_SHA = createHash('sha256').update('photo-a').digest('hex');
const SECRET_NAME = 'Zed Quuxington';

interface Client {
  headers: Record<string, string>;
}
interface Part {
  name: string;
  filename?: string;
  data: Buffer | string;
}

const multipartBody = (parts: Part[]) => {
  const boundary = `----t043${randomBytes(6).toString('hex')}`;
  const bufs: Buffer[] = [];
  for (const p of parts) {
    bufs.push(
      Buffer.from(
        `--${boundary}\r\nContent-Disposition: form-data; name="${p.name}"` +
          (p.filename ? `; filename="${p.filename}"` : '') +
          `\r\nContent-Type: application/octet-stream\r\n\r\n`,
      ),
      Buffer.isBuffer(p.data) ? p.data : Buffer.from(p.data),
      Buffer.from('\r\n'),
    );
  }
  bufs.push(Buffer.from(`--${boundary}--\r\n`));
  return { payload: Buffer.concat(bufs), contentType: `multipart/form-data; boundary=${boundary}` };
};

const HEADER = 'fullName,externalId,email,credentialType,program,expiresAt';
const csvOf = (...rows: string[]) => [HEADER, ...rows].join('\n') + '\n';

describe.skipIf(!url)('credential import (needs Postgres)', () => {
  const schema = `t043_${randomBytes(4).toString('hex')}`;
  const master = randomBytes(32);
  let owner: pg.Client;
  let db: Db;
  let app: FastifyInstance;
  let a: Client;
  let b: Client;
  let pa: Client;
  let sus: Client;
  const logs: string[] = [];
  const storage = new MemoryObjectStorage();
  const queue = new MemoryImportBatchQueue();

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
  const counts = async () => {
    const r = await ownerQuery(
      `SELECT (SELECT count(*) FROM import_batches)::int AS b, (SELECT count(*) FROM import_rows)::int AS r,
              (SELECT count(*) FROM audit_logs)::int AS al, (SELECT count(*) FROM credentials)::int AS c,
              (SELECT count(*) FROM credential_holders)::int AS h`,
    );
    const row = r.rows[0] as { b: number; r: number; al: number; c: number; h: number };
    return { ...row, objects: storage.objects.size, jobs: queue.jobs.length };
  };
  const loginAs = async (which: FastifyInstance, email: string): Promise<Client> => {
    const res = await which.inject({ method: 'POST', url: '/api/v1/auth/login', headers: json, payload: { email, password: PW } });
    expect(res.statusCode).toBe(200);
    const cookie = String(res.headers['set-cookie']).split(';')[0]!;
    return { headers: { cookie, 'x-csrf-token': csrfTokenFor(cookie.slice(cookie.indexOf('=') + 1)) } };
  };
  const send = (c: Client | null, parts: Part[], query = '', which: FastifyInstance = app) => {
    const m = multipartBody(parts);
    return which.inject({
      method: 'POST',
      url: `/api/v1/credentials/import${query}`,
      headers: { ...(c?.headers ?? {}), 'content-type': m.contentType },
      payload: m.payload,
    });
  };
  const csvPart = (text: string): Part => ({ name: 'csv', filename: 'people.csv', data: text });
  const zipPart = (...entries: { name: string; data: Buffer }[]): Part => ({ name: 'photos', filename: 'p.zip', data: makeZip(entries) });
  const body = (r: { body: string }) => JSON.parse(r.body) as Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

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
    for (const [id, slug, status] of [[INST_A, 'inst-a', 'ACTIVE'], [INST_B, 'inst-b', 'ACTIVE'], [INST_S, 'inst-s', 'SUSPENDED']] as const) {
      await ownerQuery(`INSERT INTO institutions (id, name, slug, status, updated_at) VALUES ($1,$2,$3,$4,now())`, [id, `Inst ${slug}`, slug, status]);
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
      [U_S, INST_S, 's@example.test', 'INSTITUTION_ADMIN'],
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
      [H_A, INST_A, `institutions/${INST_A}/holders/${H_A}/photo/${PHOTO_SHA}.jpg`, PHOTO_SHA],
    );

    db = new Db({ connectionString: url!, max: 8, poolConfig: { options: `-c search_path=${schema} -c role=igaro_app` } });
    const logStream = new Writable({
      write(c, _e, cb) {
        logs.push(String(c));
        cb();
      },
    });
    app = await buildApp({
      config: { logLevel: 'debug', rateLimit, masterKey: master },
      db,
      storage,
      importBatch: queue,
      importLimits: { maxRows: 5, maxZipEntries: 4, maxPhotoBytes: 5000, maxZipUncompressedBytes: 8000, maxCsvBytes: 4000 },
      logStream,
    });
    pa = await loginAs(app, 'pa@example.test');
    a = await loginAs(app, 'a@example.test');
    b = await loginAs(app, 'b@example.test');
    sus = await loginAs(app, 's@example.test');
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

  const good = (id: string, name = 'Grace Hopper') => `${name},${id},${id}@example.test,STUDENT_ID,Maths,`;

  it('dry run lists errors per row, echoes no cell content, and writes nothing', async () => {
    const before = await counts();
    const csv = csvOf(
      good('g-1'),
      `${SECRET_NAME},g-2,not-an-email,STUDENT_ID,Maths,`, // bad email
      `Bob,g-3,,NOPE,Maths,`, // unknown type
      `Cy,g-1,,STUDENT_ID,Maths,`, // duplicate externalId
      `Di,g-4,,STUDENT_ID,,`, // missing required attribute
      `"=HYPERLINK(""x"")",g-5,,STUDENT_ID,Maths,`, // formula
      `Ed,g-6,,STUDENT_ID,Maths,2020-01-01T00:00:00Z`, // expiry in the past (row 6 is >maxRows? no: 6 rows)
    );
    const res = await send(a, [csvPart(csv)], '?dryRun=true');
    expect(res.statusCode).toBe(413); // 7 rows > maxRows 5 in this app: the limit applies to dry runs too
    expect(body(res).error.code).toBe('CSV_TOO_MANY_ROWS');

    const csv5 = csvOf(
      good('g-1'),
      `${SECRET_NAME},g-2,not-an-email,STUDENT_ID,Maths,`,
      `Bob,g-3,,NOPE,Maths,`,
      `Cy,g-1,,STUDENT_ID,Maths,`,
      `"=HYPERLINK(""x"")",g-5,,STUDENT_ID,Maths,`,
    );
    const r2 = await send(a, [csvPart(csv5), zipPart(...['g-1', 'g-2', 'g-3', 'g-5'].map((n) => ({ name: `${n}.jpg`, data: JPEG() })))], '?dryRun=true');
    expect(r2.statusCode).toBe(200);
    const p = body(r2);
    expect(p).toMatchObject({ dryRun: true, totalRows: 5, validRows: 1, errorRows: 4 });
    const codes = (n: number) => (p.rows[n - 1].errors as { code: string }[]).map((e) => e.code);
    expect(p.rows[0]).toMatchObject({ row: 1, ok: true });
    expect(codes(2)).toEqual(['INVALID_EMAIL']);
    expect(codes(3)).toContain('UNKNOWN_CREDENTIAL_TYPE');
    expect(codes(4)).toContain('DUPLICATE_EXTERNAL_ID');
    expect(codes(5)).toContain('FORMULA_PREFIX');
    expect(r2.body).not.toContain(SECRET_NAME);
    expect(r2.body).not.toContain('HYPERLINK');
    expect(logs.join('')).not.toContain(SECRET_NAME);
    expect(await counts()).toEqual(before);
  });

  it('reports a missing photo, an invalid photo, a name mismatch and reuses an existing holder with a photo', async () => {
    const csv = csvOf(
      'Ada Lovelace,ada-1,,STUDENT_ID,Maths,', // existing holder, has photo, no zip entry: ok
      'Someone Else,ada-1x,,STUDENT_ID,Maths,', // no photo anywhere
      'Not Ada,ada-1,,STUDENT_ID,Maths,', // duplicate (and mismatch)
      'Pic Bad,pic-1,,STUDENT_ID,Maths,', // zip entry is a PNG renamed .jpg
    );
    const res = await send(a, [csvPart(csv), zipPart({ name: 'pic-1.jpg', data: PNG() })], '?dryRun=true');
    const p = body(res);
    expect(res.statusCode).toBe(200);
    expect(p.rows[0]).toMatchObject({ ok: true, holderExists: true });
    expect(p.rows[1].errors.map((e: { code: string }) => e.code)).toEqual(['PHOTO_REQUIRED']);
    expect(p.rows[2].errors.map((e: { code: string }) => e.code)).toContain('HOLDER_NAME_MISMATCH');
    expect(p.rows[3].errors.map((e: { code: string }) => e.code)).toEqual(['PHOTO_INVALID']);
    expect(p.photos).toEqual({ provided: 1, matched: 1, unmatched: 0 });
  });

  it('non-dry run with invalid rows is refused with 422 and writes nothing', async () => {
    const before = await counts();
    const res = await send(a, [csvPart(csvOf(good('v-1'), 'Bad,v-2,,NOPE,Maths,')), zipPart({ name: 'v-1.jpg', data: JPEG() }, { name: 'v-2.jpg', data: JPEG() })]);
    expect(res.statusCode).toBe(422);
    expect(body(res).error.code).toBe('IMPORT_VALIDATION_FAILED');
    expect(body(res).preview.errorRows).toBe(1);
    expect(await counts()).toEqual(before);
  });

  it('happy path: 202, batch + rows, sources stored under the institution, audit entry, ids-only job, status endpoint', async () => {
    const before = await counts();
    const csv = csvOf(good('h-1', 'Grace Hopper'), good('h-2', 'Alan Turing'), 'Ada Lovelace,ada-1,,STUDENT_ID,Maths,');
    const res = await send(a, [csvPart(csv), zipPart({ name: 'h-1.jpg', data: JPEG() }, { name: 'h-2.JPEG', data: JPEG() })]);
    expect(res.statusCode).toBe(202);
    const out = body(res);
    expect(out).toMatchObject({ status: 'PENDING', totalRows: 3 });
    const batchId = out.batchId as string;

    // Batch and rows
    const bt = await ownerQuery(`SELECT * FROM import_batches WHERE id = $1`, [batchId]);
    expect(bt.rows[0]).toMatchObject({ institution_id: INST_A, created_by: U_A, status: 'PENDING', total_rows: 3, filename: 'people.csv' });
    const keys = importStorageKeys(INST_A, batchId);
    expect(bt.rows[0].source_key).toBe(keys.csv);
    const rows = await ownerQuery(`SELECT row_number, status, data FROM import_rows WHERE batch_id = $1 ORDER BY row_number`, [batchId]);
    expect(rows.rows.map((r) => r.status)).toEqual(['PENDING', 'PENDING', 'PENDING']);
    expect(rows.rows[0].data).toEqual({
      fullName: 'Grace Hopper', externalId: 'h-1', email: 'h-1@example.test', credentialType: 'STUDENT_ID', attributes: { program: 'Maths' }, photo: 'zip',
    });
    expect(rows.rows[2].data.photo).toBe('holder');

    // Sources stored privately under the institution
    expect(storage.objects.get(keys.csv)?.body.toString()).toBe(csv);
    expect(storage.objects.has(keys.photos)).toBe(true);

    // Job: ids only
    const job = queue.jobs[queue.jobs.length - 1]!;
    expect(job).toEqual({ institutionId: INST_A, batchId });
    expect(parseImportBatchJobData(job)).toEqual(job);

    // Audit: counts and hashes, no PII; no holder/credential created by intake
    const au = await ownerQuery(`SELECT metadata, action, target_id FROM audit_logs WHERE institution_id = $1 AND action = 'import.created'`, [INST_A]);
    expect(au.rows).toHaveLength(1);
    expect(au.rows[0].target_id).toBe(batchId);
    expect(JSON.stringify(au.rows[0].metadata)).not.toContain('Grace');
    expect(au.rows[0].metadata.totalRows).toBe(3);
    const after = await counts();
    expect(after.c).toBe(before.c);
    expect(after.h).toBe(before.h);
    expect(after.b).toBe(before.b + 1);
    expect(after.r).toBe(before.r + 3);

    // Status endpoint
    const st = await app.inject({ method: 'GET', url: `/api/v1/credentials/import/${batchId}`, headers: a.headers });
    expect(st.statusCode).toBe(200);
    expect(body(st)).toMatchObject({ id: batchId, status: 'PENDING', totalRows: 3, importedRows: 0, errorRows: 0, pendingRows: 3, errors: [] });
    expect(logs.join('')).not.toContain('Grace Hopper');
  });

  it('cross-tenant, unknown and malformed batch ids are 404; other tenant cannot see the batch', async () => {
    const r = await ownerQuery(`SELECT id FROM import_batches WHERE institution_id = $1 LIMIT 1`, [INST_A]);
    const id = r.rows[0].id as string;
    for (const target of [id, MISSING, 'not-a-uuid']) {
      const res = await app.inject({ method: 'GET', url: `/api/v1/credentials/import/${target}`, headers: b.headers });
      expect(res.statusCode).toBe(404);
    }
    expect((await app.inject({ method: 'GET', url: `/api/v1/credentials/import/${id}`, headers: a.headers })).statusCode).toBe(200);
  });

  it('worker-written row errors are surfaced in the status endpoint', async () => {
    const r = await ownerQuery(`SELECT id FROM import_batches WHERE institution_id = $1 LIMIT 1`, [INST_A]);
    const id = r.rows[0].id as string;
    await ownerQuery(`UPDATE import_rows SET status='ERROR', error='PHOTO_INVALID' WHERE batch_id = $1 AND row_number = 2`, [id]);
    await ownerQuery(`UPDATE import_batches SET error_rows = 1 WHERE id = $1`, [id]);
    const st = body(await app.inject({ method: 'GET', url: `/api/v1/credentials/import/${id}`, headers: a.headers }));
    expect(st.errors).toEqual([{ row: 2, error: 'PHOTO_INVALID' }]);
    expect(st.pendingRows).toBe(2);
  });

  it('refuses non-admins and anonymous callers, before reading anything', async () => {
    const before = await counts();
    expect((await send(pa, [csvPart(csvOf(good('x-1')))])).statusCode).toBe(403);
    expect((await send(null, [csvPart(csvOf(good('x-1')))])).statusCode).toBe(401);
    expect((await app.inject({ method: 'GET', url: `/api/v1/credentials/import/${MISSING}`, headers: pa.headers })).statusCode).toBe(403);
    expect(await counts()).toEqual(before);
  });

  it('rejects zip path traversal, nested names, non-jpeg names and zip bombs', async () => {
    const before = await counts();
    const csv = csvPart(csvOf(good('z-1')));
    const trav = await send(a, [csv, zipPart({ name: '../z-1.jpg', data: JPEG() })], '?dryRun=true');
    expect([trav.statusCode, body(trav).error.code]).toEqual([400, 'ZIP_BAD_ENTRY_NAME']);
    const nested = await send(a, [csv, zipPart({ name: 'dir/z-1.jpg', data: JPEG() })], '?dryRun=true');
    expect(body(nested).error.code).toBe('ZIP_BAD_ENTRY_NAME');
    const png = await send(a, [csv, zipPart({ name: 'z-1.png', data: PNG() })], '?dryRun=true');
    expect(body(png).error.code).toBe('ZIP_ENTRY_NOT_JPEG');
    const big = await send(a, [csv, zipPart({ name: 'z-1.jpg', data: Buffer.alloc(6000) })], '?dryRun=true');
    expect([big.statusCode, body(big).error.code]).toEqual([413, 'ZIP_ENTRY_TOO_LARGE']);
    const total = await send(a, [csv, zipPart(...['1', '2', '3'].map((n) => ({ name: `z-${n}.jpg`, data: Buffer.alloc(3000) })))], '?dryRun=true');
    expect([total.statusCode, body(total).error.code]).toEqual([413, 'ZIP_TOO_LARGE']);
    const many = await send(a, [csv, zipPart(...['1', '2', '3', '4', '5'].map((n) => ({ name: `z-${n}.jpg`, data: JPEG() })))], '?dryRun=true');
    expect(body(many).error.code).toBe('ZIP_TOO_MANY_ENTRIES');
    // Lies about its size: inflation is capped, the row sees an invalid photo and nothing is decoded beyond the declared size.
    const lying = makeZip([{ name: 'z-1.jpg', data: Buffer.alloc(3_000_000, 0), declaredSize: 100 }]);
    const lie = await send(a, [csv, { name: 'photos', filename: 'p.zip', data: lying }], '?dryRun=true');
    expect(lie.statusCode).toBe(200);
    expect(body(lie).rows[0].errors.map((e: { code: string }) => e.code)).toEqual(['PHOTO_INVALID']);
    const garbage = await send(a, [csv, { name: 'photos', filename: 'p.zip', data: 'not a zip' }], '?dryRun=true');
    expect(body(garbage).error.code).toBe('ZIP_INVALID');
    expect(await counts()).toEqual(before);
  });

  it('enforces file level limits and shapes', async () => {
    expect(body(await send(a, [csvPart('x'.repeat(4001))], '?dryRun=true')).error.code).toBe('PAYLOAD_TOO_LARGE');
    expect(body(await send(a, [{ name: 'photos', filename: 'p.zip', data: makeZip([]) }], '?dryRun=true')).error.code).toBe('CSV_REQUIRED');
    expect(body(await send(a, [csvPart('')], '?dryRun=true')).error.code).toBe('CSV_REQUIRED');
    expect(body(await send(a, [csvPart(HEADER + '\n')], '?dryRun=true')).error.code).toBe('CSV_EMPTY');
    expect(body(await send(a, [csvPart('fullName,externalId,evil\nA,b,c\n')], '?dryRun=true')).error.code).toBe('UNKNOWN_COLUMN');
    expect(body(await send(a, [csvPart('fullName,externalId\nA,b\n')], '?dryRun=true')).error.code).toBe('MISSING_COLUMN');
    expect(body(await send(a, [csvPart('fullName,fullName,externalId,credentialType\nA,A,b,c\n')], '?dryRun=true')).error.code).toBe('DUPLICATE_COLUMN');
    expect(body(await send(a, [csvPart('fullName,externalId,credentialType\n"A,b\n')], '?dryRun=true')).error.code).toBe('CSV_MALFORMED');
    expect(body(await send(a, [{ name: 'other', filename: 'x', data: 'x' }], '?dryRun=true')).error.code).toBe('BAD_REQUEST');
    expect(body(await send(a, [csvPart(csvOf(good('q-1')))], '?dryRun=maybe')).error.code).toBe('INVALID_DRY_RUN');
    expect(body(await send(a, [csvPart(csvOf(good('q-1')))], '?foo=1')).error.code).toBe('UNKNOWN_PROPERTY');
    const notMp = await app.inject({ method: 'POST', url: '/api/v1/credentials/import', headers: { ...a.headers, ...json }, payload: {} });
    expect(notMp.statusCode).toBe(415);
    const row = await send(a, [csvPart('fullName,externalId,credentialType\nA,b\n')], '?dryRun=true');
    expect(body(row).rows[0].errors[0].code).toBe('COLUMN_COUNT');
  });

  it('suspended institution cannot import (409), even for a dry run', async () => {
    const res = await send(sus, [csvPart(csvOf(good('s-1')))], '?dryRun=true');
    expect([res.statusCode, body(res).error.code]).toEqual([409, 'INSTITUTION_SUSPENDED']);
  });

  it('another institution sees only its own types: type codes are not shared', async () => {
    const res = await send(b, [csvPart(csvOf(good('b-1')))], '?dryRun=true');
    expect(res.statusCode).toBe(400); // inst B has no attribute "program": the column is unknown to it
    expect(body(res).error.code).toBe('UNKNOWN_COLUMN');
  });

  it('storage failure leaves nothing behind; a failed enqueue marks the batch FAILED (503)', async () => {
    const before = await counts();
    const csv = csvOf(good('f-1'));
    storage.failPut = true;
    const r1 = await send(a, [csvPart(csv), zipPart({ name: 'f-1.jpg', data: JPEG() })]);
    storage.failPut = false;
    expect([r1.statusCode, body(r1).error.code]).toEqual([503, 'STORAGE_UNAVAILABLE']);
    expect(await counts()).toEqual(before);

    queue.fail = true;
    const r2 = await send(a, [csvPart(csv), zipPart({ name: 'f-1.jpg', data: JPEG() })]);
    queue.fail = false;
    expect([r2.statusCode, body(r2).error.code]).toEqual([503, 'QUEUE_UNAVAILABLE']);
    const failed = await ownerQuery(`SELECT status, completed_at FROM import_batches WHERE institution_id = $1 AND status = 'FAILED'`, [INST_A]);
    expect(failed.rows).toHaveLength(1);
    expect(failed.rows[0].completed_at).not.toBeNull();
  });

  it('limits concurrent active batches per institution', async () => {
    await ownerQuery(`DELETE FROM import_batches WHERE institution_id = $1 AND status = 'PENDING'`, [INST_A]);
    const photo = zipPart({ name: 'c-1.jpg', data: JPEG() });
    const ok: number[] = [];
    for (let i = 0; i < 3; i++) ok.push((await send(a, [csvPart(csvOf(good('c-1'))), photo])).statusCode);
    expect(ok).toEqual([202, 202, 202]);
    const r = await send(a, [csvPart(csvOf(good('c-1'))), photo]);
    expect([r.statusCode, body(r).error.code]).toEqual([409, 'TOO_MANY_ACTIVE_IMPORTS']);
  });

  it('is rate limited per institution and needs storage only for real runs', async () => {
    const limited = await buildApp({
      config: { logLevel: 'silent', rateLimit, masterKey: master },
      db,
      importRateLimit: { max: 2, windowSeconds: 60 },
    });
    const c = await loginAs(limited, 'a@example.test');
    const csv = csvPart(csvOf(good('r-1')));
    const first = await send(c, [csv, zipPart({ name: 'r-1.jpg', data: JPEG() })], '?dryRun=true', limited);
    expect(first.statusCode).toBe(200); // no storage needed for a preview
    const real = await send(c, [csv, zipPart({ name: 'r-1.jpg', data: JPEG() })], '', limited);
    expect([real.statusCode, body(real).error.code]).toEqual([503, 'STORAGE_UNAVAILABLE']);
    const third = await send(c, [csv, zipPart({ name: 'r-1.jpg', data: JPEG() })], '?dryRun=true', limited);
    expect(third.statusCode).toBe(429);
    expect(third.headers['retry-after']).toBeDefined();
    await limited.close();
  });
});
