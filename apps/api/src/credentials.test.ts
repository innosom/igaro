// Integration tests for single credential issuance (T-025). Skipped when DATABASE_URL is unset. Runs as the
// restricted igaro_app role in a scratch schema, so RLS is enforced for real. Test values only.
import { createHash, randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { Writable } from 'node:stream';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import type { FastifyInstance } from 'fastify';
import { generateSigningKey, verifyCredentialIntegrity } from '@igaro/core';
import { verifyAuditChain } from './audit.js';
import { buildApp } from './app.js';
import { csrfTokenFor, hashPassword } from './auth.js';
import { buildAttributes } from './credentials.js';
import { Db } from './db.js';
import { MemoryObjectStorage } from './storage.js';
import { PNG } from './test-images.js';

const url = process.env.DATABASE_URL;
const migrationsDir = new URL('../../../packages/db/prisma/migrations/', import.meta.url);

const INST_A = '11111111-1111-4111-8111-111111111111';
const INST_B = '22222222-2222-4222-8222-222222222222';
const U_PA = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const U_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const U_B = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const H_A = 'a0000000-0000-4000-8000-000000000001';
const H_A_NOPHOTO = 'a0000000-0000-4000-8000-000000000002';
const H_B = 'b0000000-0000-4000-8000-000000000001';
const T_A = 'a1000000-0000-4000-8000-000000000001';
const T_B = 'b1000000-0000-4000-8000-000000000001';
const MISSING = '99999999-9999-4999-8999-999999999999';
const PW = 'correct horse battery staple';
const json = { 'content-type': 'application/json' };
const BIG = { ipMax: 10000, accountMax: 10000, windowSeconds: 900 };
const rateLimit = { login: BIG, reset: BIG, token: { ipMax: 10000, windowSeconds: 900 } };
const PHOTO_SHA = createHash('sha256').update('photo-a').digest('hex');

interface Client {
  headers: Record<string, string>;
}

describe('buildAttributes (unit)', () => {
  const schema = [
    { key: 'program', label: 'Program', type: 'string', required: true },
    { key: 'year', label: 'Year', type: 'number', required: false },
    { key: 'awarded', label: 'Awarded', type: 'date', required: false },
  ];
  it('normalises to NFC strings, omits absent optionals, stringifies numbers', () => {
    const out = buildAttributes(schema, { program: 'Café', year: 3 });
    expect(out).toEqual({ program: 'Café', year: '3' });
    expect(Object.keys(out)).not.toContain('awarded');
  });
  it('rejects unknown, missing, mistyped, impossible dates and prototype names', () => {
    expect(() => buildAttributes(schema, {})).toThrow();
    expect(() => buildAttributes(schema, { program: 'x', other: 'y' })).toThrow();
    expect(() => buildAttributes(schema, { program: 'x', year: 'abc' })).toThrow();
    expect(() => buildAttributes(schema, { program: 'x', year: 1e30 })).toThrow();
    expect(() => buildAttributes(schema, { program: 5 })).toThrow();
    expect(() => buildAttributes(schema, { program: 'x', awarded: '2026-02-30' })).toThrow();
    expect(() => buildAttributes(schema, { program: 'x', constructor: 'y' })).toThrow();
    expect(() => buildAttributes(schema, { program: 'a‮b' })).toThrow();
    expect(() => buildAttributes('garbage', {})).toThrow();
  });
});

describe.skipIf(!url)('credential issuance (needs Postgres)', () => {
  const schema = `t025_${randomBytes(4).toString('hex')}`;
  const master = randomBytes(32);
  let owner: pg.Client;
  let db: Db;
  let app: FastifyInstance;
  let appNoMaster: FastifyInstance;
  let a: Client;
  let b: Client;
  let pa: Client;
  let aNoMaster: Client;
  const logs: string[] = [];
  const storage = new MemoryObjectStorage();

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

  const loginAs = async (which: FastifyInstance, email: string): Promise<Client> => {
    const res = await which.inject({ method: 'POST', url: '/api/v1/auth/login', headers: json, payload: { email, password: PW } });
    expect(res.statusCode).toBe(200);
    const cookie = String(res.headers['set-cookie']).split(';')[0]!;
    return { headers: { cookie, 'x-csrf-token': csrfTokenFor(cookie.slice(cookie.indexOf('=') + 1)) } };
  };

  const issue = (c: Client | null, body: unknown, which: FastifyInstance = app) =>
    which.inject({
      method: 'POST',
      url: '/api/v1/credentials',
      headers: { ...(c?.headers ?? {}), ...json },
      payload: body as Record<string, unknown>,
    });
  const good = { holderId: H_A, credentialTypeCode: 'STUDENT_ID', attributes: { program: 'Computer Science', yearOfStudy: 2 } };

  const activeKey = async (inst: string) =>
    (await ownerQuery(`SELECT kid, public_key FROM institution_keys WHERE institution_id = $1 AND status = 'ACTIVE'`, [inst])).rows[0] as {
      kid: string;
      public_key: string;
    };
  const insertKey = async (inst: string, status: 'ACTIVE' | 'RETIRED' | 'COMPROMISED') => {
    const k = generateSigningKey(master);
    await ownerQuery(
      `INSERT INTO institution_keys (id, institution_id, kid, algorithm, public_key, encrypted_private_key, status)
       VALUES (gen_random_uuid(), $1, $2, 'Ed25519', $3, $4, $5)`,
      [inst, k.kid, k.publicKey, k.encryptedPrivateKey, status],
    );
    return k;
  };
  const counts = async () => {
    const r = await ownerQuery(
      `SELECT (SELECT count(*)::int FROM credentials) AS c, (SELECT count(*)::int FROM credential_events) AS e,
              (SELECT count(*)::int FROM audit_logs WHERE action = 'credential.issued') AS a`,
    );
    return r.rows[0] as { c: number; e: number; a: number };
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
    for (const [id, slug] of [
      [INST_A, 'inst-a'],
      [INST_B, 'inst-b'],
    ] as const) {
      await ownerQuery(`INSERT INTO institutions (id, name, slug, updated_at) VALUES ($1,$2,$3,now())`, [id, `Inst ${slug}`, slug]);
      await insertKey(id, 'ACTIVE');
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
    const attrs = JSON.stringify([
      { key: 'program', label: 'Programme', type: 'string', required: true },
      { key: 'faculty', label: 'Faculty', type: 'string', required: false },
      { key: 'yearOfStudy', label: 'Year of study', type: 'number', required: false },
    ]);
    for (const [id, inst] of [
      [T_A, INST_A],
      [T_B, INST_B],
    ]) {
      await ownerQuery(
        `INSERT INTO credential_types (id, institution_id, code, name, kind, attribute_schema, validity_days, updated_at)
         VALUES ($1, $2, 'STUDENT_ID', 'Student ID', 'ID_CARD', $3::jsonb, 365, now())`,
        [id, inst, attrs],
      );
    }
    await ownerQuery(
      `INSERT INTO credential_types (id, institution_id, code, name, kind, attribute_schema, validity_days, updated_at)
       VALUES (gen_random_uuid(), $1, 'B_ONLY', 'B only', 'CERTIFICATE', '[]'::jsonb, NULL, now())`,
      [INST_B],
    );
    await ownerQuery(
      `INSERT INTO credential_types (id, institution_id, code, name, kind, attribute_schema, validity_days, updated_at)
       VALUES (gen_random_uuid(), $1, 'FOREVER', 'No expiry', 'CERTIFICATE', '[]'::jsonb, NULL, now())`,
      [INST_A],
    );
    for (const [id, inst, name, ext, sha] of [
      [H_A, INST_A, 'Ada Lovelace', 'ada-1', PHOTO_SHA],
      [H_A_NOPHOTO, INST_A, 'No Photo', 'np-1', null],
      [H_B, INST_B, 'Bob B', 'bob-1', PHOTO_SHA],
    ] as const) {
      await ownerQuery(
        `INSERT INTO credential_holders (id, institution_id, full_name, external_id, photo_key, photo_sha256, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,now())`,
        [id, inst, name, ext, sha ? `institutions/${inst}/holders/${id}/photo/${sha}.png` : null, sha],
      );
    }

    db = new Db({ connectionString: url!, max: 8, poolConfig: { options: `-c search_path=${schema} -c role=igaro_app` } });
    const logStream = new Writable({
      write(c, _e, cb) {
        logs.push(String(c));
        cb();
      },
    });
    app = await buildApp({ config: { logLevel: 'debug', rateLimit, masterKey: master }, db, storage, logStream });
    appNoMaster = await buildApp({ config: { logLevel: 'silent', rateLimit }, db });
    pa = await loginAs(app, 'pa@example.test');
    a = await loginAs(app, 'a@example.test');
    b = await loginAs(app, 'b@example.test');
    aNoMaster = await loginAs(appNoMaster, 'a@example.test');
  });

  afterAll(async () => {
    await app?.close();
    await appNoMaster?.close();
    await db?.close();
    if (!owner) return;
    await owner.query('ROLLBACK').catch(() => undefined);
    await owner.query('RESET search_path');
    await owner.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    await owner.end();
  });

  it('issues an ACTIVE signed credential whose signature verifies with core and the published public key', async () => {
    const res = await issue(a, good);
    expect(res.statusCode).toBe(201);
    expect(res.headers['cache-control']).toBe('no-store');
    const out = res.json();
    expect(out.status).toBe('ACTIVE');
    expect(out.credentialNumber).toMatch(/^\d{4}-\d{6}$/);
    expect(out.verificationToken).toMatch(/^[A-Za-z0-9_-]{22}$/); // 128 bits
    expect(out.holderToken).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(out.holderToken).not.toBe(out.verificationToken);
    expect(out.payload.salt).toMatch(/^[A-Za-z0-9_-]{43}$/); // 256 bits
    expect(out.payload).toMatchObject({
      schemaVersion: 'igaro.credential.v1',
      credentialId: out.id,
      credentialNumber: out.credentialNumber,
      institutionId: INST_A,
      credentialType: 'STUDENT_ID',
      holder: { fullName: 'Ada Lovelace', externalId: 'ada-1', photoSha256: PHOTO_SHA },
      attributes: { program: 'Computer Science', yearOfStudy: '2' },
    });
    const key = await activeKey(INST_A);
    expect(out.issuerKeyId).toBe(key.kid);
    expect(out.payload.issuerKeyId).toBe(key.kid);
    expect(verifyCredentialIntegrity(out.payload, out.dataHash, out.signature, key.public_key)).toBe('OK');
    // The other tenant's key must not verify it.
    expect(verifyCredentialIntegrity(out.payload, out.dataHash, out.signature, (await activeKey(INST_B)).public_key)).toBe('SIGNATURE_INVALID');
    // A one-field change breaks integrity.
    const tampered = { ...out.payload, attributes: { ...out.payload.attributes, program: 'Law' } };
    expect(verifyCredentialIntegrity(tampered, out.dataHash, out.signature, key.public_key)).toBe('HASH_MISMATCH');

    // Stored row: ACTIVE, payload identical, holder token only as hash, verification token in clear.
    const row = (await ownerQuery(`SELECT * FROM credentials WHERE id = $1`, [out.id])).rows[0];
    expect(row.status).toBe('ACTIVE');
    expect(row.payload).toEqual(out.payload);
    expect(row.data_hash).toBe(out.dataHash);
    expect(row.signature).toBe(out.signature);
    expect(row.issuer_kid).toBe(key.kid);
    expect(row.anchor_status).toBe('NOT_ANCHORED');
    expect(row.verification_token).toBe(out.verificationToken);
    expect(row.holder_token_hash).toBe(createHash('sha256').update(out.holderToken).digest('hex'));
    expect(JSON.stringify(row)).not.toContain(out.holderToken);
    expect(row.issued_at.toISOString().slice(0, 19) + 'Z').toBe(out.issuedAt);
    // type validity 365 days by default
    expect(Date.parse(out.expiresAt) - Date.parse(out.issuedAt)).toBe(365 * 86_400_000);

    // Outbox event and audit entry in the same transaction.
    const ev = (await ownerQuery(`SELECT type, payload, anchored_at FROM credential_events WHERE credential_id = $1`, [out.id])).rows;
    expect(ev).toHaveLength(1);
    expect(ev[0].type).toBe('ISSUED');
    expect(ev[0].anchored_at).toBeNull();
    expect(JSON.stringify(ev[0].payload)).not.toContain(out.holderToken);
    const audit = (await ownerQuery(`SELECT * FROM audit_logs WHERE target_id = $1`, [out.id])).rows;
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({ institution_id: INST_A, actor_id: U_A, action: 'credential.issued', target_type: 'credential' });
    const raw = JSON.stringify(audit[0]);
    for (const secret of [out.holderToken, out.verificationToken, out.payload.salt]) expect(raw).not.toContain(secret);
    const chain = await db.withTenant({ kind: 'tenant', userId: U_A, institutionId: INST_A }, (c) => verifyAuditChain(c, INST_A));
    expect(chain.ok).toBe(true);
  });

  it('numbers are sequential per institution; salts and tokens are never reused', async () => {
    const x = (await issue(a, good)).json();
    const y = (await issue(a, good)).json();
    const seq = (n: string) => Number(n.split('-')[1]);
    expect(seq(y.credentialNumber)).toBe(seq(x.credentialNumber) + 1);
    expect(new Set([x.payload.salt, y.payload.salt]).size).toBe(2);
    expect(new Set([x.verificationToken, y.verificationToken, x.holderToken, y.holderToken]).size).toBe(4);
    // Institution B has its own sequence.
    const z = (await issue(b, { ...good, holderId: H_B })).json();
    expect(seq(z.credentialNumber)).toBe(1);
  });

  it('parallel issuance never duplicates a number or forks the audit chain', async () => {
    const results = await Promise.all(Array.from({ length: 6 }, () => issue(a, good)));
    expect(results.every((r) => r.statusCode === 201)).toBe(true);
    const nums = results.map((r) => r.json().credentialNumber as string);
    expect(new Set(nums).size).toBe(6);
    const chain = await db.withTenant({ kind: 'tenant', userId: U_A, institutionId: INST_A }, (c) => verifyAuditChain(c, INST_A));
    expect(chain.ok).toBe(true);
  });

  it('expiry: explicit value, null, none by type default, and a past value is refused', async () => {
    const future = '2099-01-31T00:00:00Z';
    const e1 = (await issue(a, { ...good, expiresAt: future })).json();
    expect(e1.expiresAt).toBe(future);
    expect(e1.payload.expiresAt).toBe(future);
    const e2 = (await issue(a, { ...good, expiresAt: null })).json();
    expect(e2.expiresAt).toBeNull();
    const e3 = (await issue(a, { holderId: H_A, credentialTypeCode: 'FOREVER', attributes: {} })).json();
    expect(e3.expiresAt).toBeNull();
    for (const bad of ['2020-01-01T00:00:00Z', '2099-01-31', '2099-02-30T00:00:00Z', 'tomorrow', 5]) {
      const r = await issue(a, { ...good, expiresAt: bad });
      expect(r.statusCode, String(bad)).toBe(400);
      expect(r.json().error.code).toBe('INVALID_EXPIRES_AT');
    }
  });

  it('NFC-normalises text that goes into the signed payload', async () => {
    const r = await issue(a, { ...good, attributes: { program: 'Café Studies' } });
    expect(r.statusCode).toBe(201);
    expect(r.json().payload.attributes.program).toBe('Café Studies');
  });

  describe('validation (400) and nothing is written', () => {
    const cases: [string, unknown, string][] = [
      ['not an object', 'x', 'BAD_REQUEST'],
      ['array body', [], 'BAD_REQUEST'],
      ['unknown property', { ...good, institutionId: INST_B }, 'UNKNOWN_PROPERTY'],
      ['status smuggled', { ...good, status: 'REVOKED' }, 'UNKNOWN_PROPERTY'],
      ['holderId missing', { credentialTypeCode: 'STUDENT_ID', attributes: {} }, 'INVALID_HOLDER_ID'],
      ['type code missing', { holderId: H_A, attributes: {} }, 'INVALID_TYPE_CODE'],
      ['attributes not an object', { ...good, attributes: [] }, 'INVALID_ATTRIBUTES'],
      ['required attribute missing', { ...good, attributes: {} }, 'MISSING_ATTRIBUTE'],
      ['unknown attribute', { ...good, attributes: { program: 'x', extra: 'y' } }, 'UNKNOWN_ATTRIBUTE'],
      ['prototype attribute', { ...good, attributes: { program: 'x', __proto__: 'y', constructor: 'z' } }, 'UNKNOWN_ATTRIBUTE'],
      ['string attribute is a number', { ...good, attributes: { program: 5 } }, 'INVALID_ATTRIBUTE_VALUE'],
      ['number attribute is text', { ...good, attributes: { program: 'x', yearOfStudy: 'two' } }, 'INVALID_ATTRIBUTE_VALUE'],
      ['control character', { ...good, attributes: { program: 'a\u0000b' } }, 'INVALID_ATTRIBUTE_VALUE'],
      ['bidi override', { ...good, attributes: { program: 'a‮b' } }, 'INVALID_ATTRIBUTE_VALUE'],
      ['too long', { ...good, attributes: { program: 'x'.repeat(501) } }, 'INVALID_ATTRIBUTE_VALUE'],
    ];
    for (const [name, body, code] of cases) {
      it(name, async () => {
        const before = await counts();
        const r = await issue(a, typeof body === 'string' ? JSON.stringify(body) : body);
        expect(r.statusCode).toBe(400);
        expect(r.json().error.code).toBe(code);
        expect(await counts()).toEqual(before);
      });
    }
  });

  it('refuses a holder without a photo (409): the payload must commit to a photo hash', async () => {
    const before = await counts();
    const r = await issue(a, { ...good, holderId: H_A_NOPHOTO });
    expect(r.statusCode).toBe(409);
    expect(r.json().error.code).toBe('HOLDER_PHOTO_REQUIRED');
    expect(await counts()).toEqual(before);
  });

  it("cross-tenant: another tenant's holder or type is 404, never 403, and nothing is written", async () => {
    const before = await counts();
    const holder = await issue(a, { ...good, holderId: H_B });
    expect(holder.statusCode).toBe(404);
    expect(holder.json()).toEqual({ error: { code: 'NOT_FOUND', message: 'Not found' } });
    const type = await issue(a, { ...good, credentialTypeCode: 'B_ONLY', attributes: {} });
    expect(type.statusCode).toBe(404);
    expect(type.json()).toEqual({ error: { code: 'NOT_FOUND', message: 'Not found' } });
    for (const unknown of [{ ...good, holderId: MISSING }, { ...good, holderId: 'not-a-uuid' }, { ...good, credentialTypeCode: 'NOPE' }]) {
      const r = await issue(a, unknown);
      expect(r.statusCode).toBe(404);
      expect(r.json()).toEqual({ error: { code: 'NOT_FOUND', message: 'Not found' } });
    }
    expect(await counts()).toEqual(before);
  });

  it('authorization: 401 without a session, 403 for a platform admin, 403 without the CSRF header', async () => {
    expect((await issue(null, good)).statusCode).toBe(401);
    expect((await issue(pa, good)).statusCode).toBe(403);
    const noCsrf = await issue({ headers: { cookie: a.headers.cookie! } }, good);
    expect(noCsrf.statusCode).toBe(403);
  });

  it('suspended institution cannot issue (409)', async () => {
    await ownerQuery(`UPDATE institutions SET status = 'SUSPENDED' WHERE id = $1`, [INST_B]);
    try {
      const r = await issue(b, { ...good, holderId: H_B });
      expect(r.statusCode).toBe(409);
      expect(r.json().error.code).toBe('INSTITUTION_SUSPENDED');
    } finally {
      await ownerQuery(`UPDATE institutions SET status = 'ACTIVE' WHERE id = $1`, [INST_B]);
    }
  });

  describe('signing key rules', () => {
    // Key status changes are one-way in the DB, so each case gets its own institution seeded with the key states.
    const seedInstitution = async (n: number, statuses: ('ACTIVE' | 'RETIRED' | 'COMPROMISED')[]) => {
      const hex = n.toString(16).padStart(12, '0');
      const inst = `cc000000-0000-4000-8000-${hex}`;
      const holder = `cc000001-0000-4000-8000-${hex}`;
      const email = `c${n}@example.test`;
      await ownerQuery(`INSERT INTO institutions (id, name, slug, updated_at) VALUES ($1,$2,$3,now())`, [inst, `Inst C${n}`, `inst-c${n}`]);
      for (const st of statuses) await insertKey(inst, st);
      await ownerQuery(
        `INSERT INTO users (id, institution_id, email, name, password_hash, role, status, updated_at)
         VALUES (gen_random_uuid(), $1, $2, 'Name', $3, 'INSTITUTION_ADMIN', 'ACTIVE', now())`,
        [inst, email, await hashPassword(PW)],
      );
      await ownerQuery(
        `INSERT INTO credential_types (id, institution_id, code, name, kind, attribute_schema, validity_days, updated_at)
         VALUES (gen_random_uuid(), $1, 'STUDENT_ID', 'Student ID', 'ID_CARD', '[]'::jsonb, NULL, now())`,
        [inst],
      );
      await ownerQuery(
        `INSERT INTO credential_holders (id, institution_id, full_name, photo_sha256, updated_at) VALUES ($1,$2,'C Holder',$3,now())`,
        [holder, inst, PHOTO_SHA],
      );
      return { client: await loginAs(app, email), body: { holderId: holder, credentialTypeCode: 'STUDENT_ID', attributes: {} } };
    };

    it('a RETIRED or COMPROMISED key is never used; with no ACTIVE key issuance is refused (409)', async () => {
      const before = await counts();
      let n = 1;
      for (const statuses of [['RETIRED'], ['COMPROMISED'], ['RETIRED', 'COMPROMISED']] as const) {
        const { client, body } = await seedInstitution(n++, [...statuses]);
        const r = await issue(client, body);
        expect(r.statusCode, statuses.join()).toBe(409);
        expect(r.json().error.code).toBe('NO_ACTIVE_KEY');
      }
      expect(await counts()).toEqual(before);
    });

    it('with a retired and an active key, only the ACTIVE key signs', async () => {
      const { client, body } = await seedInstitution(10, ['RETIRED', 'ACTIVE']);
      const r = await issue(client, body);
      expect(r.statusCode).toBe(201);
      const keys = (await ownerQuery(`SELECT kid, status FROM institution_keys WHERE institution_id = $1`, [r.json().payload.institutionId])).rows;
      expect(keys.find((k) => k.status === 'ACTIVE')!.kid).toBe(r.json().issuerKeyId);
    });

    it('after rotation the new ACTIVE key signs, and the old (RETIRED) credential still verifies against its own kid', async () => {
      const old = await activeKey(INST_A);
      const first = (await issue(a, good)).json();
      const rot = await app.inject({ method: 'POST', url: '/api/v1/institution/keys/rotate', headers: { ...a.headers, ...json }, payload: { password: PW } });
      expect(rot.statusCode).toBeLessThan(300);
      const now = await activeKey(INST_A);
      expect(now.kid).not.toBe(old.kid);
      const second = (await issue(a, good)).json();
      expect(second.issuerKeyId).toBe(now.kid);
      expect(first.issuerKeyId).toBe(old.kid);
      expect(verifyCredentialIntegrity(second.payload, second.dataHash, second.signature, now.public_key)).toBe('OK');
      expect(verifyCredentialIntegrity(first.payload, first.dataHash, first.signature, old.public_key)).toBe('OK');
    });

    it('503 without a master key; a wrong master key fails closed with no key material in the response or logs', async () => {
      const before = await counts();
      const r = await issue(aNoMaster, good, appNoMaster);
      expect(r.statusCode).toBe(503);
      expect(r.json().error.code).toBe('KEY_CUSTODY_UNAVAILABLE');

      const wrong = await buildApp({ config: { logLevel: 'silent', rateLimit, masterKey: randomBytes(32) }, db });
      try {
        const c = await loginAs(wrong, 'a@example.test');
        const w = await issue(c, good, wrong);
        expect(w.statusCode).toBe(500);
        expect(w.json()).toEqual({ error: { code: 'SIGNING_FAILED', message: 'Could not sign the credential' } });
        const enc = (await ownerQuery(`SELECT encrypted_private_key FROM institution_keys WHERE institution_id = $1`, [INST_A])).rows.map(
          (x) => x.encrypted_private_key as string,
        );
        for (const e of enc) expect(w.body).not.toContain(e);
      } finally {
        await wrong.close();
      }
      expect(await counts()).toEqual(before);
    });

    it('a key row whose public key does not match its private key is caught by the self-check', async () => {
      const { client, body } = await seedInstitution(20, []);
      const inst = (await ownerQuery(`SELECT institution_id FROM users WHERE email = 'c20@example.test'`)).rows[0].institution_id as string;
      const real = generateSigningKey(master);
      const other = generateSigningKey(master);
      await ownerQuery(
        `INSERT INTO institution_keys (id, institution_id, kid, algorithm, public_key, encrypted_private_key, status)
         VALUES (gen_random_uuid(), $1, $2, 'Ed25519', $3, $4, 'ACTIVE')`,
        [inst, real.kid, other.publicKey, real.encryptedPrivateKey],
      );
      const before = await counts();
      const r = await issue(client, body);
      expect(r.statusCode).toBe(500);
      expect(r.json().error.code).toBe('SIGNING_FAILED');
      expect(await counts()).toEqual(before);
    });
  });

  it('rolls back everything when the audit insert fails: no credential, event or number consumed', async () => {
    await ownerQuery(`
      CREATE FUNCTION t025_fail() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN IF NEW.action = 'credential.issued' THEN RAISE EXCEPTION 'forced failure'; END IF; RETURN NEW; END $$`);
    await ownerQuery(`CREATE TRIGGER t025_fail_trg BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION t025_fail()`);
    const before = await counts();
    const numBefore = (await ownerQuery(`SELECT max(credential_number) AS m FROM credentials WHERE institution_id = $1`, [INST_A])).rows[0].m;
    try {
      const r = await issue(a, good);
      expect(r.statusCode).toBe(500);
      expect(r.json()).toEqual({ error: { code: 'INTERNAL', message: 'Internal server error' } });
    } finally {
      await ownerQuery(`DROP TRIGGER t025_fail_trg ON audit_logs`);
      await ownerQuery(`DROP FUNCTION t025_fail()`);
    }
    expect(await counts()).toEqual(before);
    expect((await ownerQuery(`SELECT max(credential_number) AS m FROM credentials WHERE institution_id = $1`, [INST_A])).rows[0].m).toBe(numBefore);
    // And the next issuance still works and continues the chain.
    expect((await issue(a, good)).statusCode).toBe(201);
    const chain = await db.withTenant({ kind: 'tenant', userId: U_A, institutionId: INST_A }, (c) => verifyAuditChain(c, INST_A));
    expect(chain.ok).toBe(true);
  });

  it('replacing a holder photo keeps the object that issued credentials commit to (T-018 M1)', async () => {
    const h = (await app.inject({ method: 'POST', url: '/api/v1/holders', headers: { ...a.headers, ...json }, payload: { fullName: 'Photo Holder' } })).json();
    const up = async (data: Buffer) => {
      const boundary = `----t025${randomBytes(4).toString('hex')}`;
      const payload = Buffer.concat([
        Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="p.bin"\r\n\r\n`),
        data,
        Buffer.from(`\r\n--${boundary}--\r\n`),
      ]);
      return app.inject({
        method: 'POST',
        url: `/api/v1/holders/${h.id}/photo`,
        headers: { ...a.headers, 'content-type': `multipart/form-data; boundary=${boundary}` },
        payload,
      });
    };
    expect((await up(PNG(0))).statusCode).toBe(200);
    const first = (await ownerQuery(`SELECT photo_key, photo_sha256 FROM credential_holders WHERE id = $1`, [h.id])).rows[0];
    const c = await issue(a, { ...good, holderId: h.id });
    expect(c.statusCode).toBe(201);
    expect(c.json().payload.holder.photoSha256).toBe(first.photo_sha256);

    expect((await up(PNG(5))).statusCode).toBe(200);
    const second = (await ownerQuery(`SELECT photo_key, photo_sha256 FROM credential_holders WHERE id = $1`, [h.id])).rows[0];
    expect(second.photo_sha256).not.toBe(first.photo_sha256);
    // The signed commitment still has its file, found by hash.
    expect(storage.objects.has(first.photo_key)).toBe(true);
    expect(first.photo_key).toContain(first.photo_sha256);
    expect(createHash('sha256').update(storage.objects.get(first.photo_key)!.body).digest('hex')).toBe(first.photo_sha256);

    // A third photo: the second was never signed, so it is cleaned up as before.
    expect((await up(PNG(9))).statusCode).toBe(200);
    expect(storage.objects.has(second.photo_key)).toBe(false);
    expect(storage.objects.has(first.photo_key)).toBe(true);
  });

  it('never logs tokens, salts, signatures or key material', async () => {
    const out = (await issue(a, good)).json();
    const keyRows = (await ownerQuery(`SELECT encrypted_private_key FROM institution_keys`)).rows;
    const all = logs.join('\n');
    expect(all.length).toBeGreaterThan(0);
    for (const secret of [out.holderToken, out.verificationToken, out.payload.salt, out.signature, master.toString('base64'), master.toString('hex')]) {
      expect(all).not.toContain(secret);
    }
    for (const r of keyRows) expect(all).not.toContain(r.encrypted_private_key as string);
    expect(all).toContain('credential issued');
  });
});
