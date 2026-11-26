// Integration tests for public verification (T-032, ADR 0022). Skipped when DATABASE_URL is unset.
// Runs as igaro_app (RLS on) in a scratch schema. Test values only.
import { createHash, randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { Writable } from 'node:stream';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import type { FastifyInstance } from 'fastify';
import { generateSigningKey, verifyCredentialIntegrity } from '@igaro/core';
import { buildApp } from './app.js';
import { csrfTokenFor, hashPassword } from './auth.js';
import { Db } from './db.js';
import { MemoryObjectStorage } from './storage.js';
import { hashIp } from './logging.js';

const url = process.env.DATABASE_URL;
const migrationsDir = new URL('../../../packages/db/prisma/migrations/', import.meta.url);

const PW = 'correct horse battery staple';
const json = { 'content-type': 'application/json' };
const BIG = { ipMax: 10000, accountMax: 10000, windowSeconds: 900 };
const PHOTO_SHA = createHash('sha256').update('photo-v').digest('hex');
const RAW_IP = '203.0.113.77';
const UA = 'vitest-agent/1.0';
const ipHashKey = randomBytes(32);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

type Tag = 'A' | 'S' | 'C'; // normal, suspended institution, compromised key
const ID = (n: number) => `${n}${n}${n}${n}${n}${n}${n}${n}-${n}${n}${n}${n}-4${n}${n}${n}-8${n}${n}${n}-${String(n).repeat(12)}`;
const INST: Record<Tag, string> = { A: ID(1), S: ID(2), C: ID(3) };
const USER: Record<Tag, string> = { A: ID(4), S: ID(5), C: ID(6) };
const HOLDER: Record<Tag, string> = { A: ID(7), S: ID(8), C: ID(9) };

interface Client { headers: Record<string, string> }
interface Issued { id: string; verificationToken: string; holderToken: string; credentialNumber: string; payload: { salt: string; issuerKeyId: string } }

describe.skipIf(!url)('public verification (needs Postgres)', () => {
  const schema = `t032_${randomBytes(4).toString('hex')}`;
  const master = randomBytes(32);
  const lines: string[] = [];
  const logStream = new Writable({ write(chunk, _e, cb) { lines.push(String(chunk)); cb(); } });
  const storage = new MemoryObjectStorage();
  let owner: pg.Client;
  let db: Db;
  let app: FastifyInstance;
  const client = {} as Record<Tag, Client>;

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
  const loginAs = async (email: string): Promise<Client> => {
    const res = await app.inject({ method: 'POST', url: '/api/v1/auth/login', headers: json, payload: { email, password: PW } });
    expect(res.statusCode).toBe(200);
    const cookie = String(res.headers['set-cookie']).split(';')[0]!;
    return { headers: { cookie, 'x-csrf-token': csrfTokenFor(cookie.slice(cookie.indexOf('=') + 1)) } };
  };
  const post = (c: Client, path: string, body: unknown) =>
    app.inject({ method: 'POST', url: `/api/v1${path}`, headers: { ...c.headers, ...json }, payload: body as Record<string, unknown> });
  const issue = async (t: Tag, extra: Record<string, unknown> = {}) => {
    const res = await post(client[t], '/credentials', { holderId: HOLDER[t], credentialTypeCode: 'STUDENT_ID', attributes: { program: 'Computer Science' }, ...extra });
    expect(res.statusCode).toBe(201);
    return res.json() as Issued;
  };
  const verify = (token: string, ip = RAW_IP, a: FastifyInstance = app) =>
    a.inject({ method: 'GET', url: `/api/v1/verify/${token}`, remoteAddress: ip, headers: { 'user-agent': UA } });
  type Body = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
  const result = async (token: string) => (await verify(token)).json() as Body;
  const logRows = async () => (await ownerQuery(`SELECT * FROM verification_logs ORDER BY created_at, id`)).rows as Body[];

  beforeAll(async () => {
    owner = new pg.Client({ connectionString: url });
    await owner.connect();
    await owner.query(`CREATE SCHEMA "${schema}"`);
    await owner.query(`SET search_path TO "${schema}"`);
    const dirs = readdirSync(migrationsDir, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name).sort();
    for (const d of dirs) await owner.query(readFileSync(new URL(`${d}/migration.sql`, migrationsDir), 'utf8'));
    await owner.query(`GRANT USAGE ON SCHEMA "${schema}" TO igaro_app`);

    const pwHash = await hashPassword(PW);
    for (const t of ['A', 'S', 'C'] as const) {
      await ownerQuery(`INSERT INTO institutions (id, name, slug, updated_at) VALUES ($1,$2,$3,now())`, [INST[t], `Inst ${t}`, `inst-${t.toLowerCase()}`]);
      const k = generateSigningKey(master);
      await ownerQuery(
        `INSERT INTO institution_keys (id, institution_id, kid, algorithm, public_key, encrypted_private_key, status)
         VALUES (gen_random_uuid(), $1, $2, 'Ed25519', $3, $4, 'ACTIVE')`,
        [INST[t], k.kid, k.publicKey, k.encryptedPrivateKey],
      );
      await ownerQuery(
        `INSERT INTO credential_types (id, institution_id, code, name, kind, attribute_schema, validity_days, updated_at)
         VALUES (gen_random_uuid(), $1, 'STUDENT_ID', 'Student ID', 'ID_CARD'::credential_kind, $2::jsonb, 365, now())`,
        [INST[t], JSON.stringify([{ key: 'program', label: 'Programme', type: 'string', required: true }])],
      );
      await ownerQuery(
        `INSERT INTO users (id, institution_id, email, name, password_hash, role, status, updated_at)
         VALUES ($1,$2,$3,'Name',$4,'INSTITUTION_ADMIN','ACTIVE',now())`,
        [USER[t], INST[t], `${t.toLowerCase()}@example.test`, pwHash],
      );
      await ownerQuery(
        `INSERT INTO credential_holders (id, institution_id, full_name, external_id, photo_key, photo_sha256, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,now())`,
        [HOLDER[t], INST[t], `Holder ${t}`, `EXT-${t}-001`, `institutions/${INST[t]}/holders/${HOLDER[t]}/photo/${PHOTO_SHA}.png`, PHOTO_SHA],
      );
    }

    db = new Db({ connectionString: url!, max: 8, poolConfig: { options: `-c search_path=${schema} -c role=igaro_app` } });
    app = await buildApp({
      config: { logLevel: 'info', ipHashKey, masterKey: master, rateLimit: { login: BIG, reset: BIG, token: { ipMax: 10000, windowSeconds: 900 }, verify: { ipMax: 10000, tokenMax: 10000, windowSeconds: 60 } } },
      db,
      storage,
      logStream,
    });
    for (const t of ['A', 'S', 'C'] as const) client[t] = await loginAs(`${t.toLowerCase()}@example.test`);
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

  it('VERIFIED for an active credential, public view limited to publicFields, no secrets', async () => {
    const c = await issue('A');
    const res = await verify(c.verificationToken);
    expect(res.statusCode).toBe(200);
    expect(res.headers['cache-control']).toBe('no-store');
    const body = res.json();
    expect(body.result).toBe('VERIFIED');
    expect(body.status).toBe('ACTIVE');
    expect(body.institution).toMatchObject({ name: 'Inst A', slug: 'inst-a' });
    expect(body.holder).toEqual({ fullName: 'Holder A' }); // publicFields = [] by default
    expect(body.type).toEqual({ code: 'STUDENT_ID', name: 'STUDENT_ID', kind: 'ID_CARD' });
    expect(body.proof).toEqual({ signedBy: 'Inst A', kid: c.payload.issuerKeyId, anchorStatus: 'NOT_ANCHORED' });
    expect(body.supersededBy).toBeNull();
    expect(body.issuedAt).toMatch(/Z$/);
    const text = res.body;
    for (const secret of [c.payload.salt, c.id, c.holderToken, c.credentialNumber, INST.A, 'reason', 'photoSha256']) {
      expect(text).not.toContain(secret);
    }
  });

  it('honours the institution publicFields allow-list', async () => {
    const c = await issue('A');
    await ownerQuery(`UPDATE institutions SET public_fields = $2::jsonb WHERE id = $1`, [INST.A, JSON.stringify(['photo', 'idNumber', 'attributes'])]);
    const body = await result(c.verificationToken);
    expect(body.holder).toMatchObject({ fullName: 'Holder A', idNumber: 'EXT-A-001', attributes: { program: 'Computer Science' } });
    expect(body.holder.photoUrl).toMatch(/^memory:\/\//);
    // A photo that no longer matches the signed hash is never shown.
    await ownerQuery(`UPDATE credential_holders SET photo_sha256 = $2 WHERE id = $1`, [HOLDER.A, 'f'.repeat(64)]);
    expect((await result(c.verificationToken)).holder.photoUrl).toBeNull();
    await ownerQuery(`UPDATE credential_holders SET photo_sha256 = $2 WHERE id = $1`, [HOLDER.A, PHOTO_SHA]);
    await ownerQuery(`UPDATE institutions SET public_fields = '[]'::jsonb WHERE id = $1`, [INST.A]);
    expect((await result(c.verificationToken)).holder).toEqual({ fullName: 'Holder A' });
  });

  it('builds the photo URL from the signed photoSha256 even if photo_key is swapped (tamper)', async () => {
    const c = await issue('A');
    await ownerQuery(`UPDATE institutions SET public_fields = $2::jsonb WHERE id = $1`, [INST.A, JSON.stringify(['photo'])]);
    const swapped = `institutions/${INST.A}/holders/${HOLDER.A}/photo/${'e'.repeat(64)}.png`;
    await ownerQuery(`UPDATE credential_holders SET photo_key = $2 WHERE id = $1`, [HOLDER.A, swapped]);
    try {
      const body = await result(c.verificationToken);
      expect(body.result).toBe('VERIFIED');
      expect(decodeURIComponent(decodeURIComponent(body.holder.photoUrl))).toContain(`/holders/${HOLDER.A}/photo/${PHOTO_SHA}.png`);
      expect(body.holder.photoUrl).not.toContain('e'.repeat(64));
      expect(body.holder.photoSha256).toBe(PHOTO_SHA);
      // A hostile extension or path in the column is never copied into the key.
      await ownerQuery(`UPDATE credential_holders SET photo_key = $2 WHERE id = $1`, [HOLDER.A, '../../x/other.html']);
      expect((await result(c.verificationToken)).holder.photoUrl).toBeNull();
    } finally {
      await ownerQuery(`UPDATE credential_holders SET photo_key = $2 WHERE id = $1`, [
        HOLDER.A,
        `institutions/${INST.A}/holders/${HOLDER.A}/photo/${PHOTO_SHA}.png`,
      ]);
      await ownerQuery(`UPDATE institutions SET public_fields = '[]'::jsonb WHERE id = $1`, [INST.A]);
    }
  });

  it('NOT_FOUND for unknown, malformed and oversized tokens with one uniform shape', async () => {
    const real = await result((await issue('A')).verificationToken);
    const shapes = new Set<string>();
    for (const t of [randomBytes(16).toString('base64url'), 'short', 'x'.repeat(95), 'y'.repeat(300), '%00abc', 'a'.repeat(22)]) {
      const res = await verify(t);
      expect(res.statusCode).toBe(200);
      const b = res.json();
      expect(b.result).toBe('NOT_FOUND');
      shapes.add(Object.keys(b).join(','));
      expect(Object.values({ ...b, result: null }).every((v) => v === null)).toBe(true);
    }
    expect(shapes.size).toBe(1);
    expect(shapes.has(Object.keys(real).join(','))).toBe(true);
    // credential.json: plain 404
    expect((await app.inject({ method: 'GET', url: `/api/v1/verify/${randomBytes(16).toString('base64url')}/credential.json` })).statusCode).toBe(404);
  });

  it('SUSPENDED, REVOKED, EXPIRED and reinstated', async () => {
    const s = await issue('A');
    expect((await post(client.A, `/credentials/${s.id}/suspend`, { reason: 'secret-suspend-reason' })).statusCode).toBe(200);
    const sb = await verify(s.verificationToken);
    expect(sb.json().result).toBe('SUSPENDED');
    expect(sb.body).not.toContain('secret-suspend-reason');
    expect((await post(client.A, `/credentials/${s.id}/reinstate`, {})).statusCode).toBe(200);
    expect((await result(s.verificationToken)).result).toBe('VERIFIED');

    const r = await issue('A');
    expect((await post(client.A, `/credentials/${r.id}/revoke`, { reason: 'secret-revoke-reason' })).statusCode).toBe(200);
    const rb = await verify(r.verificationToken);
    expect(rb.json()).toMatchObject({ result: 'REVOKED', status: 'REVOKED' });
    expect(rb.body).not.toContain('secret-revoke-reason');

    const e = await issue('A', { expiresAt: new Date(Date.now() + 1500).toISOString().slice(0, 19) + 'Z' });
    expect((await result(e.verificationToken)).result).toBe('VERIFIED');
    await sleep(2600);
    expect(await result(e.verificationToken)).toMatchObject({ result: 'EXPIRED', status: 'EXPIRED' });
  });

  it('SUPERSEDED links the new credential by its verification token, not its id', async () => {
    const old = await issue('A');
    const res = await post(client.A, `/credentials/${old.id}/reissue`, { reason: 'secret-reissue-reason', attributes: { program: 'Mathematics' } });
    expect(res.statusCode).toBe(201);
    const fresh = (res.json() as { credential: Issued }).credential;
    const res2 = await verify(old.verificationToken);
    const b = res2.json();
    expect(b.result).toBe('SUPERSEDED');
    expect(b.supersededBy).toBe(fresh.verificationToken);
    expect(res2.body).not.toContain(fresh.id);
    expect(res2.body).not.toContain('secret-reissue-reason');
    expect((await result(fresh.verificationToken)).result).toBe('VERIFIED');
  });

  it('institution suspended gives VALID_WITH_WARNING; a revoked credential still shows REVOKED', async () => {
    const ok = await issue('S');
    const rev = await issue('S');
    expect((await post(client.S, `/credentials/${rev.id}/revoke`, { reason: 'x' })).statusCode).toBe(200);
    await ownerQuery(`UPDATE institutions SET status = 'SUSPENDED' WHERE id = $1`, [INST.S]);
    expect(await result(ok.verificationToken)).toMatchObject({ result: 'VALID_WITH_WARNING', warning: 'INSTITUTION_SUSPENDED' });
    expect((await result(rev.verificationToken)).result).toBe('REVOKED');
  });

  it('compromised key is VERIFICATION_FAILED (shown as failed), without leaking the cause', async () => {
    const c = await issue('C');
    await ownerQuery(`UPDATE institution_keys SET status = 'COMPROMISED', retired_at = now() WHERE institution_id = $1`, [INST.C]);
    const res = await verify(c.verificationToken);
    const b = res.json();
    expect(b.result).toBe('VERIFICATION_FAILED');
    expect(b.institution).toBeNull();
    expect(res.body).not.toMatch(/COMPROMISED/);
    const rows = await logRows();
    expect(rows[rows.length - 1]!.result).toBe('KEY_COMPROMISED'); // distinguished in logs only (ADR 0002)
  });

  it('DB tampering is VERIFICATION_FAILED, even when the credential is revoked, and raises an ops alert', async () => {
    const t1 = await issue('A');
    const t2 = await issue('A');
    const t3 = await issue('A');
    expect((await post(client.A, `/credentials/${t2.id}/revoke`, { reason: 'x' })).statusCode).toBe(200);
    await ownerQuery(`UPDATE credentials SET payload = jsonb_set(payload, '{holder,fullName}', '"Mallory"') WHERE id = $1`, [t1.id], true);
    await ownerQuery(`UPDATE credentials SET payload = jsonb_set(payload, '{holder,fullName}', '"Mallory"') WHERE id = $1`, [t2.id], true);
    await ownerQuery(`UPDATE credentials SET signature = $2 WHERE id = $1`, [t3.id, 'A'.repeat(86)], true);
    lines.length = 0;
    for (const t of [t1, t2, t3]) {
      const res = await verify(t.verificationToken);
      expect(res.json().result).toBe('VERIFICATION_FAILED');
      expect(res.body).not.toContain('Mallory');
    }
    const alerts = lines.map((l) => JSON.parse(l)).filter((l) => l.event === 'VERIFICATION_INTEGRITY_FAILURE');
    expect(alerts).toHaveLength(3);
    expect(alerts[0]).toMatchObject({ alert: 'ops', level: 50, institutionId: INST.A, credentialId: t1.id });
    for (const l of lines) for (const v of [t1.verificationToken, t1.payload.salt, RAW_IP]) expect(l).not.toContain(v);
  });

  it('a payload copied from another credential fails the row binding', async () => {
    const a = await issue('A');
    const b = await issue('A');
    await ownerQuery(
      `UPDATE credentials SET payload = (SELECT payload FROM credentials WHERE id = $2), data_hash = (SELECT data_hash FROM credentials WHERE id = $2),
              signature = (SELECT signature FROM credentials WHERE id = $2) WHERE id = $1`,
      [a.id, b.id],
      true,
    );
    expect((await result(a.verificationToken)).result).toBe('VERIFICATION_FAILED');
    expect((await result(b.verificationToken)).result).toBe('VERIFIED');
  });

  it('writes verification_logs with a keyed IP hash, never the raw IP or the token', async () => {
    const c = await issue('A');
    const before = (await logRows()).length;
    await verify(c.verificationToken);
    await verify(randomBytes(16).toString('base64url'));
    const rows = (await logRows()).slice(before);
    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({ result: 'VERIFIED', credential_id: c.id, institution_id: INST.A, ip_hash: hashIp(RAW_IP, ipHashKey), user_agent: UA });
    expect(rows[1]).toMatchObject({ result: 'NOT_FOUND', credential_id: null, institution_id: null, ip_hash: hashIp(RAW_IP, ipHashKey) });
    const dump = JSON.stringify(rows);
    expect(dump).not.toContain(RAW_IP);
    expect(dump).not.toContain(c.verificationToken);
    // access logs carry neither the token nor the raw IP
    for (const l of lines) {
      expect(l).not.toContain(c.verificationToken);
      expect(l).not.toContain(RAW_IP);
    }
  });

  it('credential.json carries the signed document and verifies with core, including for revoked credentials', async () => {
    const c = await issue('A');
    await post(client.A, `/credentials/${c.id}/revoke`, { reason: 'secret-revoke-reason' });
    const res = await app.inject({ method: 'GET', url: `/api/v1/verify/${c.verificationToken}/credential.json` });
    expect(res.statusCode).toBe(200);
    const b = res.json();
    expect(Object.keys(b).sort()).toEqual(['dataHash', 'kid', 'payload', 'publicKeysUrl', 'signature']);
    expect(b.kid).toBe(c.payload.issuerKeyId);
    expect(b.publicKeysUrl).toBe('/i/inst-a/keys.json');
    expect(res.body).not.toContain('secret-revoke-reason');
    expect(res.body).not.toContain(c.holderToken);
    expect(res.body).not.toContain(c.verificationToken);
    const pub = (await ownerQuery(`SELECT public_key FROM institution_keys WHERE kid = $1`, [b.kid])).rows[0].public_key as string;
    expect(verifyCredentialIntegrity(b.payload, b.dataHash, b.signature, pub)).toBe('OK');
  });

  it('is served without a session and a cookie from another tenant grants nothing extra', async () => {
    const c = await issue('A');
    const res = await app.inject({ method: 'GET', url: `/api/v1/verify/${c.verificationToken}`, headers: { cookie: client.S.headers.cookie! } });
    expect(res.json().result).toBe('VERIFIED');
  });

  it('rate limits per IP and per token with 429 and Retry-After', async () => {
    const limited = await buildApp({
      config: { logLevel: 'silent', ipHashKey, masterKey: master, rateLimit: { login: BIG, reset: BIG, token: { ipMax: 100, windowSeconds: 900 }, verify: { ipMax: 4, tokenMax: 2, windowSeconds: 60 } } },
      db,
    });
    try {
      // Per token: only NOT_FOUND/failed lookups count (2 allowed), across IPs, and credential.json shares the budget.
      const tok = randomBytes(16).toString('base64url');
      expect((await verify(tok, '198.51.100.1', limited)).statusCode).toBe(200);
      expect((await verify(tok, '198.51.100.2', limited)).statusCode).toBe(200);
      const blocked = await verify(tok, '198.51.100.3', limited);
      expect(blocked.statusCode).toBe(429);
      expect(Number(blocked.headers['retry-after'])).toBeGreaterThan(0);
      expect(blocked.body).not.toContain(tok);
      const j = await limited.inject({ method: 'GET', url: `/api/v1/verify/${tok}/credential.json`, remoteAddress: '198.51.100.4' });
      expect(j.statusCode).toBe(429);
      // A real credential is never locked out by repeated successful checks (the token budget is 2): one per IP, 6 times.
      const real = await issue('A');
      for (let i = 0; i < 6; i++) expect((await verify(real.verificationToken, `198.51.100.${10 + i}`, limited)).statusCode).toBe(200);
      // Per IP: 4 requests allowed, the 5th is refused, whatever the tokens.
      for (let i = 0; i < 4; i++) expect((await verify(randomBytes(16).toString('base64url'), '198.51.100.30', limited)).statusCode).toBe(200);
      expect((await verify(randomBytes(16).toString('base64url'), '198.51.100.30', limited)).statusCode).toBe(429);
    } finally {
      await limited.close();
    }
  });
});
