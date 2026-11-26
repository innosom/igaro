// Integration tests for keys.json and the holder view (T-033, ADR 0023). Skipped when DATABASE_URL is unset.
// Runs as igaro_app (RLS on) in a scratch schema. Test values only.
import { createHash, randomBytes } from 'node:crypto';
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

const url = process.env.DATABASE_URL;
const migrationsDir = new URL('../../../packages/db/prisma/migrations/', import.meta.url);

const PW = 'correct horse battery staple';
const json = { 'content-type': 'application/json' };
const BIG = { ipMax: 10000, accountMax: 10000, windowSeconds: 900 };
const PHOTO_SHA = createHash('sha256').update('photo-v').digest('hex');
const RAW_IP = '203.0.113.77';
const ipHashKey = randomBytes(32);

type Tag = 'A' | 'S' | 'C';
const ID = (n: number) => `${n}${n}${n}${n}${n}${n}${n}${n}-${n}${n}${n}${n}-4${n}${n}${n}-8${n}${n}${n}-${String(n).repeat(12)}`;
const INST: Record<Tag, string> = { A: ID(1), S: ID(2), C: ID(3) };
const USER: Record<Tag, string> = { A: ID(4), S: ID(5), C: ID(6) };
const HOLDER: Record<Tag, string> = { A: ID(7), S: ID(8), C: ID(9) };

interface Client { headers: Record<string, string> }
interface Issued { id: string; verificationToken: string; holderToken: string; credentialNumber: string; payload: { salt: string; issuerKeyId: string } }
type Body = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

describe.skipIf(!url)('public keys and holder view (needs Postgres)', () => {
  const schema = `t033_${randomBytes(4).toString('hex')}`;
  const master = randomBytes(32);
  const lines: string[] = [];
  const logStream = new Writable({ write(chunk, _e, cb) { lines.push(String(chunk)); cb(); } });
  const storage = new MemoryObjectStorage();
  let owner: pg.Client;
  let db: Db;
  let app: FastifyInstance;
  const client = {} as Record<Tag, Client>;

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
  const post = (c: Client, path: string, body: unknown) =>
    app.inject({ method: 'POST', url: `/api/v1${path}`, headers: { ...c.headers, ...json }, payload: body as Record<string, unknown> });
  const issue = async (t: Tag) => {
    const res = await post(client[t], '/credentials', { holderId: HOLDER[t], credentialTypeCode: 'STUDENT_ID', attributes: { program: 'Computer Science' } });
    expect(res.statusCode).toBe(201);
    return res.json() as Issued;
  };
  const get = (url2: string, ip = RAW_IP, a: FastifyInstance = app) => a.inject({ method: 'GET', url: url2, remoteAddress: ip });

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

  it('keys.json lists keys with status and no private material; at root, no-store', async () => {
    const res = await get('/i/inst-a/keys.json');
    expect(res.statusCode).toBe(200);
    expect(res.headers['cache-control']).toBe('no-store');
    const body = res.json();
    expect(body.keys).toHaveLength(1);
    expect(Object.keys(body.keys[0]).sort()).toEqual(['alg', 'createdAt', 'kid', 'publicKey', 'retiredAt', 'status']);
    expect(body.keys[0]).toMatchObject({ alg: 'Ed25519', status: 'ACTIVE', retiredAt: null });
    const priv = (await ownerQuery(`SELECT encrypted_private_key FROM institution_keys WHERE institution_id = $1`, [INST.A])).rows[0].encrypted_private_key as string;
    expect(res.body).not.toContain(priv);
    expect(res.body).not.toMatch(/private|encrypted/i);
    expect((await get('/api/v1/i/inst-a/keys.json')).statusCode).toBe(404);
  });

  it('keys.json shows COMPROMISED and ACTIVE keys with status, only for that institution', async () => {
    const k = generateSigningKey(master);
    await ownerQuery(`UPDATE institution_keys SET status = 'COMPROMISED', retired_at = now() WHERE institution_id = $1`, [INST.C]);
    await ownerQuery(
      `INSERT INTO institution_keys (id, institution_id, kid, algorithm, public_key, encrypted_private_key, status)
       VALUES (gen_random_uuid(), $1, $2, 'Ed25519', $3, $4, 'ACTIVE')`,
      [INST.C, k.kid, k.publicKey, k.encryptedPrivateKey],
    );
    const body = (await get('/i/inst-c/keys.json')).json();
    expect(body.keys.map((x: Body) => x.status).sort()).toEqual(['ACTIVE', 'COMPROMISED']);
    expect(body.keys.find((x: Body) => x.status === 'COMPROMISED').retiredAt).toMatch(/Z$/);
    const a = (await get('/i/inst-a/keys.json')).json();
    expect(a.keys.map((x: Body) => x.kid)).not.toContain(k.kid);
  });

  it('keys.json shows a RETIRED key', async () => {
    const k = generateSigningKey(master);
    await ownerQuery(
      `INSERT INTO institution_keys (id, institution_id, kid, algorithm, public_key, encrypted_private_key, status, retired_at)
       VALUES (gen_random_uuid(), $1, $2, 'Ed25519', $3, $4, 'RETIRED', now())`,
      [INST.S, k.kid, k.publicKey, k.encryptedPrivateKey],
    );
    const body = (await get('/i/inst-s/keys.json')).json();
    expect(body.keys.map((x: Body) => x.status).sort()).toEqual(['ACTIVE', 'RETIRED']);
  });

  it('keys.json is 404 for unknown and malformed slugs', async () => {
    for (const s of ['nope-institution', 'A', '-bad-', 'x'.repeat(200), '..%2f']) {
      expect((await get(`/i/${s}/keys.json`)).statusCode).toBe(404);
    }
  });

  it('holder view returns holder, branding and the credential with links; no-store; no secrets', async () => {
    const c = await issue('A');
    const res = await get(`/api/v1/holder/${c.holderToken}`);
    expect(res.statusCode).toBe(200);
    expect(res.headers['cache-control']).toBe('no-store');
    const body = res.json();
    expect(body.holder).toEqual({ fullName: 'Holder A' });
    expect(body.institution).toMatchObject({ name: 'Inst A', slug: 'inst-a' });
    expect(body.credentials).toHaveLength(1);
    expect(body.credentials[0]).toMatchObject({
      verificationToken: c.verificationToken,
      status: 'ACTIVE',
      type: { code: 'STUDENT_ID' },
      links: { verify: `/v/${c.verificationToken}`, credentialJson: `/api/v1/verify/${c.verificationToken}/credential.json` },
    });
    for (const secret of [c.payload.salt, c.id, c.holderToken, c.credentialNumber, INST.A, 'photoSha256']) expect(res.body).not.toContain(secret);
    const rev = await post(client.A, `/credentials/${c.id}/revoke`, { reason: 'test' });
    expect(rev.statusCode).toBe(200);
    expect((await get(`/api/v1/holder/${c.holderToken}`)).json().credentials[0].status).toBe('REVOKED');
  });

  it('holder view is 404 with one uniform body for unknown, malformed, oversized and verification tokens', async () => {
    const c = await issue('A');
    const bodies = new Set<string>();
    for (const t of [randomBytes(16).toString('base64url'), 'short', 'x'.repeat(300), c.verificationToken, 'a'.repeat(22)]) {
      const res = await get(`/api/v1/holder/${t}`);
      expect(res.statusCode).toBe(404);
      bodies.add(res.body);
    }
    expect(bodies.size).toBe(1);
  });

  it('holder token is stored only as a hash', async () => {
    const c = await issue('A');
    const rows = (await ownerQuery(`SELECT * FROM credentials WHERE id = $1`, [c.id])).rows;
    expect(rows[0].holder_token_hash).toBe(createHash('sha256').update(c.holderToken).digest('hex'));
    expect(JSON.stringify(rows)).not.toContain(c.holderToken);
  });

  it('cross-tenant: a holder token only opens its own credential and institution', async () => {
    const a = await issue('A');
    const b = await issue('S');
    const va = (await get(`/api/v1/holder/${a.holderToken}`)).json();
    const vb = (await get(`/api/v1/holder/${b.holderToken}`)).json();
    expect(va.institution.slug).toBe('inst-a');
    expect(vb.institution.slug).toBe('inst-s');
    expect(va.credentials[0].verificationToken).toBe(a.verificationToken);
    expect(JSON.stringify(va)).not.toContain(b.verificationToken);
    expect((await app.inject({ method: 'GET', url: `/api/v1/credentials/${b.id}`, headers: client.A.headers })).statusCode).toBe(404);
  });

  it('tokens and key material never reach the logs', async () => {
    const c = await issue('A');
    await get(`/api/v1/holder/${c.holderToken}`);
    await get(`/api/v1/holder/${'z'.repeat(22)}`);
    await get('/i/inst-a/keys.json');
    const all = lines.join('');
    expect(all).not.toContain(c.holderToken);
    expect(all).not.toContain(c.payload.salt);
    expect(all).toContain('/holder/:token');
  });

  it('rate limits per IP on both routes and per token for unknown holder tokens', async () => {
    const tight = new Db({ connectionString: url!, max: 4, poolConfig: { options: `-c search_path=${schema} -c role=igaro_app` } });
    const a2 = await buildApp({
      config: { logLevel: 'silent', ipHashKey, masterKey: master, rateLimit: { login: BIG, reset: BIG, token: { ipMax: 10000, windowSeconds: 900 }, verify: { ipMax: 3, tokenMax: 2, windowSeconds: 60 } } },
      db: tight,
      storage,
    });
    try {
      const codes: number[] = [];
      for (let i = 0; i < 5; i++) codes.push((await get('/i/inst-a/keys.json', '198.51.100.1', a2)).statusCode);
      expect(codes).toEqual([200, 200, 200, 429, 429]);
      expect((await get('/i/inst-a/keys.json', '198.51.100.1', a2)).headers['retry-after']).toBeDefined();
      const tok = randomBytes(16).toString('base64url');
      const c2: number[] = [];
      for (let i = 0; i < 4; i++) c2.push((await get(`/api/v1/holder/${tok}`, `198.51.100.${10 + i}`, a2)).statusCode);
      expect(c2).toEqual([404, 404, 429, 429]);
    } finally {
      await a2.close();
      await tight.close();
    }
  });
});
