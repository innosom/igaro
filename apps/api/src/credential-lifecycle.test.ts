// Integration tests for credential lifecycle (T-026). Skipped when DATABASE_URL is unset. Runs as igaro_app (RLS on)
// in a scratch schema. Test values only.
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
import { parseLifecycleBody, parseReissueBody } from './credential-lifecycle.js';
import { Db } from './db.js';
import { MemoryObjectStorage } from './storage.js';

const url = process.env.DATABASE_URL;
const migrationsDir = new URL('../../../packages/db/prisma/migrations/', import.meta.url);

const INST_A = '11111111-1111-4111-8111-111111111111';
const INST_B = '22222222-2222-4222-8222-222222222222';
const U_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const U_B = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const H_A = 'a0000000-0000-4000-8000-000000000001';
const H_B = 'b0000000-0000-4000-8000-000000000001';
const MISSING = '99999999-9999-4999-8999-999999999999';
const PW = 'correct horse battery staple';
const json = { 'content-type': 'application/json' };
const BIG = { ipMax: 10000, accountMax: 10000, windowSeconds: 900 };
const rateLimit = { login: BIG, reset: BIG, token: { ipMax: 10000, windowSeconds: 900 } };
const PHOTO_SHA = createHash('sha256').update('photo-a').digest('hex');

interface Client {
  headers: Record<string, string>;
}

describe('lifecycle body parsing (unit)', () => {
  it('requires and bounds the reason', () => {
    expect(() => parseLifecycleBody({}, true)).toThrow();
    expect(() => parseLifecycleBody({ reason: '   ' }, true)).toThrow();
    expect(() => parseLifecycleBody({ reason: 'x'.repeat(501) }, true)).toThrow();
    expect(() => parseLifecycleBody({ reason: 5 }, true)).toThrow();
    expect(() => parseLifecycleBody({ reason: 'a‮b' }, true)).toThrow();
    expect(() => parseLifecycleBody({ reason: 'ok', extra: 1 }, true)).toThrow();
    expect(parseLifecycleBody({ reason: ' ok ' }, true)).toEqual({ reason: 'ok' });
    expect(parseLifecycleBody(undefined, false)).toEqual({});
    expect(() => parseReissueBody({ attributes: {} })).toThrow();
    expect(parseReissueBody({ reason: 'typo', expiresAt: null }).expiresAt).toBeNull();
    expect(() => parseReissueBody({ reason: 'r', expiresAt: 'tomorrow' })).toThrow();
  });
});

describe.skipIf(!url)('credential lifecycle (needs Postgres)', () => {
  const schema = `t026_${randomBytes(4).toString('hex')}`;
  const master = randomBytes(32);
  let owner: pg.Client;
  let db: Db;
  let app: FastifyInstance;
  let a: Client;
  let b: Client;
  const logs: string[] = [];

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
  const post = (c: Client | null, path: string, body?: unknown) =>
    app.inject({
      method: 'POST',
      url: `/api/v1${path}`,
      headers: { ...(c?.headers ?? {}), ...(body === undefined ? {} : json) },
      ...(body === undefined ? {} : { payload: body as Record<string, unknown> }),
    });
  const issue = async (c: Client, holderId = H_A, attributes: Record<string, unknown> = { program: 'Computer Science' }) => {
    const res = await post(c, '/credentials', { holderId, credentialTypeCode: 'STUDENT_ID', attributes });
    expect(res.statusCode).toBe(201);
    return res.json() as { id: string; credentialNumber: string; dataHash: string; signature: string; payload: Record<string, unknown> };
  };
  const row = async (id: string) =>
    (await ownerQuery(`SELECT status, superseded_by FROM credentials WHERE id = $1`, [id])).rows[0] as {
      status: string;
      superseded_by: string | null;
    };
  const events = async (id: string) =>
    (await ownerQuery(`SELECT type, payload FROM credential_events WHERE credential_id = $1 ORDER BY seq`, [id])).rows as {
      type: string;
      payload: Record<string, unknown>;
    }[];
  const audits = async (action: string, target: string) =>
    (await ownerQuery(`SELECT metadata FROM audit_logs WHERE action = $1 AND target_id = $2`, [action, target])).rows as {
      metadata: Record<string, unknown>;
    }[];

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
      const k = generateSigningKey(master);
      await ownerQuery(
        `INSERT INTO institution_keys (id, institution_id, kid, algorithm, public_key, encrypted_private_key, status)
         VALUES (gen_random_uuid(), $1, $2, 'Ed25519', $3, $4, 'ACTIVE')`,
        [id, k.kid, k.publicKey, k.encryptedPrivateKey],
      );
      await ownerQuery(
        `INSERT INTO credential_types (id, institution_id, code, name, kind, attribute_schema, validity_days, updated_at)
         VALUES (gen_random_uuid(), $1, 'STUDENT_ID', 'Student ID', 'ID_CARD', $2::jsonb, 365, now())`,
        [id, JSON.stringify([{ key: 'program', label: 'Programme', type: 'string', required: true }])],
      );
    }
    for (const [id, inst, email] of [
      [U_A, INST_A, 'a@example.test'],
      [U_B, INST_B, 'b@example.test'],
    ] as const) {
      await ownerQuery(
        `INSERT INTO users (id, institution_id, email, name, password_hash, role, status, updated_at)
         VALUES ($1,$2,$3,'Name',$4,'INSTITUTION_ADMIN','ACTIVE',now())`,
        [id, inst, email, pwHash],
      );
    }
    for (const [id, inst, name] of [
      [H_A, INST_A, 'Ada Lovelace'],
      [H_B, INST_B, 'Bob B'],
    ] as const) {
      await ownerQuery(
        `INSERT INTO credential_holders (id, institution_id, full_name, external_id, photo_key, photo_sha256, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,now())`,
        [id, inst, name, `ext-${name}`, `institutions/${inst}/holders/${id}/photo/${PHOTO_SHA}.png`, PHOTO_SHA],
      );
    }

    db = new Db({ connectionString: url!, max: 8, poolConfig: { options: `-c search_path=${schema} -c role=igaro_app` } });
    const logStream = new Writable({
      write(c, _e, cb) {
        logs.push(String(c));
        cb();
      },
    });
    app = await buildApp({ config: { logLevel: 'debug', rateLimit, masterKey: master }, db, storage: new MemoryObjectStorage(), logStream });
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

  it('suspends with a reason, then reinstates; events and audit written in order', async () => {
    const c = await issue(a);
    const s = await post(a, `/credentials/${c.id}/suspend`, { reason: 'Under investigation' });
    expect(s.statusCode).toBe(200);
    expect(s.json()).toMatchObject({ id: c.id, status: 'SUSPENDED', previousStatus: 'ACTIVE' });
    expect((await row(c.id)).status).toBe('SUSPENDED');
    const r = await post(a, `/credentials/${c.id}/reinstate`);
    expect(r.statusCode).toBe(200);
    expect(r.json()).toMatchObject({ status: 'ACTIVE', previousStatus: 'SUSPENDED' });
    expect((await events(c.id)).map((e) => e.type)).toEqual(['ISSUED', 'SUSPENDED', 'REINSTATED']);
    expect((await audits('credential.suspended', c.id))[0]!.metadata).toMatchObject({ reason: 'Under investigation', previousStatus: 'ACTIVE' });
    expect(await audits('credential.reinstated', c.id)).toHaveLength(1);
    const stored = (await ownerQuery(`SELECT payload, data_hash, signature FROM credentials WHERE id = $1`, [c.id])).rows[0];
    expect(stored.payload).toEqual(c.payload);
    expect(stored.data_hash).toBe(c.dataHash);
    expect(stored.signature).toBe(c.signature);
  });

  it('requires a reason for suspend and revoke (400) and changes nothing', async () => {
    const c = await issue(a);
    for (const path of ['suspend', 'revoke']) {
      for (const body of [undefined, {}, { reason: '' }, { reason: '   ' }, { reason: 5 }, { reason: 'x'.repeat(501) }]) {
        const res = await post(a, `/credentials/${c.id}/${path}`, body);
        expect(res.statusCode).toBe(400);
      }
    }
    expect((await post(a, `/credentials/${c.id}/revoke`, {})).json().error.code).toBe('REASON_REQUIRED');
    expect((await row(c.id)).status).toBe('ACTIVE');
    expect(await events(c.id)).toHaveLength(1);
    expect((await post(a, `/credentials/${c.id}/suspend`, { reason: 'r', status: 'ACTIVE' })).statusCode).toBe(400);
  });

  it('revoke is terminal: every later action is 409 and the row cannot change', async () => {
    const c = await issue(a);
    const rv = await post(a, `/credentials/${c.id}/revoke`, { reason: 'Issued in error' });
    expect(rv.statusCode).toBe(200);
    expect(rv.json().status).toBe('REVOKED');
    expect((await audits('credential.revoked', c.id))[0]!.metadata).toMatchObject({ reason: 'Issued in error' });
    const attempts: [string, unknown][] = [
      ['suspend', { reason: 'x' }],
      ['reinstate', undefined],
      ['revoke', { reason: 'x' }],
    ];
    for (const [path, body] of attempts) {
      const res = await post(a, `/credentials/${c.id}/${path}`, body);
      expect(res.statusCode).toBe(409);
      expect(res.json().error.code).toBe('INVALID_TRANSITION');
    }
    expect((await row(c.id)).status).toBe('REVOKED');
    await expect(ownerQuery(`UPDATE credentials SET status = 'ACTIVE' WHERE id = $1`, [c.id])).rejects.toThrow();
  });

  it('illegal transitions are 409: reinstate ACTIVE, suspend SUSPENDED, revoke SUSPENDED', async () => {
    const c = await issue(a);
    expect((await post(a, `/credentials/${c.id}/reinstate`)).statusCode).toBe(409);
    expect((await post(a, `/credentials/${c.id}/suspend`, { reason: 'one' })).statusCode).toBe(200);
    expect((await post(a, `/credentials/${c.id}/suspend`, { reason: 'two' })).statusCode).toBe(409);
    // core lifecycle: REVOKE is ACTIVE -> REVOKED only (ADR 0014 M4 owner question stays open).
    expect((await post(a, `/credentials/${c.id}/revoke`, { reason: 'three' })).statusCode).toBe(409);
    expect((await row(c.id)).status).toBe('SUSPENDED');
  });

  it('reissue supersedes the old credential and links it to a new, correctly signed one', async () => {
    const old = await issue(a);
    const res = await post(a, `/credentials/${old.id}/reissue`, { reason: 'Name corrected', attributes: { program: 'Mathematics' } });
    expect(res.statusCode).toBe(201);
    const out = res.json();
    expect(out.previous).toMatchObject({ id: old.id, status: 'SUPERSEDED', supersededBy: out.credential.id });
    const n = out.credential;
    expect(n.id).not.toBe(old.id);
    expect(n.status).toBe('ACTIVE');
    expect(n.credentialNumber).not.toBe(old.credentialNumber);
    expect(n.payload.attributes).toEqual({ program: 'Mathematics' });
    expect(n.payload.salt).not.toBe(old.payload.salt);
    expect(n.verificationToken).toMatch(/^[A-Za-z0-9_-]{22}$/);
    const pub = (await ownerQuery(`SELECT public_key FROM institution_keys WHERE institution_id = $1 AND status='ACTIVE'`, [INST_A])).rows[0].public_key;
    expect(verifyCredentialIntegrity(n.payload, n.dataHash, n.signature, pub)).toBe('OK');
    expect(await row(old.id)).toEqual({ status: 'SUPERSEDED', superseded_by: n.id });
    expect((await events(old.id)).map((e) => e.type)).toEqual(['ISSUED', 'REISSUED']);
    const ev = await events(n.id);
    expect(ev.map((e) => e.type)).toEqual(['ISSUED']);
    expect(ev[0]!.payload.reissuedFrom).toBe(old.id);
    expect((await audits('credential.reissued', old.id))[0]!.metadata).toMatchObject({ reason: 'Name corrected', newCredentialId: n.id });
    for (const p of ['suspend', 'revoke']) expect((await post(a, `/credentials/${old.id}/${p}`, { reason: 'x' })).statusCode).toBe(409);
    expect((await post(a, `/credentials/${old.id}/reissue`, { reason: 'again' })).statusCode).toBe(409);
    expect((await ownerQuery(`SELECT payload FROM credentials WHERE id = $1`, [old.id])).rows[0].payload).toEqual(old.payload);
  });

  it('reissue without attributes keeps the old ones and the old expiry; reason is required', async () => {
    const old = await issue(a);
    expect((await post(a, `/credentials/${old.id}/reissue`, {})).statusCode).toBe(400);
    expect((await row(old.id)).status).toBe('ACTIVE');
    const res = await post(a, `/credentials/${old.id}/reissue`, { reason: 'Re-sign' });
    expect(res.statusCode).toBe(201);
    expect(res.json().credential.payload.attributes).toEqual(old.payload.attributes);
    expect(res.json().credential.payload.expiresAt).toBe(old.payload.expiresAt);
  });

  it('a failed reissue (invalid attributes) rolls everything back', async () => {
    const old = await issue(a);
    const before = (await ownerQuery(`SELECT count(*)::int AS n FROM credentials`)).rows[0].n;
    const res = await post(a, `/credentials/${old.id}/reissue`, { reason: 'x', attributes: { nope: 'y' } });
    expect(res.statusCode).toBe(400);
    expect((await row(old.id)).status).toBe('ACTIVE');
    expect((await ownerQuery(`SELECT count(*)::int AS n FROM credentials`)).rows[0].n).toBe(before);
    expect(await events(old.id)).toHaveLength(1);
  });

  it('reissue after a mistaken revocation: old stays REVOKED, new links to it, only once', async () => {
    const old = await issue(a);
    expect((await post(a, `/credentials/${old.id}/revoke`, { reason: 'Mistake' })).statusCode).toBe(200);
    const res = await post(a, `/credentials/${old.id}/reissue`, { reason: 'Revocation was a mistake' });
    expect(res.statusCode).toBe(201);
    const out = res.json();
    expect(out.previous).toMatchObject({ id: old.id, status: 'REVOKED', supersededBy: null });
    expect(out.credential.status).toBe('ACTIVE');
    expect(await row(old.id)).toEqual({ status: 'REVOKED', superseded_by: null });
    expect((await events(out.credential.id))[0]!.payload.reissuedFrom).toBe(old.id);
    expect((await events(old.id)).map((e) => e.type)).toEqual(['ISSUED', 'REVOKED']);
    const again = await post(a, `/credentials/${old.id}/reissue`, { reason: 'twice' });
    expect(again.statusCode).toBe(409);
    expect(again.json().error.code).toBe('ALREADY_REISSUED');
  });

  it('SUSPENDED credentials cannot be reissued (409)', async () => {
    const c = await issue(a);
    await post(a, `/credentials/${c.id}/suspend`, { reason: 'hold' });
    expect((await post(a, `/credentials/${c.id}/reissue`, { reason: 'x' })).statusCode).toBe(409);
    expect((await row(c.id)).status).toBe('SUSPENDED');
  });

  it('cross-tenant and unknown ids are 404 for every action and nothing changes', async () => {
    const c = await issue(a);
    const bodies: [string, unknown][] = [
      ['suspend', { reason: 'x' }],
      ['reinstate', undefined],
      ['revoke', { reason: 'x' }],
      ['reissue', { reason: 'x' }],
    ];
    for (const [p, body] of bodies) {
      const foreign = await post(b, `/credentials/${c.id}/${p}`, body);
      expect(foreign.statusCode).toBe(404);
      const missing = await post(b, `/credentials/${MISSING}/${p}`, body);
      expect(missing.statusCode).toBe(404);
      expect(missing.json()).toEqual(foreign.json());
      expect((await post(a, `/credentials/not-a-uuid/${p}`, body)).statusCode).toBe(404);
    }
    expect((await row(c.id)).status).toBe('ACTIVE');
    expect(await events(c.id)).toHaveLength(1);
  });

  it('requires a session and CSRF', async () => {
    const c = await issue(a);
    expect((await post(null, `/credentials/${c.id}/revoke`, { reason: 'x' })).statusCode).toBe(401);
    const noCsrf = await app.inject({
      method: 'POST',
      url: `/api/v1/credentials/${c.id}/revoke`,
      headers: { cookie: a.headers.cookie!, ...json },
      payload: { reason: 'x' },
    });
    expect(noCsrf.statusCode).toBe(403);
    expect((await row(c.id)).status).toBe('ACTIVE');
  });

  it('concurrent revokes: exactly one wins, the others are 409, single event', async () => {
    const c = await issue(a);
    const rs = await Promise.all([1, 2, 3].map((i) => post(a, `/credentials/${c.id}/revoke`, { reason: `r${i}` })));
    expect(rs.map((r) => r.statusCode).sort()).toEqual([200, 409, 409]);
    expect((await events(c.id)).filter((e) => e.type === 'REVOKED')).toHaveLength(1);
  });

  it('keeps the audit chain valid and never logs tokens or salts', async () => {
    const old = await issue(a);
    const res = await post(a, `/credentials/${old.id}/reissue`, { reason: 'log check' });
    const n = res.json().credential;
    const chain = await db.withTenant({ kind: 'tenant', userId: U_A, institutionId: INST_A }, (c) => verifyAuditChain(c, INST_A));
    expect(chain.ok).toBe(true);
    const all = logs.join('\n');
    for (const secret of [n.verificationToken, n.holderToken, n.payload.salt, n.signature, old.payload.salt]) {
      expect(all).not.toContain(secret as string);
    }
  });
});
