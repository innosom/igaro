// Integration tests for credential list/get, dashboard stats, audit logs and verify-chain (T-027).
// Skipped when DATABASE_URL is unset. Runs as igaro_app (RLS on) in a scratch schema. Test values only.
import { createHash, randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import type { FastifyInstance } from 'fastify';
import { generateSigningKey } from '@igaro/core';
import { buildApp } from './app.js';
import { csrfTokenFor, hashPassword } from './auth.js';
import { parseAuditListQuery, parseCredentialListQuery } from './credential-queries.js';
import { Db } from './db.js';
import { MemoryObjectStorage } from './storage.js';

const url = process.env.DATABASE_URL;
const migrationsDir = new URL('../../../packages/db/prisma/migrations/', import.meta.url);

const INST_A = '11111111-1111-4111-8111-111111111111';
const INST_B = '22222222-2222-4222-8222-222222222222';
const U_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const U_B = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const H_A1 = 'a0000000-0000-4000-8000-000000000001';
const H_A2 = 'a0000000-0000-4000-8000-000000000002';
const H_B = 'b0000000-0000-4000-8000-000000000001';
const MISSING = '99999999-9999-4999-8999-999999999999';
const PW = 'correct horse battery staple';
const json = { 'content-type': 'application/json' };
const BIG = { ipMax: 10000, accountMax: 10000, windowSeconds: 900 };
const rateLimit = { login: BIG, reset: BIG, token: { ipMax: 10000, windowSeconds: 900 } };
const PHOTO_SHA = createHash('sha256').update('photo-a').digest('hex');
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

interface Client {
  headers: Record<string, string>;
}
interface Issued {
  id: string;
  credentialNumber: string;
  verificationToken: string;
  holderToken: string;
  payload: { salt: string };
}

describe('list query parsing (unit)', () => {
  it('validates filters, limit and cursor and rejects unknown parameters', () => {
    expect(parseCredentialListQuery({}).limit).toBe(50);
    expect(parseCredentialListQuery({ limit: '200' }).limit).toBe(200);
    for (const bad of [{ limit: '201' }, { limit: '0' }, { limit: '-1' }, { limit: 'x' }, { status: 'active' }, { status: 'NOPE' },
      { type: 'lower' }, { q: 'x'.repeat(101) }, { q: 'a\u0000b' }, { cursor: '!!' }, { cursor: 'abcd' }, { institutionId: 'x' }, { q: ['a', 'b'] }]) {
      expect(() => parseCredentialListQuery(bad)).toThrow();
    }
    expect(parseCredentialListQuery({ q: '  ada  ' }).q).toBe('ada');
    expect(parseCredentialListQuery({ q: '   ' }).q).toBeUndefined();
    expect(() => parseAuditListQuery({ cursor: Buffer.from('0').toString('base64url') })).toThrow();
    expect(() => parseAuditListQuery({ status: 'x' })).toThrow();
    expect(parseAuditListQuery({ cursor: Buffer.from('12').toString('base64url') }).before).toBe('12');
  });
});

describe.skipIf(!url)('credential queries (needs Postgres)', () => {
  const schema = `t027_${randomBytes(4).toString('hex')}`;
  const master = randomBytes(32);
  let owner: pg.Client;
  let db: Db;
  let app: FastifyInstance;
  let a: Client;
  let b: Client;

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
  const post = (c: Client, path: string, body: unknown) =>
    app.inject({ method: 'POST', url: `/api/v1${path}`, headers: { ...c.headers, ...json }, payload: body as Record<string, unknown> });
  const get = (c: Client | null, path: string) => app.inject({ method: 'GET', url: `/api/v1${path}`, headers: c?.headers ?? {} });
  const issue = async (c: Client, holderId: string, extra: Record<string, unknown> = {}, type = 'STUDENT_ID') => {
    const res = await post(c, '/credentials', { holderId, credentialTypeCode: type, attributes: { program: 'Computer Science' }, ...extra });
    expect(res.statusCode).toBe(201);
    return res.json() as Issued;
  };

  const issued: Issued[] = [];
  let expired: Issued;
  let suspended: Issued;
  let revoked: Issued;
  let certA: Issued;
  let foreign: Issued;

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
      await ownerQuery(`INSERT INTO institutions (id, name, slug, updated_at) VALUES ($1,$2,$3,now())`, [id, `Inst ${slug}`, slug]);
      const k = generateSigningKey(master);
      await ownerQuery(
        `INSERT INTO institution_keys (id, institution_id, kid, algorithm, public_key, encrypted_private_key, status)
         VALUES (gen_random_uuid(), $1, $2, 'Ed25519', $3, $4, 'ACTIVE')`,
        [id, k.kid, k.publicKey, k.encryptedPrivateKey],
      );
      for (const [code, name, kind] of [['STUDENT_ID', 'Student ID', 'ID_CARD'], ['CERT', 'Certificate', 'CERTIFICATE']] as const) {
        await ownerQuery(
          `INSERT INTO credential_types (id, institution_id, code, name, kind, attribute_schema, validity_days, updated_at)
           VALUES (gen_random_uuid(), $1, $2, $3, $4::credential_kind, $5::jsonb, 365, now())`,
          [id, code, name, kind, JSON.stringify([{ key: 'program', label: 'Programme', type: 'string', required: true }])],
        );
      }
    }
    for (const [id, inst, email] of [[U_A, INST_A, 'a@example.test'], [U_B, INST_B, 'b@example.test']] as const) {
      await ownerQuery(
        `INSERT INTO users (id, institution_id, email, name, password_hash, role, status, updated_at)
         VALUES ($1,$2,$3,'Name',$4,'INSTITUTION_ADMIN','ACTIVE',now())`,
        [id, inst, email, pwHash],
      );
    }
    for (const [id, inst, name] of [[H_A1, INST_A, 'Ada Lovelace'], [H_A2, INST_A, 'Grace Hopper'], [H_B, INST_B, 'Bob Builder']] as const) {
      await ownerQuery(
        `INSERT INTO credential_holders (id, institution_id, full_name, external_id, photo_key, photo_sha256, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,now())`,
        [id, inst, name, `ext-${name}`, `institutions/${inst}/holders/${id}/photo/${PHOTO_SHA}.png`, PHOTO_SHA],
      );
    }

    db = new Db({ connectionString: url!, max: 8, poolConfig: { options: `-c search_path=${schema} -c role=igaro_app` } });
    app = await buildApp({ config: { logLevel: 'silent', rateLimit, masterKey: master }, db, storage: new MemoryObjectStorage() });
    a = await loginAs('a@example.test');
    b = await loginAs('b@example.test');

    for (let i = 0; i < 3; i++) issued.push(await issue(a, H_A1));
    expired = await issue(a, H_A2, { expiresAt: new Date(Date.now() + 1500).toISOString().slice(0, 19) + 'Z' });
    suspended = await issue(a, H_A2);
    revoked = await issue(a, H_A1);
    certA = await issue(a, H_A2, {}, 'CERT');
    foreign = await issue(b, H_B);
    expect((await post(a, `/credentials/${suspended.id}/suspend`, { reason: 'check' })).statusCode).toBe(200);
    expect((await post(a, `/credentials/${revoked.id}/revoke`, { reason: 'error' })).statusCode).toBe(200);
    await sleep(2600); // let `expired` pass its expiry
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

  it('requires an Institution Admin session', async () => {
    for (const p of ['/credentials', `/credentials/${issued[0]!.id}`, '/dashboard/stats', '/audit-logs', '/audit-logs/verify-chain']) {
      expect((await get(null, p)).statusCode).toBe(401);
    }
  });

  it('lists only the session tenant, newest first, with computed status', async () => {
    const res = await get(a, '/credentials?limit=200');
    expect(res.statusCode).toBe(200);
    const body = res.json() as { items: { id: string; status: string; credentialNumber: string }[]; nextCursor: string | null };
    expect(body.nextCursor).toBeNull();
    expect(body.items).toHaveLength(7);
    expect(body.items.map((i) => i.id)).not.toContain(foreign.id);
    expect(body.items.find((i) => i.id === expired.id)!.status).toBe('EXPIRED');
    expect(body.items.find((i) => i.id === suspended.id)!.status).toBe('SUSPENDED');
    expect(body.items[0]!.id).toBe(certA.id);
    const fb = (await get(b, '/credentials')).json() as { items: { id: string }[] };
    expect(fb.items.map((i) => i.id)).toEqual([foreign.id]);
  });

  it('filters by status (EXPIRED computed, ACTIVE excludes expired), type and q', async () => {
    const ids = async (qs: string) => ((await get(a, `/credentials?${qs}`)).json() as { items: { id: string }[] }).items.map((i) => i.id).sort();
    expect(await ids('status=EXPIRED')).toEqual([expired.id]);
    expect(await ids('status=ACTIVE')).toEqual([...issued.map((i) => i.id), certA.id].sort());
    expect(await ids('status=SUSPENDED')).toEqual([suspended.id]);
    expect(await ids('status=REVOKED')).toEqual([revoked.id]);
    expect(await ids('status=SUPERSEDED')).toEqual([]);
    expect(await ids('type=CERT')).toEqual([certA.id]);
    expect(await ids('type=NOPE')).toEqual([]);
    expect(await ids('status=ACTIVE&type=CERT')).toEqual([certA.id]);
    // q: holder name, case-insensitive substring
    expect(await ids('q=GRACE')).toEqual([expired.id, suspended.id, certA.id].sort());
    expect(await ids('q=lovelace&status=REVOKED')).toEqual([revoked.id]);
    // q: credential number (case-insensitive substring)
    expect(await ids(`q=${encodeURIComponent(issued[0]!.credentialNumber)}`)).toEqual([issued[0]!.id]);
    // LIKE wildcards are literal
    expect(await ids('q=%25')).toEqual([]);
    expect(await ids('q=_')).toEqual([]);
    expect(await ids('q=Bob')).toEqual([]); // other tenant's holder
  });

  it('paginates with an opaque cursor and caps the limit', async () => {
    const seen: string[] = [];
    let cursor: string | null = null;
    let pages = 0;
    do {
      const res = await get(a, `/credentials?limit=3${cursor ? `&cursor=${cursor}` : ''}`);
      expect(res.statusCode).toBe(200);
      const body = res.json() as { items: { id: string }[]; nextCursor: string | null };
      expect(body.items.length).toBeLessThanOrEqual(3);
      seen.push(...body.items.map((i) => i.id));
      cursor = body.nextCursor;
      pages++;
    } while (cursor);
    expect(pages).toBe(3);
    expect(new Set(seen).size).toBe(7);
    expect((await get(a, '/credentials?limit=201')).statusCode).toBe(400);
    expect((await get(a, '/credentials?limit=0')).statusCode).toBe(400);
    expect((await get(a, '/credentials?cursor=garbage!')).statusCode).toBe(400);
    expect((await get(a, '/credentials?institutionId=' + INST_B)).json().error.code).toBe('UNKNOWN_PROPERTY');
    expect((await get(a, '/credentials?status=bogus')).statusCode).toBe(400);
  });

  it('returns the credential with its events and computed status', async () => {
    const res = await get(a, `/credentials/${suspended.id}`);
    expect(res.statusCode).toBe(200);
    const c = res.json();
    expect(c).toMatchObject({ id: suspended.id, status: 'SUSPENDED', storedStatus: 'SUSPENDED', holder: { fullName: 'Grace Hopper' }, type: { code: 'STUDENT_ID' } });
    expect(c.attributes).toEqual({ program: 'Computer Science' });
    expect(c.events.map((e: { type: string }) => e.type)).toEqual(['ISSUED', 'SUSPENDED']);
    const e = (await get(a, `/credentials/${expired.id}`)).json();
    expect(e).toMatchObject({ status: 'EXPIRED', storedStatus: 'ACTIVE' });
  });

  it('returns 404 for another tenant, unknown and malformed ids (same body)', async () => {
    const bodies = new Set<string>();
    for (const id of [foreign.id, MISSING, 'not-a-uuid']) {
      const res = await get(a, `/credentials/${id}`);
      expect(res.statusCode).toBe(404);
      bodies.add(res.body);
    }
    expect(bodies.size).toBe(1);
    expect((await get(b, `/credentials/${issued[0]!.id}`)).statusCode).toBe(404);
    expect((await get(b, `/credentials/${foreign.id}`)).statusCode).toBe(200);
  });

  it('never returns verification tokens, holder tokens, token hashes or the salt', async () => {
    const all = [issued[0]!, expired, suspended, revoked, certA];
    const bodies = [(await get(a, '/credentials?limit=200')).body, ...(await Promise.all(all.map(async (c) => (await get(a, `/credentials/${c.id}`)).body)))];
    const hashes = (await ownerQuery(`SELECT holder_token_hash FROM credentials WHERE institution_id = $1`, [INST_A])).rows.map((r) => r.holder_token_hash as string);
    for (const body of bodies) {
      for (const c of all) {
        expect(body).not.toContain(c.verificationToken);
        expect(body).not.toContain(c.holderToken);
        expect(body).not.toContain(c.payload.salt);
      }
      for (const h of hashes) expect(body).not.toContain(h);
      expect(body).not.toMatch(/verificationToken|holderToken|holderTokenHash|"salt"|photoKey/i);
    }
    const stats = (await get(a, '/dashboard/stats')).body + (await get(a, '/audit-logs?limit=200')).body;
    for (const c of all) {
      expect(stats).not.toContain(c.verificationToken);
      expect(stats).not.toContain(c.holderToken);
      expect(stats).not.toContain(c.payload.salt);
    }
  });

  it('counts by status including computed EXPIRED, per tenant', async () => {
    const s = (await get(a, '/dashboard/stats')).json();
    expect(s).toEqual({ total: 7, byStatus: { DRAFT: 0, ACTIVE: 4, SUSPENDED: 1, REVOKED: 1, SUPERSEDED: 0, EXPIRED: 1 } });
    const sb = (await get(b, '/dashboard/stats')).json();
    expect(sb.total).toBe(1);
    expect(sb.byStatus.ACTIVE).toBe(1);
  });

  it('lists the tenant audit log newest first with a cursor and no foreign entries', async () => {
    const first = (await get(a, '/audit-logs?limit=5')).json() as { items: { seq: string; action: string; metadata: unknown }[]; nextCursor: string | null };
    expect(first.items).toHaveLength(5);
    expect(first.nextCursor).not.toBeNull();
    expect(Number(first.items[0]!.seq)).toBeGreaterThan(Number(first.items[4]!.seq));
    expect(first.items[0]!.action).toBe('credential.revoked');
    const rest = (await get(a, `/audit-logs?limit=200&cursor=${first.nextCursor}`)).json() as { items: { seq: string }[]; nextCursor: string | null };
    expect(rest.nextCursor).toBeNull();
    expect(Number(rest.items[0]!.seq)).toBeLessThan(Number(first.items[4]!.seq));
    const mine = (await ownerQuery(`SELECT count(*)::int AS n FROM audit_logs WHERE institution_id = $1`, [INST_A])).rows[0].n;
    expect(first.items.length + rest.items.length).toBe(mine);
    const raw = JSON.stringify([first, rest]);
    expect(raw).not.toContain(foreign.id);
    expect(raw).not.toMatch(/"ip"/);
    expect((await get(a, '/audit-logs?limit=1000')).statusCode).toBe(400);
  });

  it('verify-chain: valid chain without signed heads reports headsRecorded:false', async () => {
    const v = (await get(a, '/audit-logs/verify-chain')).json();
    expect(v).toMatchObject({ valid: true, headsRecorded: false, signedHeads: { checked: 0, matched: 0, mismatchedDays: [] } });
    expect(v.entries).toBeGreaterThan(0);
    expect(v.head).toMatch(/^[0-9a-f]{64}$/);
  });

  it('verify-chain: matches a signed head, then detects tampering and a head the chain no longer contains', async () => {
    const heads = (await ownerQuery(`SELECT entry_hash, seq FROM audit_logs WHERE institution_id = $1 ORDER BY seq DESC LIMIT 1`, [INST_A])).rows[0];
    await ownerQuery(
      `INSERT INTO audit_head_hashes (id, institution_id, day, head_hash, signature, signer_kid) VALUES (gen_random_uuid(), $1, '2026-11-24', $2, 'sig', 'kid')`,
      [INST_A, heads.entry_hash],
    );
    const ok = (await get(a, '/audit-logs/verify-chain')).json();
    expect(ok).toMatchObject({ valid: true, headsRecorded: true, signedHeads: { checked: 1, matched: 1, mismatchedDays: [] } });

    // A bogus signed head (e.g. the chain was rewritten after it was signed) is reported.
    await ownerQuery(
      `INSERT INTO audit_head_hashes (id, institution_id, day, head_hash, signature, signer_kid) VALUES (gen_random_uuid(), $1, '2026-11-23', $2, 'sig', 'kid')`,
      [INST_A, 'f'.repeat(64)],
    );
    const bad = (await get(a, '/audit-logs/verify-chain')).json();
    expect(bad).toMatchObject({ valid: false, headsRecorded: false, signedHeads: { checked: 2, matched: 1, mismatchedDays: ['2026-11-23'] } });

    // Tamper with one entry in place (the owner bypasses the append-only trigger, as a DB-level attacker would).
    const target = (await ownerQuery(`SELECT seq FROM audit_logs WHERE institution_id = $1 ORDER BY seq OFFSET 2 LIMIT 1`, [INST_A])).rows[0].seq as string;
    await owner.query('BEGIN');
    await owner.query(`ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_no_update_trg`);
    await owner.query(`SELECT set_config('app.is_platform_admin','true',true)`);
    await owner.query(`UPDATE audit_logs SET action = 'credential.forged' WHERE institution_id = $1 AND seq = $2`, [INST_A, target]);
    await owner.query(`ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_no_update_trg`);
    await owner.query('COMMIT');
    const t = (await get(a, '/audit-logs/verify-chain')).json();
    expect(t).toMatchObject({ valid: false, brokenAtSeq: target, reason: 'HASH_MISMATCH' });
    expect(t.head).toBeUndefined();
    // The other tenant's chain is unaffected and independent.
    expect((await get(b, '/audit-logs/verify-chain')).json()).toMatchObject({ valid: true, headsRecorded: false });
  });
});
