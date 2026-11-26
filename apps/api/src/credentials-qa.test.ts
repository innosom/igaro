// T-029 QA suite for credentials (white paper section 15; CLAUDE.md invariants 1, 4, 5, 6).
// Complements credential-lifecycle / credentials / audit / cross-tenant tests rather than repeating them:
//   Q1 tamper         -> stored payload / data_hash / signature edited as superuser; core recomputation must fail
//   Q2 lifecycle      -> full status x action matrix through the API, status only via credential_events
//   Q3 REVOKED final  -> DB trigger refuses every change and DELETE even through raw SQL; no DELETE for anyone
//   Q4 audit chain    -> edit, delete, recompute-all-later, forged / wrong heads; app role is append-only
//   Q5 cross-tenant   -> every credential endpoint 404 / empty for tenant B, and raw SQL under B's scope sees nothing
// Needs Postgres ($DATABASE_URL), scratch schema, API role igaro_app (RLS on). Test values only.
import { createHash, randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { Writable } from 'node:stream';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import type { FastifyInstance } from 'fastify';
import {
  canTransition,
  computeDataHash,
  computeEntryHash,
  generateSigningKey,
  signAuditHead,
  unwrapPrivateKey,
  verifyCredentialIntegrity,
  type ChainedEntry,
  type CredentialPayloadV1,
  type CredentialStatus,
  type LifecycleAction,
} from '@igaro/core';
import { verifyAuditChain } from './audit.js';
import { buildApp } from './app.js';
import { csrfTokenFor, hashPassword } from './auth.js';
import { Db } from './db.js';
import { MemoryObjectStorage } from './storage.js';

const url = process.env.DATABASE_URL;
const migrationsDir = new URL('../../../packages/db/prisma/migrations/', import.meta.url);

const PW = 'correct horse battery staple';
const json = { 'content-type': 'application/json' };
const BIG = { ipMax: 10000, accountMax: 10000, windowSeconds: 900 };
const rateLimit = { login: BIG, reset: BIG, token: { ipMax: 10000, windowSeconds: 900 } };
const PHOTO_SHA = createHash('sha256').update('photo-qa').digest('hex');
const MISSING = '99999999-9999-4999-8999-999999999999';
const NOT_FOUND = { error: { code: 'NOT_FOUND', message: 'Not found' } };
const DAY = '2026-11-26';

// Fixed ids per tenant: A and B for tamper/lifecycle/cross-tenant, C..F each get a private audit chain.
const T = ['A', 'B', 'C', 'D', 'E', 'F'] as const;
type Tag = (typeof T)[number];
const idOf = (i: number, p: string) => `${p.repeat(8)}-${p.repeat(4)}-4${p.repeat(3)}-8${p.repeat(3)}-${String(i + 1).repeat(12)}`;
const INST = Object.fromEntries(T.map((t, i) => [t, idOf(i, '1')])) as Record<Tag, string>;
const USER = Object.fromEntries(T.map((t, i) => [t, idOf(i, 'a')])) as Record<Tag, string>;
const HOLDER = Object.fromEntries(T.map((t, i) => [t, idOf(i, 'b')])) as Record<Tag, string>;

interface Client {
  headers: Record<string, string>;
}
interface Issued {
  id: string;
  credentialNumber: string;
  dataHash: string;
  signature: string;
  payload: CredentialPayloadV1;
  verificationToken: string;
}

describe.skipIf(!url)('T-029 credentials QA (needs Postgres)', () => {
  const schema = `t029_${randomBytes(4).toString('hex')}`;
  const master = randomBytes(32);
  const headKey = generateSigningKey(master);
  const headPriv = unwrapPrivateKey(headKey.encryptedPrivateKey, master, headKey.kid);
  const otherKey = generateSigningKey(master);
  const otherPriv = unwrapPrivateKey(otherKey.encryptedPrivateKey, master, otherKey.kid);
  let owner: pg.Client;
  let db: Db;
  let app: FastifyInstance;
  const client = {} as Record<Tag, Client>;
  const pub = {} as Record<Tag, string>;
  const logs: string[] = [];

  /** Owner (table owner, platform scope). `bypass` disables user triggers = what a DB superuser could do. */
  const ownerTx = async <R>(fn: (c: pg.Client) => Promise<R>, opts: { bypass?: boolean; commit?: boolean } = {}): Promise<R> => {
    const commit = opts.commit ?? true;
    await owner.query('BEGIN');
    try {
      await owner.query(`SELECT set_config('app.is_platform_admin','true',true)`);
      if (opts.bypass) for (const t of ['credentials', 'credential_events', 'audit_logs', 'audit_head_hashes']) await owner.query(`ALTER TABLE ${t} DISABLE TRIGGER USER`);
      const out = await fn(owner);
      if (opts.bypass) for (const t of ['credentials', 'credential_events', 'audit_logs', 'audit_head_hashes']) await owner.query(`ALTER TABLE ${t} ENABLE TRIGGER USER`);
      await owner.query(commit ? 'COMMIT' : 'ROLLBACK');
      return out;
    } catch (e) {
      await owner.query('ROLLBACK');
      throw e;
    }
  };
  const q = async (sql: string, params: unknown[] = []) => (await ownerTx((c) => c.query(sql, params))).rows;
  const ten = (t: Tag) => ({ kind: 'tenant' as const, userId: USER[t], institutionId: INST[t] });

  const login = async (email: string): Promise<Client> => {
    const res = await app.inject({ method: 'POST', url: '/api/v1/auth/login', headers: json, payload: { email, password: PW } });
    expect(res.statusCode).toBe(200);
    const cookie = String(res.headers['set-cookie']).split(';')[0]!;
    return { headers: { cookie, 'x-csrf-token': csrfTokenFor(cookie.slice(cookie.indexOf('=') + 1)) } };
  };
  const call = (c: Client, method: 'GET' | 'POST', path: string, body?: unknown) =>
    app.inject({
      method,
      url: `/api/v1${path}`,
      headers: { ...c.headers, ...(body === undefined ? {} : json) },
      ...(body === undefined ? {} : { payload: body as Record<string, unknown> }),
    });
  const issue = async (t: Tag, attributes: Record<string, string> = { program: 'Computer Science' }): Promise<Issued> => {
    const res = await call(client[t], 'POST', '/credentials', { holderId: HOLDER[t], credentialTypeCode: 'STUDENT_ID', attributes });
    expect(res.statusCode).toBe(201);
    return res.json() as Issued;
  };
  const stored = async (id: string) =>
    (await q(`SELECT status::text AS status, superseded_by, payload, data_hash, signature FROM credentials WHERE id = $1`, [id]))[0]!;
  const eventTypes = async (id: string) =>
    (await q(`SELECT type::text AS type FROM credential_events WHERE credential_id = $1 ORDER BY seq`, [id])).map((r) => r.type as string);

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
    for (const t of T) {
      const k = generateSigningKey(master);
      pub[t] = k.publicKey;
      await q(`INSERT INTO institutions (id, name, slug, updated_at) VALUES ($1,$2,$3,now())`, [INST[t], `Inst ${t}`, `inst-${t.toLowerCase()}`]);
      await q(
        `INSERT INTO institution_keys (id, institution_id, kid, algorithm, public_key, encrypted_private_key, status)
         VALUES (gen_random_uuid(), $1, $2, 'Ed25519', $3, $4, 'ACTIVE')`,
        [INST[t], k.kid, k.publicKey, k.encryptedPrivateKey],
      );
      await q(
        `INSERT INTO credential_types (id, institution_id, code, name, kind, attribute_schema, validity_days, updated_at)
         VALUES (gen_random_uuid(), $1, 'STUDENT_ID', 'Student ID', 'ID_CARD', $2::jsonb, 365, now())`,
        [INST[t], JSON.stringify([{ key: 'program', label: 'Programme', type: 'string', required: true }])],
      );
      await q(
        `INSERT INTO users (id, institution_id, email, name, password_hash, role, status, updated_at)
         VALUES ($1,$2,$3,'Name',$4,'INSTITUTION_ADMIN','ACTIVE',now())`,
        [USER[t], INST[t], `${t.toLowerCase()}@example.test`, pwHash],
      );
      await q(
        `INSERT INTO credential_holders (id, institution_id, full_name, external_id, photo_key, photo_sha256, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,now())`,
        [HOLDER[t], INST[t], `Holder ${t}`, `ext-${t}`, `institutions/${INST[t]}/holders/${HOLDER[t]}/photo/${PHOTO_SHA}.png`, PHOTO_SHA],
      );
    }

    db = new Db({ connectionString: url!, max: 8, poolConfig: { options: `-c search_path=${schema} -c role=igaro_app` } });
    const logStream = new Writable({
      write(c, _e, cb) {
        logs.push(String(c));
        cb();
      },
    });
    app = await buildApp({
      config: { logLevel: 'debug', rateLimit, masterKey: master, auditHeadPublicKeys: { [headKey.kid]: headKey.publicKey } },
      db,
      storage: new MemoryObjectStorage(),
      logStream,
    });
    for (const t of T) client[t] = await login(`${t.toLowerCase()}@example.test`);
  }, 120000);

  afterAll(async () => {
    await app?.close();
    await db?.close();
    if (!owner) return;
    await owner.query('ROLLBACK').catch(() => undefined);
    await owner.query('RESET search_path');
    await owner.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    await owner.end();
  });

  // ---------------------------------------------------------------------------------------------
  describe('Q1 tamper: stored signed data edited as superuser is caught by core recomputation (section 15 integrity)', () => {
    /** Apply `sql` to credential `id` as superuser (user triggers off), re-read the row, roll the change back. */
    const tampered = async (id: string, sql: string, params: unknown[]) =>
      ownerTx(
        async (c) => {
          await c.query(sql, [id, ...params]);
          return (await c.query(`SELECT payload, data_hash, signature FROM credentials WHERE id = $1`, [id])).rows[0] as {
            payload: unknown;
            data_hash: string;
            signature: string;
          };
        },
        { bypass: true, commit: false },
      );
    const integrity = (r: { payload: unknown; data_hash: string; signature: string }, key = pub.A) =>
      verifyCredentialIntegrity(r.payload, r.data_hash, r.signature, key);

    it('baseline: the issued row verifies; the API returned exactly what the DB stores', async () => {
      const c = await issue('A');
      const row = await stored(c.id);
      expect(integrity(row as never)).toBe('OK');
      expect(row.data_hash).toBe(c.dataHash);
      expect(computeDataHash(row.payload as CredentialPayloadV1)).toBe(c.dataHash);
    });

    const payloadEdits: [string, string, unknown[]][] = [
      ['attribute value', `UPDATE credentials SET payload = jsonb_set(payload, '{attributes,program}', '"Forged"') WHERE id = $1`, []],
      ['holder name', `UPDATE credentials SET payload = jsonb_set(payload, '{holder,fullName}', '"Mallory"') WHERE id = $1`, []],
      ['photo hash', `UPDATE credentials SET payload = jsonb_set(payload, '{holder,photoSha256}', to_jsonb($2::text)) WHERE id = $1`, ['f'.repeat(64)]],
      ['credential number', `UPDATE credentials SET payload = jsonb_set(payload, '{credentialNumber}', '"A-999999"') WHERE id = $1`, []],
      ['issuer key id', `UPDATE credentials SET payload = jsonb_set(payload, '{issuerKeyId}', '"kid_00000000000000ff"') WHERE id = $1`, []],
      ['expiry', `UPDATE credentials SET payload = jsonb_set(payload, '{expiresAt}', '"2099-01-01T00:00:00Z"') WHERE id = $1`, []],
      ['salt', `UPDATE credentials SET payload = jsonb_set(payload, '{salt}', to_jsonb($2::text)) WHERE id = $1`, ['A'.repeat(43)]],
      ['extra field', `UPDATE credentials SET payload = payload || '{"admin":true}'::jsonb WHERE id = $1`, []],
      ['removed field', `UPDATE credentials SET payload = payload - 'salt' WHERE id = $1`, []],
    ];
    for (const [name, sql, params] of payloadEdits) {
      it(`payload ${name} edited -> HASH_MISMATCH`, async () => {
        const c = await issue('A');
        const row = await tampered(c.id, sql, params);
        expect(integrity(row)).toBe('HASH_MISMATCH');
      });
    }

    it('attacker recomputes data_hash for the edited payload -> SIGNATURE_INVALID (cannot re-sign)', async () => {
      const c = await issue('A');
      const row = await ownerTx(
        async (cl) => {
          await cl.query(`UPDATE credentials SET payload = jsonb_set(payload, '{attributes,program}', '"Forged"') WHERE id = $1`, [c.id]);
          const r = (await cl.query(`SELECT payload FROM credentials WHERE id = $1`, [c.id])).rows[0];
          await cl.query(`UPDATE credentials SET data_hash = $2 WHERE id = $1`, [c.id, computeDataHash(r.payload)]);
          return (await cl.query(`SELECT payload, data_hash, signature FROM credentials WHERE id = $1`, [c.id])).rows[0];
        },
        { bypass: true, commit: false },
      );
      expect(integrity(row)).toBe('SIGNATURE_INVALID');
    });

    it('data_hash edited alone -> HASH_MISMATCH (stored hash is never trusted)', async () => {
      const c = await issue('A');
      const row = await tampered(c.id, `UPDATE credentials SET data_hash = $2 WHERE id = $1`, ['0'.repeat(64)]);
      expect(integrity(row)).toBe('HASH_MISMATCH');
    });

    it('signature edited (flipped char, swapped from another credential, truncated, empty) -> SIGNATURE_INVALID', async () => {
      const c = await issue('A');
      const other = await issue('A', { program: 'Other' });
      const flip = c.signature.startsWith('A') ? `B${c.signature.slice(1)}` : `A${c.signature.slice(1)}`;
      for (const sig of [flip, other.signature, c.signature.slice(0, -2), '']) {
        const row = await tampered(c.id, `UPDATE credentials SET signature = $2 WHERE id = $1`, [sig]);
        expect(integrity(row), sig.slice(0, 6)).toBe('SIGNATURE_INVALID');
      }
    });

    it("a credential never verifies under another institution's key, and cross-institution payload swap fails", async () => {
      const c = await issue('A');
      const row = await stored(c.id);
      expect(integrity(row as never, pub.B)).toBe('SIGNATURE_INVALID');
      expect(verifyCredentialIntegrity({ ...(row.payload as object), institutionId: INST.B }, c.dataHash, c.signature, pub.A)).toBe('HASH_MISMATCH');
    });

    it('the same edits are refused by the DB for everyone not bypassing triggers (owner and igaro_app)', async () => {
      const c = await issue('A');
      const before = await stored(c.id);
      for (const col of ['payload', 'data_hash', 'signature', 'issuer_kid']) {
        const set = col === 'payload' ? `payload = payload || '{"x":1}'::jsonb` : `${col} = 'zzz'`;
        await expect(ownerTx((cl) => cl.query(`UPDATE credentials SET ${set} WHERE id = $1`, [c.id])), `owner ${col}`).rejects.toThrow(/immutable/);
        await expect(db.withTenant(ten('A'), (cl) => cl.query(`UPDATE credentials SET ${set} WHERE id = $1`, [c.id])), `app ${col}`).rejects.toThrow(/immutable|permission denied/);
      }
      expect(await stored(c.id)).toEqual(before);
    });
  });

  // ---------------------------------------------------------------------------------------------
  describe('Q2 lifecycle: every allowed and forbidden transition through the API (section 15 lifecycle)', () => {
    type Action = 'suspend' | 'reinstate' | 'revoke' | 'reissue';
    const coreAction: Record<Exclude<Action, 'reissue'>, LifecycleAction> = { suspend: 'SUSPEND', reinstate: 'REINSTATE', revoke: 'REVOKE' };
    const act = (id: string, a: Action) =>
      call(client.A, 'POST', `/credentials/${id}/${a}`, a === 'reinstate' ? undefined : { reason: `qa ${a}` });
    const inState = async (s: CredentialStatus): Promise<string> => {
      const c = await issue('A');
      if (s === 'SUSPENDED') expect((await act(c.id, 'suspend')).statusCode).toBe(200);
      if (s === 'REVOKED') expect((await act(c.id, 'revoke')).statusCode).toBe(200);
      if (s === 'SUPERSEDED') expect((await act(c.id, 'reissue')).statusCode).toBe(201);
      expect((await stored(c.id)).status).toBe(s);
      return c.id;
    };

    // Expected API outcome per (current status, action): the core table, plus reissue (ACTIVE, or REVOKED once; ADR 0017).
    const matrix: Record<string, Record<Action, number>> = {
      ACTIVE: { suspend: 200, reinstate: 409, revoke: 200, reissue: 201 },
      SUSPENDED: { suspend: 409, reinstate: 200, revoke: 409, reissue: 409 },
      REVOKED: { suspend: 409, reinstate: 409, revoke: 409, reissue: 201 },
      SUPERSEDED: { suspend: 409, reinstate: 409, revoke: 409, reissue: 409 },
    };
    const target: Record<string, Partial<Record<Action, string>>> = {
      ACTIVE: { suspend: 'SUSPENDED', revoke: 'REVOKED', reissue: 'SUPERSEDED' },
      SUSPENDED: { reinstate: 'ACTIVE' },
      REVOKED: { reissue: 'REVOKED' }, // old stays REVOKED; the new credential is ACTIVE
    };

    for (const from of Object.keys(matrix) as CredentialStatus[]) {
      for (const action of ['suspend', 'reinstate', 'revoke', 'reissue'] as Action[]) {
        const want = matrix[from]![action];
        it(`${from} + ${action} -> ${want}`, async () => {
          const id = await inState(from);
          const evBefore = await eventTypes(id);
          const res = await act(id, action);
          expect(res.statusCode).toBe(want);
          if (action !== 'reissue') expect(canTransition(from, coreAction[action])).toBe(want === 200);
          if (want === 409) {
            expect(res.json().error.code).toBe('INVALID_TRANSITION');
            expect(await eventTypes(id)).toEqual(evBefore);
            expect((await stored(id)).status).toBe(from);
          } else {
            expect((await stored(id)).status).toBe(target[from]![action]);
            // A reissue of a REVOKED credential leaves the old row (and its events) untouched; the new credential gets ISSUED.
            expect((await eventTypes(id)).length).toBe(evBefore.length + (from === 'REVOKED' ? 0 : 1));
          }
        });
      }
    }

    it('reason is required for suspend and revoke (400, nothing changes); reinstate needs none', async () => {
      const id = await inState('ACTIVE');
      for (const a of ['suspend', 'revoke'] as const) {
        for (const body of [undefined, {}, { reason: '' }, { reason: '  ' }]) {
          expect((await call(client.A, 'POST', `/credentials/${id}/${a}`, body)).statusCode, `${a} ${JSON.stringify(body)}`).toBe(400);
        }
      }
      expect(await eventTypes(id)).toEqual(['ISSUED']);
      await call(client.A, 'POST', `/credentials/${id}/suspend`, { reason: 'because' });
      expect((await call(client.A, 'POST', `/credentials/${id}/reinstate`)).statusCode).toBe(200);
    });

    it('reissue links the old credential SUPERSEDED to a new ACTIVE one that verifies; reinstate on it is 409', async () => {
      const old = await issue('A');
      const res = await act(old.id, 'reissue');
      const n = res.json().credential as Issued;
      const row = await stored(old.id);
      expect(row).toMatchObject({ status: 'SUPERSEDED', superseded_by: n.id });
      expect(verifyCredentialIntegrity(n.payload, n.dataHash, n.signature, pub.A)).toBe('OK');
      expect((await act(old.id, 'reinstate')).statusCode).toBe(409);
      const detail = (await call(client.A, 'GET', `/credentials/${old.id}`)).json();
      expect(detail).toMatchObject({ status: 'SUPERSEDED', supersededBy: n.id });
    });

    it('status changes only through credential_events: raw status UPDATE without an event is refused', async () => {
      const id = await inState('ACTIVE');
      await expect(ownerTx((c) => c.query(`UPDATE credentials SET status = 'SUSPENDED' WHERE id = $1`, [id]))).rejects.toThrow(/requires a SUSPENDED credential_events row/);
      await expect(db.withTenant(ten('A'), (c) => c.query(`UPDATE credentials SET status = 'REVOKED' WHERE id = $1`, [id]))).rejects.toThrow(/requires a REVOKED credential_events row/);
      // Forbidden jumps are refused even with an event.
      await expect(
        ownerTx(async (c) => {
          await c.query(`INSERT INTO credential_events (id, institution_id, credential_id, type) VALUES (gen_random_uuid(),$1,$2,'REINSTATED')`, [INST.A, id]);
          await c.query(`UPDATE credentials SET status = 'DRAFT' WHERE id = $1`, [id]);
        }),
      ).rejects.toThrow(/not allowed/);
      // An event that does not match a status change is refused at commit.
      await expect(
        ownerTx((c) => c.query(`INSERT INTO credential_events (id, institution_id, credential_id, type) VALUES (gen_random_uuid(),$1,$2,'SUSPENDED')`, [INST.A, id])),
      ).rejects.toThrow(/not backed by a matching status change/);
      expect((await stored(id)).status).toBe('ACTIVE');
      expect(await eventTypes(id)).toEqual(['ISSUED']);
    });

    it('events are append-only (no UPDATE of type, no DELETE) and replaying them reproduces every stored status', async () => {
      const id = await inState('SUSPENDED');
      await expect(ownerTx((c) => c.query(`UPDATE credential_events SET type = 'REINSTATED' WHERE credential_id = $1`, [id]))).rejects.toThrow(/append-only/);
      await expect(ownerTx((c) => c.query(`DELETE FROM credential_events WHERE credential_id = $1`, [id]))).rejects.toThrow();
      await expect(db.withTenant(ten('A'), (c) => c.query(`DELETE FROM credential_events WHERE credential_id = $1`, [id]))).rejects.toThrow();
      const next: Record<string, string> = { SUSPENDED: 'SUSPENDED', REINSTATED: 'ACTIVE', REVOKED: 'REVOKED', REISSUED: 'SUPERSEDED', ISSUED: 'ACTIVE' };
      const rows = await q(
        `SELECT c.id, c.status::text AS status, array_agg(e.type::text ORDER BY e.seq) AS evs
           FROM credentials c JOIN credential_events e ON e.credential_id = c.id WHERE c.institution_id = $1 GROUP BY c.id, c.status`,
        [INST.A],
      );
      expect(rows.length).toBeGreaterThan(10);
      for (const r of rows) expect(next[(r.evs as string[]).at(-1)!], String(r.id)).toBe(r.status);
    });
  });

  // ---------------------------------------------------------------------------------------------
  describe('Q3 REVOKED is final and credentials are never deleted at DB level (section 15 revoked-final)', () => {
    it('every raw UPDATE of a REVOKED row is refused (owner and app role), including with a forged event', async () => {
      const c = await issue('A');
      expect((await call(client.A, 'POST', `/credentials/${c.id}/revoke`, { reason: 'qa' })).statusCode).toBe(200);
      const before = await stored(c.id);
      const attempts = [
        `UPDATE credentials SET status = 'ACTIVE' WHERE id = $1`,
        `UPDATE credentials SET status = 'SUSPENDED' WHERE id = $1`,
        `UPDATE credentials SET status = 'SUPERSEDED' WHERE id = $1`,
        `UPDATE credentials SET updated_at = now() WHERE id = $1`,
        `UPDATE credentials SET superseded_by = id WHERE id = $1`,
        `UPDATE credentials SET payload = payload || '{"x":1}'::jsonb WHERE id = $1`,
        `UPDATE credentials SET expires_at = now() + interval '10 years' WHERE id = $1`,
      ];
      for (const sql of attempts) {
        await expect(ownerTx((cl) => cl.query(sql, [c.id])), `owner: ${sql}`).rejects.toThrow(/REVOKED and cannot be changed/);
        await expect(db.withTenant(ten('A'), (cl) => cl.query(sql, [c.id])), `app: ${sql}`).rejects.toThrow(/REVOKED and cannot be changed|permission denied/);
      }
      // Forged REINSTATED/ISSUED event first does not help.
      for (const type of ['REINSTATED', 'ISSUED']) {
        await expect(
          ownerTx(async (cl) => {
            await cl.query(`INSERT INTO credential_events (id, institution_id, credential_id, type) VALUES (gen_random_uuid(),$1,$2,$3)`, [INST.A, c.id, type]);
            await cl.query(`UPDATE credentials SET status = 'ACTIVE' WHERE id = $1`, [c.id]);
          }),
        ).rejects.toThrow(/REVOKED and cannot be changed/);
      }
      expect(await stored(c.id)).toEqual(before);
      expect(await eventTypes(c.id)).toEqual(['ISSUED', 'REVOKED']);
      // API: still 409 for every action but reissue (which leaves the old row REVOKED, see lifecycle tests).
      for (const a of ['suspend', 'reinstate', 'revoke']) {
        expect((await call(client.A, 'POST', `/credentials/${c.id}/${a}`, a === 'reinstate' ? undefined : { reason: 'x' })).statusCode).toBe(409);
      }
      expect((await call(client.A, 'GET', `/credentials/${c.id}`)).json().status).toBe('REVOKED');
    });

    it('credentials cannot be DELETEd or TRUNCATEd by the owner or the app role, in any status', async () => {
      const active = await issue('A');
      const susp = await issue('A');
      await call(client.A, 'POST', `/credentials/${susp.id}/suspend`, { reason: 'qa' });
      const rev = await issue('A');
      await call(client.A, 'POST', `/credentials/${rev.id}/revoke`, { reason: 'qa' });
      const n = async () => (await q(`SELECT count(*)::int AS n FROM credentials`))[0]!.n as number;
      const before = await n();
      for (const id of [active.id, susp.id, rev.id]) {
        await expect(ownerTx((c) => c.query(`DELETE FROM credentials WHERE id = $1`, [id]))).rejects.toThrow();
        await expect(db.withTenant(ten('A'), (c) => c.query(`DELETE FROM credentials WHERE id = $1`, [id]))).rejects.toThrow();
      }
      await expect(ownerTx((c) => c.query(`DELETE FROM credentials`))).rejects.toThrow();
      await expect(ownerTx((c) => c.query(`TRUNCATE credentials CASCADE`))).rejects.toThrow();
      await expect(db.withTenant(ten('A'), (c) => c.query(`TRUNCATE credentials`))).rejects.toThrow();
      expect(await n()).toBe(before);
      // No credential DELETE route exists either.
      const res = await app.inject({ method: 'DELETE', url: `/api/v1/credentials/${active.id}`, headers: client.A.headers });
      expect([404, 405]).toContain(res.statusCode);
      expect((await stored(active.id)).status).toBe('ACTIVE');
    });
  });

  // ---------------------------------------------------------------------------------------------
  describe('Q4 audit chain: tamper detection with the signed daily head (section 15 audit)', () => {
    /** Generate chain entries for a tenant through the real API: one issue + one suspend per call. */
    const generate = async (t: Tag, n = 3) => {
      for (let i = 0; i < n; i++) {
        const c = await issue(t);
        await call(client[t], 'POST', `/credentials/${c.id}/suspend`, { reason: `qa ${i}` });
      }
    };
    const chain = async (t: Tag) =>
      (await q(`SELECT seq::text AS seq, entry_hash FROM audit_logs WHERE institution_id = $1 ORDER BY seq`, [INST[t]])) as { seq: string; entry_hash: string }[];
    const verify = async (t: Tag) => {
      const res = await call(client[t], 'GET', '/audit-logs/verify-chain');
      expect(res.statusCode).toBe(200);
      return res.json();
    };
    const signedHead = (t: Tag, headHash: string, day = DAY, key = headPriv, kid = headKey.kid) =>
      q(`INSERT INTO audit_head_hashes (id, institution_id, day, head_hash, signature, signer_kid) VALUES (gen_random_uuid(),$1,$2::date,$3,$4,$5)`, [
        INST[t],
        day,
        headHash,
        signAuditHead({ institutionId: INST[t], day, headHash }, key),
        kid,
      ]);
    const readEntries = async (t: Tag): Promise<(ChainedEntry & { id: string })[]> =>
      (
        await q(
          `SELECT id, institution_id, seq::text AS seq, actor_id, action, target_type, target_id, metadata, ip,
                  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at, prev_hash, entry_hash
             FROM audit_logs WHERE institution_id = $1 ORDER BY seq`,
          [INST[t]],
        )
      ).map((r) => ({
        id: r.id, institutionId: r.institution_id, seq: r.seq, actorId: r.actor_id, action: r.action, targetType: r.target_type,
        targetId: r.target_id, metadata: r.metadata, ip: r.ip, createdAt: r.created_at, prevHash: r.prev_hash, entryHash: r.entry_hash,
      }));

    it('untouched chain with a correctly signed head is valid and the signature is verified', async () => {
      await generate('C');
      const rows = await chain('C');
      await signedHead('C', rows.at(-1)!.entry_hash);
      const v = await verify('C');
      expect(v).toMatchObject({ valid: true, headsRecorded: true, entries: rows.length });
      expect(v.signedHeads).toMatchObject({ checked: 1, matched: 1, signaturesVerified: 1, mismatchedDays: [], signatureInvalidDays: [] });
    });

    it('editing an entry (superuser, trigger bypassed) breaks the chain at that seq', async () => {
      await generate('D');
      const rows = await chain('D');
      await signedHead('D', rows.at(-1)!.entry_hash);
      await ownerTx((c) => c.query(`UPDATE audit_logs SET metadata = '{"reason":"edited"}' WHERE institution_id = $1 AND seq = 2`, [INST.D]), { bypass: true });
      const v = await verify('D');
      expect(v).toMatchObject({ valid: false, brokenAtSeq: '2', reason: 'HASH_MISMATCH' });
    });

    it('deleting an entry in the middle is detected (sequence gap)', async () => {
      await generate('E');
      await ownerTx((c) => c.query(`DELETE FROM audit_logs WHERE institution_id = $1 AND seq = 3`, [INST.E]), { bypass: true });
      const v = await verify('E');
      expect(v).toMatchObject({ valid: false, brokenAtSeq: '4', reason: 'SEQ_GAP' });
    });

    it('rewriting an entry AND recomputing every later hash yields a self-consistent chain; the signed head exposes it', async () => {
      await generate('F');
      const rows = await chain('F');
      await signedHead('F', rows.at(-1)!.entry_hash);
      expect((await verify('F')).valid).toBe(true);

      const entries = await readEntries('F');
      expect(entries.length).toBeGreaterThan(4);
      await ownerTx(
        async (c) => {
          let prev = entries[1]!.prevHash;
          for (const [i, e] of entries.slice(1).entries()) {
            const md = i === 0 ? { reason: 'rewritten by attacker' } : e.metadata;
            const entryHash = computeEntryHash(prev, { ...e, metadata: md });
            await c.query(`UPDATE audit_logs SET metadata = $2::jsonb, prev_hash = $3, entry_hash = $4 WHERE id = $1`, [e.id, JSON.stringify(md), prev, entryHash]);
            prev = entryHash;
          }
        },
        { bypass: true },
      );
      // The attacker's chain is internally valid (this is exactly why the signed head exists) ...
      const own = await db.withTenant(ten('F'), (c) => verifyAuditChain(c, INST.F));
      expect(own.ok).toBe(true);
      // ... but its head differs from the signed one.
      const v = await verify('F');
      expect(v.valid).toBe(false);
      expect(v.headsRecorded).toBe(false);
      expect(v.signedHeads).toMatchObject({ checked: 1, matched: 0, mismatchedDays: [DAY] });
    });

    it('deleting the head entry itself (tail truncation to before the signed head) is detected', async () => {
      await generate('B', 2);
      const rows = await chain('B');
      await signedHead('B', rows.at(-1)!.entry_hash);
      expect((await verify('B')).valid).toBe(true);
      await ownerTx((c) => c.query(`DELETE FROM audit_logs WHERE institution_id = $1 AND seq = $2`, [INST.B, rows.at(-1)!.seq]), { bypass: true });
      const v = await verify('B');
      expect(v.valid).toBe(false);
      expect(v.signedHeads.mismatchedDays).toEqual([DAY]);
    });

    it('a head with a forged signature (wrong key, wrong day, other chain) or an unknown signer kid is a failure', async () => {
      const latest = (await chain('A')).at(-1)!.entry_hash;
      // 1. signed by a different key but claiming the platform kid
      await signedHead('A', latest, '2026-11-20', otherPriv, headKey.kid);
      let v = await verify('A');
      expect(v.valid).toBe(false);
      expect(v.signedHeads.signatureInvalidDays).toEqual(['2026-11-20']);
      // 2. signature made for a different day
      await ownerTx((c) => c.query(`DELETE FROM audit_head_hashes WHERE institution_id = $1`, [INST.A]), { bypass: true });
      await q(`INSERT INTO audit_head_hashes (id, institution_id, day, head_hash, signature, signer_kid) VALUES (gen_random_uuid(),$1,'2026-11-21',$2,$3,$4)`, [
        INST.A,
        latest,
        signAuditHead({ institutionId: INST.A, day: '2026-11-22', headHash: latest }, headPriv),
        headKey.kid,
      ]);
      v = await verify('A');
      expect(v.valid).toBe(false);
      expect(v.signedHeads.signatureInvalidDays).toEqual(['2026-11-21']);
      // 3. signature made for another institution's chain (replay)
      await ownerTx((c) => c.query(`DELETE FROM audit_head_hashes WHERE institution_id = $1`, [INST.A]), { bypass: true });
      await q(`INSERT INTO audit_head_hashes (id, institution_id, day, head_hash, signature, signer_kid) VALUES (gen_random_uuid(),$1,'2026-11-21',$2,$3,$4)`, [
        INST.A,
        latest,
        signAuditHead({ institutionId: INST.B, day: '2026-11-21', headHash: latest }, headPriv),
        headKey.kid,
      ]);
      v = await verify('A');
      expect(v.valid).toBe(false);
      expect(v.signedHeads.signatureInvalidDays).toEqual(['2026-11-21']);
      // 4. unknown signer kid while keys are configured
      await ownerTx((c) => c.query(`DELETE FROM audit_head_hashes WHERE institution_id = $1`, [INST.A]), { bypass: true });
      await signedHead('A', latest, '2026-11-21', otherPriv, otherKey.kid);
      v = await verify('A');
      expect(v.valid).toBe(false);
      expect(v.headsRecorded).toBe(false);
      expect(v.signedHeads.signatureUnverifiedDays).toEqual(['2026-11-21']);
    });

    it('app role cannot UPDATE, DELETE or TRUNCATE audit_logs / audit_head_hashes, or write heads; owner is blocked by triggers', async () => {
      const before = await chain('C');
      const sqls = [
        `UPDATE audit_logs SET action = 'x'`,
        `UPDATE audit_logs SET entry_hash = repeat('a',64)`,
        `DELETE FROM audit_logs`,
        `TRUNCATE audit_logs`,
        `UPDATE audit_head_hashes SET head_hash = repeat('a',64)`,
        `DELETE FROM audit_head_hashes`,
        `TRUNCATE audit_head_hashes`,
        `INSERT INTO audit_head_hashes (id, institution_id, day, head_hash, signature, signer_kid) VALUES (gen_random_uuid(), '${INST.C}', '2026-12-31', 'h', 's', 'k')`,
      ];
      for (const sql of sqls) await expect(db.withTenant(ten('C'), (c) => c.query(sql)), `app: ${sql}`).rejects.toThrow();
      for (const sql of sqls.slice(0, 7)) await expect(ownerTx((c) => c.query(sql)), `owner: ${sql}`).rejects.toThrow();
      expect(await chain('C')).toEqual(before);
    });

    it('credential changes are audited with reasons, and the chain stays valid after the whole suite of lifecycle calls', async () => {
      const c = await issue('A');
      await call(client.A, 'POST', `/credentials/${c.id}/suspend`, { reason: 'audit me' });
      const a = (await call(client.A, 'GET', '/audit-logs?limit=5')).json();
      const entry = a.items.find((i: { action: string; targetId: string }) => i.action === 'credential.suspended' && i.targetId === c.id);
      expect(entry.metadata).toMatchObject({ reason: 'audit me' });
      const chainOk = await db.withTenant(ten('A'), (cl) => verifyAuditChain(cl, INST.A));
      expect(chainOk.ok).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------------------------
  describe('Q5 cross-tenant: every credential endpoint, tenant B against tenant A (section 15 tenancy)', () => {
    let cred: Issued;
    beforeAll(async () => {
      cred = await issue('A', { program: 'Secret Programme Alpha' });
      await call(client.A, 'POST', `/credentials/${cred.id}/suspend`, { reason: 'secret reason alpha' });
    });
    const expect404 = async (c: Client, method: 'GET' | 'POST', path: string, body?: unknown) => {
      const res = await call(c, method, path, body);
      expect(res.statusCode, `${method} ${path}`).toBe(404);
      expect(res.json()).toEqual(NOT_FOUND);
    };

    it('GET/suspend/reinstate/revoke/reissue by id: 404 with a body identical to a missing id; A is unchanged', async () => {
      const before = await stored(cred.id);
      const evBefore = await eventTypes(cred.id);
      await expect404(client.B, 'GET', `/credentials/${cred.id}`);
      for (const [p, body] of [
        ['suspend', { reason: 'x' }],
        ['reinstate', undefined],
        ['revoke', { reason: 'x' }],
        ['reissue', { reason: 'x', attributes: { program: 'hijack' } }],
      ] as const) {
        await expect404(client.B, 'POST', `/credentials/${cred.id}/${p}`, body);
        const missing = await call(client.B, 'POST', `/credentials/${MISSING}/${p}`, body);
        expect(missing.json()).toEqual(NOT_FOUND);
      }
      expect(await stored(cred.id)).toEqual(before);
      expect(await eventTypes(cred.id)).toEqual(evBefore);
      expect((await call(client.A, 'GET', `/credentials/${cred.id}`)).json().status).toBe('SUSPENDED');
    });

    it("list and stats: B never sees A's credentials (even by search) and counts only its own", async () => {
      await issue('B');
      const nB = (await q(`SELECT count(*)::int AS n FROM credentials WHERE institution_id = $1`, [INST.B]))[0]!.n as number;
      const list = (await call(client.B, 'GET', '/credentials?limit=100')).json();
      expect(list.items.length).toBe(nB);
      expect(JSON.stringify(list)).not.toContain(cred.id);
      expect(JSON.stringify(list)).not.toContain(cred.credentialNumber);
      for (const qs of [`q=${cred.credentialNumber}`, 'q=Holder%20A', 'status=SUSPENDED', 'type=STUDENT_ID']) {
        const r = (await call(client.B, 'GET', `/credentials?${qs}`)).json();
        expect(JSON.stringify(r), qs).not.toContain(cred.id);
      }
      const statsA = (await call(client.A, 'GET', '/dashboard/stats')).json();
      const statsB = (await call(client.B, 'GET', '/dashboard/stats')).json();
      expect(statsB.total).toBe(nB);
      expect(Object.values(statsB.byStatus as Record<string, number>).reduce((a, b) => a + b, 0)).toBe(nB);
      expect(statsA.total).toBeGreaterThan(statsB.total);
      expect(statsA.byStatus.SUSPENDED).toBeGreaterThanOrEqual(1);
    });

    it('an institution id smuggled in the query string never changes whose data is returned', async () => {
      for (const path of ['/credentials', '/dashboard/stats', '/audit-logs', '/audit-logs/verify-chain']) {
        const res = await call(client.B, 'GET', `${path}?institutionId=${INST.A}`);
        expect([200, 400], path).toContain(res.statusCode);
        const text = JSON.stringify(res.json());
        expect(text, path).not.toContain(cred.id);
        expect(text, path).not.toContain(INST.A);
      }
    });

    it("audit-logs and verify-chain: B reads only B's chain; A's entries and reasons never appear", async () => {
      const al = (await call(client.B, 'GET', '/audit-logs?limit=200')).json();
      const text = JSON.stringify(al);
      expect(text).not.toContain('secret reason alpha');
      expect(text).not.toContain(cred.id);
      const idsA = new Set((await q(`SELECT id FROM audit_logs WHERE institution_id = $1`, [INST.A])).map((r) => r.id));
      for (const i of al.items) expect(idsA.has(i.id)).toBe(false);
      const vc = (await call(client.B, 'GET', '/audit-logs/verify-chain')).json();
      const nB = (await q(`SELECT count(*)::int AS n FROM audit_logs WHERE institution_id = $1`, [INST.B]))[0]!.n;
      expect(vc.entries).toBe(nB);
      const vcA = (await call(client.A, 'GET', '/audit-logs/verify-chain')).json();
      expect(vcA.entries).not.toBe(vc.entries);
    });

    it('unauthenticated requests are 401 on every credential endpoint', async () => {
      for (const [m, p] of [
        ['GET', '/credentials'],
        ['GET', `/credentials/${cred.id}`],
        ['GET', '/dashboard/stats'],
        ['GET', '/audit-logs'],
        ['GET', '/audit-logs/verify-chain'],
        ['POST', `/credentials/${cred.id}/suspend`],
      ] as const) {
        const res = await app.inject({ method: m, url: `/api/v1${p}` });
        expect(res.statusCode, p).toBe(401);
      }
    });

    it("RLS proof: raw SQL under B's scope sees zero of A's rows and cannot write them", async () => {
      const tables = ['credentials', 'credential_events', 'credential_holders', 'credential_types', 'audit_logs', 'audit_head_hashes', 'institution_keys'];
      const aCount = async (t: string) => (await q(`SELECT count(*)::int AS n FROM ${t} WHERE institution_id = $1`, [INST.A]))[0]!.n as number;
      for (const t of tables) {
        if (t !== 'audit_head_hashes') expect(await aCount(t), t).toBeGreaterThan(0);
        const seen = await db.withTenant(ten('B'), async (c) => (await c.query(`SELECT count(*)::int AS n FROM ${t} WHERE institution_id = $1`, [INST.A])).rows[0].n);
        expect(seen, t).toBe(0);
      }
      const probe = await db.withTenant(ten('B'), async (c) => ({
        byId: (await c.query(`SELECT 1 FROM credentials WHERE id = $1`, [cred.id])).rowCount,
        byToken: (await c.query(`SELECT 1 FROM credentials WHERE verification_token = $1`, [cred.verificationToken])).rowCount,
        update: (await c.query(`UPDATE credentials SET updated_at = now() WHERE id = $1`, [cred.id])).rowCount,
        updateHolder: (await c.query(`UPDATE credential_holders SET full_name = 'x' WHERE id = $1`, [HOLDER.A])).rowCount,
      }));
      expect(probe).toEqual({ byId: 0, byToken: 0, update: 0, updateHolder: 0 });
      // Inserting a row for A's institution under B's scope is refused by the RLS check.
      await expect(
        db.withTenant(ten('B'), (c) =>
          c.query(`INSERT INTO credential_events (id, institution_id, credential_id, type) VALUES (gen_random_uuid(),$1,$2,'REVOKED')`, [INST.A, cred.id]),
        ),
      ).rejects.toThrow();
      // And no scope at all sees nothing.
      const none = await db.withTenant(ten('B'), (c) => c.query(`SELECT set_config('app.institution_id','',true)`).then(() => c.query(`SELECT count(*)::int AS n FROM credentials`)));
      expect(none.rows[0].n).toBe(0);
    });
  });

  it('no token, salt, signature or reason secret from the QA run appears in application logs (invariant 9)', async () => {
    const c = await issue('A');
    const re = await call(client.A, 'POST', `/credentials/${c.id}/reissue`, { reason: 'log scan' });
    const body = re.json();
    const n = body.credential ?? body;
    const all = logs.join('\n');
    expect(all.length).toBeGreaterThan(0);
    for (const s of [c.verificationToken, c.payload.salt, c.signature, n?.verificationToken, n?.holderToken, n?.payload?.salt, n?.signature]) {
      if (typeof s === 'string' && s.length > 8) expect(all).not.toContain(s);
    }
    expect(all).not.toContain(master.toString('base64'));
    expect(all).not.toContain(master.toString('hex'));
  });
});
