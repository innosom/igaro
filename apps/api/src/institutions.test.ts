// Integration tests for platform-admin institution management (T-015). Skipped when DATABASE_URL is
// unset. Migrations are applied into a scratch schema and the API connects as the restricted
// igaro_app role, so RLS is enforced for real.
import { createHash, randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { Writable } from 'node:stream';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import pg from 'pg';
import type { FastifyInstance } from 'fastify';
import { publicKeyFromRaw, unwrapPrivateKey } from '@igaro/core';
import { buildApp } from './app.js';
import { csrfTokenFor, hashPassword } from './auth.js';
import { Db } from './db.js';
import { MemoryAccountMailQueue } from './notifications.js';

// Wrap generateSigningKey so one test can force a kid collision; otherwise it is the real function.
vi.mock('@igaro/core', async (orig) => {
  const m = await orig<typeof import('@igaro/core')>();
  return { ...m, generateSigningKey: vi.fn(m.generateSigningKey) };
});

const url = process.env.DATABASE_URL;
const migrationsDir = new URL('../../../packages/db/prisma/migrations/', import.meta.url);

const EXISTING = '11111111-1111-4111-8111-111111111111';
const U_PA = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const U_IA = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

const PW = 'correct horse battery staple';
const MASTER = randomBytes(32);
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const json = { 'content-type': 'application/json' };
const BIG = { ipMax: 10000, accountMax: 10000, windowSeconds: 900 };
const rateLimit = { login: BIG, reset: BIG, token: { ipMax: 10000, windowSeconds: 900 } };

interface Client {
  headers: Record<string, string>;
}

describe.skipIf(!url)('institutions: platform admin management (needs Postgres)', () => {
  const schema = `t015_${randomBytes(4).toString('hex')}`;
  let owner: pg.Client;
  let db: Db;
  let app: FastifyInstance;
  let pa: Client;
  let ia: Client;
  const logs: string[] = [];
  const queue = new MemoryAccountMailQueue();
  let n = 0;
  const slug = () => `inst-${randomBytes(4).toString('hex')}-${n++}`;

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

  const loginAs = async (a: FastifyInstance, email: string): Promise<Client> => {
    const res = await a.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      headers: json,
      payload: { email, password: PW },
    });
    expect(res.statusCode).toBe(200);
    const cookie = String(res.headers['set-cookie']).split(';')[0]!;
    const token = cookie.slice(cookie.indexOf('=') + 1);
    return { headers: { cookie, 'x-csrf-token': csrfTokenFor(token), ...json } };
  };

  const call = (
    c: Client | null,
    method: 'GET' | 'POST' | 'PATCH',
    path: string,
    payload?: unknown,
    a = app,
  ) =>
    a.inject({
      method,
      url: `/api/v1${path}`,
      headers: c?.headers ?? json,
      ...(payload === undefined ? {} : { payload: payload as Record<string, unknown> }),
    });

  const create = (name = 'Test University', s = slug(), adminEmail = `admin-${s}@example.test`) =>
    call(pa, 'POST', '/institutions', { name, slug: s, adminEmail });

  beforeAll(async () => {
    owner = new pg.Client({ connectionString: url });
    await owner.connect();
    await owner.query(`CREATE SCHEMA "${schema}"`);
    await owner.query(`SET search_path TO "${schema}"`);
    const dirs = readdirSync(migrationsDir, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => d.name)
      .sort();
    for (const d of dirs) {
      await owner.query(readFileSync(new URL(`${d}/migration.sql`, migrationsDir), 'utf8'));
    }
    await owner.query(`GRANT USAGE ON SCHEMA "${schema}" TO igaro_app`);

    const pwHash = await hashPassword(PW);
    await ownerQuery(
      `INSERT INTO institutions (id, name, slug, updated_at) VALUES ($1,'Existing','existing',now())`,
      [EXISTING],
    );
    for (const [id, inst, email, role] of [
      [U_PA, null, 'pa@example.test', 'PLATFORM_ADMIN'],
      [U_IA, EXISTING, 'ia@example.test', 'INSTITUTION_ADMIN'],
    ] as const) {
      await ownerQuery(
        `INSERT INTO users (id, institution_id, email, name, password_hash, role, status, updated_at)
         VALUES ($1,$2,$3,'Name',$4,$5,'ACTIVE',now())`,
        [id, inst, email, pwHash, role],
      );
    }

    db = new Db({
      connectionString: url!,
      max: 6,
      poolConfig: { options: `-c search_path=${schema} -c role=igaro_app` },
    });
    const logStream = new Writable({
      write(chunk, _enc, cb) {
        logs.push(String(chunk));
        cb();
      },
    });
    app = await buildApp({
      config: { logLevel: 'debug', rateLimit, masterKey: MASTER },
      db,
      logStream,
      accountMail: queue,
    });
    pa = await loginAs(app, 'pa@example.test');
    ia = await loginAs(app, 'ia@example.test');
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

  describe('authorization', () => {
    it('401 without a session on every route', async () => {
      const id = EXISTING;
      for (const [m, p, body] of [
        ['GET', '/institutions', undefined],
        ['POST', '/institutions', { name: 'x', slug: 'abc', adminEmail: 'a@b.test' }],
        ['PATCH', `/institutions/${id}/status`, { status: 'ACTIVE' }],
      ] as const) {
        const res = await call(null, m, p, body);
        expect(res.statusCode, `${m} ${p}`).toBe(401);
      }
    });

    it('403 for an institution admin on every route, and nothing is written', async () => {
      const before = (await ownerQuery(`SELECT count(*)::int AS n FROM institutions`)).rows[0].n;
      const s = slug();
      const res = [
        await call(ia, 'GET', '/institutions'),
        await call(ia, 'POST', '/institutions', { name: 'x', slug: s, adminEmail: 'a@b.test' }),
        await call(ia, 'PATCH', `/institutions/${EXISTING}/status`, {
          status: 'SUSPENDED',
          reason: 'nope',
        }),
      ];
      for (const r of res) {
        expect(r.statusCode).toBe(403);
        expect(r.json().error.code).toBe('FORBIDDEN');
      }
      expect((await ownerQuery(`SELECT count(*)::int AS n FROM institutions`)).rows[0].n).toBe(
        before,
      );
      expect(
        (await ownerQuery(`SELECT status FROM institutions WHERE id = $1`, [EXISTING])).rows[0]
          .status,
      ).toBe('ACTIVE');
    });

    it('mutating routes require the CSRF header', async () => {
      const noCsrf: Client = { headers: { cookie: pa.headers.cookie!, ...json } };
      const s = slug();
      const post = await call(noCsrf, 'POST', '/institutions', {
        name: 'x',
        slug: s,
        adminEmail: 'csrf@example.test',
      });
      expect(post.statusCode).toBe(403);
      expect(post.json().error.code).toBe('CSRF_REQUIRED');
      const patch = await call(noCsrf, 'PATCH', `/institutions/${EXISTING}/status`, {
        status: 'SUSPENDED',
        reason: 'r',
      });
      expect(patch.statusCode).toBe(403);
      expect(
        (await ownerQuery(`SELECT 1 FROM institutions WHERE slug = $1`, [s])).rowCount,
      ).toBe(0);
    });
  });

  describe('POST /institutions', () => {
    it('creates institution + wrapped ACTIVE key + hashed invite, and queues the invite mail', async () => {
      const s = slug();
      const res = await create('Eastern Arabian University', s, ' First.Admin@Example.test ');
      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.inviteQueued).toBe(true);
      expect(body.institution).toMatchObject({
        name: 'Eastern Arabian University',
        slug: s,
        status: 'ACTIVE',
      });
      const id = body.institution.id as string;

      // Key: exactly one, ACTIVE, wrapped under the master key and bound to its kid.
      const keys = (await ownerQuery(`SELECT * FROM institution_keys WHERE institution_id = $1`, [id]))
        .rows;
      expect(keys).toHaveLength(1);
      const k = keys[0];
      expect(k).toMatchObject({ status: 'ACTIVE', algorithm: 'Ed25519' });
      expect(k.kid).toMatch(/^kid_[0-9a-f]{16}$/);
      expect(body.institution.activeKid).toBe(k.kid);
      expect(k.encrypted_private_key).toMatch(/^igaro\.key\.v1\./);
      expect(k.encrypted_private_key).not.toContain(MASTER.toString('base64'));
      const priv = unwrapPrivateKey(k.encrypted_private_key, MASTER, k.kid);
      expect(priv.asymmetricKeyType).toBe('ed25519');
      expect(() => unwrapPrivateKey(k.encrypted_private_key, randomBytes(32), k.kid)).toThrow();
      expect(() => unwrapPrivateKey(k.encrypted_private_key, MASTER, 'kid_0000000000000000')).toThrow();
      expect(publicKeyFromRaw(k.public_key).asymmetricKeyType).toBe('ed25519');

      // Response carries no key material.
      expect(res.body).not.toContain(k.encrypted_private_key);
      expect(res.body).not.toContain(k.public_key);

      // Invite: only the hash is stored; the raw token only travels in the mail job.
      const job = queue.jobs[queue.jobs.length - 1]!;
      expect(job).toMatchObject({
        kind: 'INVITE',
        to: 'first.admin@example.test',
        institutionId: id,
      });
      const token = (job as { token: string }).token;
      expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
      const inv = (await ownerQuery(`SELECT * FROM invites WHERE institution_id = $1`, [id])).rows;
      expect(inv).toHaveLength(1);
      expect(inv[0]).toMatchObject({ token_hash: sha(token), email: 'first.admin@example.test' });
      expect(inv[0].used_at).toBeNull();
      expect(JSON.stringify(inv[0])).not.toContain(token);
      expect(res.body).not.toContain(token);

      // The invite works end to end and the new admin lands in the new institution.
      const acc = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/invites/accept',
        headers: json,
        payload: { token, password: 'a brand new passphrase 42' },
      });
      expect(acc.statusCode).toBe(204);
      const u = (
        await ownerQuery(`SELECT institution_id, role FROM users WHERE email = $1`, [
          'first.admin@example.test',
        ])
      ).rows[0];
      expect(u).toMatchObject({ institution_id: id, role: 'INSTITUTION_ADMIN' });
    });

    it('retries when the generated kid collides with an existing one', async () => {
      const core = await import('@igaro/core');
      const mocked = vi.mocked(core.generateSigningKey);
      const first = await create();
      const takenKid = first.json().institution.activeKid as string;
      const collide = { ...core.generateSigningKey(MASTER), kid: takenKid };
      mocked.mockImplementationOnce(() => collide);
      const calls = mocked.mock.calls.length;
      const res = await create();
      expect(res.statusCode).toBe(201);
      expect(mocked.mock.calls.length).toBeGreaterThanOrEqual(calls + 2);
      const kid = res.json().institution.activeKid as string;
      expect(kid).not.toBe(takenKid);
      const id = res.json().institution.id as string;
      expect(
        (await ownerQuery(`SELECT 1 FROM institution_keys WHERE institution_id = $1`, [id])).rowCount,
      ).toBe(1);
    });

    it('409 on a duplicate slug and leaves nothing behind (single transaction)', async () => {
      const s = slug();
      expect((await create('One', s)).statusCode).toBe(201);
      const keysBefore = (await ownerQuery(`SELECT count(*)::int AS n FROM institution_keys`)).rows[0].n;
      const invBefore = (await ownerQuery(`SELECT count(*)::int AS n FROM invites`)).rows[0].n;
      const jobs = queue.jobs.length;
      const dup = await create('Two', s, 'other-admin@example.test');
      expect(dup.statusCode).toBe(409);
      expect(dup.json().error.code).toBe('SLUG_TAKEN');
      expect((await ownerQuery(`SELECT count(*)::int AS n FROM institution_keys`)).rows[0].n).toBe(
        keysBefore,
      );
      expect((await ownerQuery(`SELECT count(*)::int AS n FROM invites`)).rows[0].n).toBe(invBefore);
      expect(queue.jobs.length).toBe(jobs);
    });

    it('409 when the admin email already has an account', async () => {
      const res = await create('X', slug(), 'IA@example.test');
      expect(res.statusCode).toBe(409);
      expect(res.json().error.code).toBe('EMAIL_IN_USE');
    });

    it('400 on invalid input', async () => {
      const bad: unknown[] = [
        {},
        { name: 'x', slug: 'ab', adminEmail: 'a@b.test' }, // too short
        { name: 'x', slug: 'UPPER', adminEmail: 'a@b.test' },
        { name: 'x', slug: '-lead', adminEmail: 'a@b.test' },
        { name: 'x', slug: 'trail-', adminEmail: 'a@b.test' },
        { name: 'x', slug: 'has space', adminEmail: 'a@b.test' },
        { name: 'x', slug: 'a/../b', adminEmail: 'a@b.test' },
        { name: 'x', slug: 'a'.repeat(41), adminEmail: 'a@b.test' },
        { name: '', slug: 'okslug', adminEmail: 'a@b.test' },
        { name: 'x', slug: 'okslug', adminEmail: 'not-an-email' },
        { name: 'x', slug: 'okslug', adminEmail: 5 },
        { name: ['x'], slug: 'okslug', adminEmail: 'a@b.test' },
      ];
      for (const b of bad) {
        const res = await call(pa, 'POST', '/institutions', b);
        expect(res.statusCode, JSON.stringify(b)).toBe(400);
      }
      expect(
        (await ownerQuery(`SELECT 1 FROM institutions WHERE slug = 'okslug'`)).rowCount,
      ).toBe(0);
    });

    it('503 and no institution when no master key is configured', async () => {
      const noKey = await buildApp({
        config: { logLevel: 'silent', rateLimit },
        db,
        accountMail: queue,
      });
      try {
        const c = await loginAs(noKey, 'pa@example.test');
        const s = slug();
        const res = await call(
          c,
          'POST',
          '/institutions',
          { name: 'x', slug: s, adminEmail: 'nokey@example.test' },
          noKey,
        );
        expect(res.statusCode).toBe(503);
        expect(res.json().error.code).toBe('KEY_CUSTODY_UNAVAILABLE');
        expect((await ownerQuery(`SELECT 1 FROM institutions WHERE slug = $1`, [s])).rowCount).toBe(0);
      } finally {
        await noKey.close();
      }
    });
  });

  describe('GET /institutions', () => {
    it('paginates by cursor without gaps or repeats and exposes no secrets', async () => {
      for (let i = 0; i < 5; i++) expect((await create()).statusCode).toBe(201);
      const total = (await ownerQuery(`SELECT count(*)::int AS n FROM institutions`)).rows[0]
        .n as number;
      expect(total).toBeGreaterThanOrEqual(6);

      const seen: string[] = [];
      let cursor: string | null = null;
      let pages = 0;
      do {
        const qs: string = `?limit=2${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`;
        const res = await call(pa, 'GET', `/institutions${qs}`);
        expect(res.statusCode).toBe(200);
        const body = res.json();
        expect(body.items.length).toBeLessThanOrEqual(2);
        for (const it of body.items) {
          seen.push(it.id);
          expect(Object.keys(it).sort()).toEqual(
            ['activeKid', 'createdAt', 'id', 'name', 'slug', 'status', 'updatedAt'].sort(),
          );
        }
        cursor = body.nextCursor;
        pages++;
      } while (cursor && pages < 100);
      expect(new Set(seen).size).toBe(seen.length);
      expect(seen).toHaveLength(total);
      expect(pages).toBe(Math.ceil(total / 2));

      const all = await call(pa, 'GET', '/institutions');
      expect(all.json().items).toHaveLength(total);
      expect(all.json().nextCursor).toBeNull();
      expect(all.body).not.toContain('igaro.key.v1');
      expect(all.headers['cache-control']).toBe('no-store');
    });

    it('400 on a bad limit or cursor', async () => {
      for (const q of ['?limit=0', '?limit=201', '?limit=abc', '?limit=-1', '?cursor=%%%', '?cursor=e30']) {
        expect((await call(pa, 'GET', `/institutions${q}`)).statusCode, q).toBe(400);
      }
    });
  });

  describe('PATCH /institutions/:id/status', () => {
    it('suspends with a reason, reinstates, and is idempotent', async () => {
      const id = (await create()).json().institution.id as string;
      const path = `/institutions/${id}/status`;

      for (const b of [
        { status: 'SUSPENDED' },
        { status: 'SUSPENDED', reason: '' },
        { status: 'SUSPENDED', reason: '   ' },
        { status: 'SUSPENDED', reason: 'x'.repeat(501) },
        { status: 'SUSPENDED', reason: 7 },
        { status: 'DELETED', reason: 'x' },
        { reason: 'x' },
      ]) {
        expect((await call(pa, 'PATCH', path, b)).statusCode, JSON.stringify(b)).toBe(400);
      }
      const noReason = await call(pa, 'PATCH', path, { status: 'SUSPENDED' });
      expect(noReason.json().error.code).toBe('REASON_REQUIRED');

      const sus = await call(pa, 'PATCH', path, { status: 'SUSPENDED', reason: 'Unpaid invoice' });
      expect(sus.statusCode).toBe(200);
      expect(sus.json()).toMatchObject({ id, status: 'SUSPENDED' });
      expect(
        (await ownerQuery(`SELECT status FROM institutions WHERE id = $1`, [id])).rows[0].status,
      ).toBe('SUSPENDED');
      expect(logs.join('')).toContain('institution.status_changed');

      const again = await call(pa, 'PATCH', path, { status: 'SUSPENDED', reason: 'again' });
      expect(again.statusCode).toBe(200);
      expect(again.json().status).toBe('SUSPENDED');

      const back = await call(pa, 'PATCH', path, { status: 'ACTIVE' });
      expect(back.statusCode).toBe(200);
      expect(back.json().status).toBe('ACTIVE');
      expect(
        (await ownerQuery(`SELECT status FROM institutions WHERE id = $1`, [id])).rows[0].status,
      ).toBe('ACTIVE');
    });

    it('404 for an unknown or malformed id', async () => {
      for (const id of ['99999999-9999-4999-8999-999999999999', 'not-a-uuid', '1']) {
        const res = await call(pa, 'PATCH', `/institutions/${id}/status`, {
          status: 'SUSPENDED',
          reason: 'r',
        });
        expect(res.statusCode, id).toBe(404);
        expect(res.json().error.code).toBe('NOT_FOUND');
      }
    });
  });

  describe('no secrets in logs', () => {
    it('never logs tokens, wrapped keys, the master key, passwords or the admin email', async () => {
      const email = 'logcheck-admin@example.test';
      const res = await create('Log Check', slug(), email);
      expect(res.statusCode).toBe(201);
      const id = res.json().institution.id as string;
      const token = (queue.jobs[queue.jobs.length - 1] as { token: string }).token;
      const wrapped = (
        await ownerQuery(`SELECT encrypted_private_key, public_key FROM institution_keys WHERE institution_id = $1`, [id])
      ).rows[0];
      await call(pa, 'PATCH', `/institutions/${id}/status`, { status: 'SUSPENDED', reason: 'r' });
      // an error path as well
      await create('Dup', 'existing', 'dup@example.test');

      const all = logs.join('\n');
      expect(all.length).toBeGreaterThan(0);
      expect(all).not.toContain(token);
      expect(all).not.toContain(wrapped.encrypted_private_key);
      expect(all).not.toContain(MASTER.toString('base64'));
      expect(all).not.toContain(MASTER.toString('hex'));
      expect(all).not.toContain(PW);
      expect(all).not.toContain(email);
      expect(all).not.toContain('BEGIN PRIVATE KEY');
    });
  });
});
