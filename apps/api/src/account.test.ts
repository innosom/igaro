// Integration tests for invite accept, password reset and login rate limiting (T-010).
// Skipped when DATABASE_URL is unset. Migrations are applied into a scratch schema and the API
// connects as the restricted igaro_app role.
import { createHash, randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { Writable } from 'node:stream';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import type { FastifyInstance } from 'fastify';
import { AccountService } from './account.js';
import { buildApp } from './app.js';
import { hashPassword, verifyPassword } from './auth.js';
import { Db } from './db.js';
import { MemoryAccountMailQueue } from './notifications.js';

const url = process.env.DATABASE_URL;
const migrationsDir = new URL('../../../packages/db/prisma/migrations/', import.meta.url);

const INST = '11111111-1111-4111-8111-111111111111';
const OTHER = '22222222-2222-4222-8222-222222222222';
const U_IA = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const U_PA = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const U_OFF = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const U_OTHER = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';

const PW = 'correct horse battery staple';
const NEW_PW = 'a brand new passphrase 42';
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const json = { 'content-type': 'application/json' };
const BIG = { ipMax: 10000, accountMax: 10000, windowSeconds: 900 };

describe.skipIf(!url)('account: invites, password reset, rate limits (needs Postgres)', () => {
  const schema = `t010_${randomBytes(4).toString('hex')}`;
  let owner: pg.Client;
  let db: Db;
  let app: FastifyInstance;
  const logs: string[] = [];
  const queue = new MemoryAccountMailQueue();
  let svc: AccountService;

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

  const post = (a: FastifyInstance, path: string, payload: unknown, remoteAddress?: string) =>
    a.inject({
      method: 'POST',
      url: `/api/v1/auth/${path}`,
      headers: json,
      payload: payload as Record<string, unknown>,
      ...(remoteAddress ? { remoteAddress } : {}),
    });
  const login = (email: string, password = PW, a = app, ip?: string) =>
    post(a, 'login', { email, password }, ip);

  const lastJob = () => queue.jobs[queue.jobs.length - 1]!;
  const newAccountApp = (rateLimit: {
    login?: typeof BIG;
    reset?: typeof BIG;
    token?: { ipMax: number; windowSeconds: number };
  }) =>
    buildApp({
      config: {
        logLevel: 'silent',
        rateLimit: {
          login: rateLimit.login ?? BIG,
          reset: rateLimit.reset ?? BIG,
          token: rateLimit.token ?? { ipMax: 10000, windowSeconds: 900 },
        },
      },
      db,
      accountMail: queue,
    });

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
      `INSERT INTO institutions (id, name, slug, updated_at) VALUES ($1,'One','one',now()), ($2,'Two','two',now())`,
      [INST, OTHER],
    );
    const insUser = (id: string, inst: string | null, email: string, role: string, st = 'ACTIVE') =>
      ownerQuery(
        `INSERT INTO users (id, institution_id, email, name, password_hash, role, status, updated_at)
         VALUES ($1,$2,$3,'Name',$4,$5,$6,now())`,
        [id, inst, email, pwHash, role, st],
      );
    await insUser(U_IA, INST, 'ia@example.test', 'INSTITUTION_ADMIN');
    await insUser(U_PA, null, 'pa@example.test', 'PLATFORM_ADMIN');
    await insUser(U_OFF, INST, 'off@example.test', 'INSTITUTION_ADMIN', 'DISABLED');
    await insUser(U_OTHER, OTHER, 'other@example.test', 'INSTITUTION_ADMIN');

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
      config: {
        logLevel: 'debug',
        rateLimit: { login: BIG, reset: BIG, token: { ipMax: 10000, windowSeconds: 900 } },
      },
      db,
      logStream,
      accountMail: queue,
    });
    svc = new AccountService(db, { queue });
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

  describe('invite accept', () => {
    it('creates the admin, stores only the token hash, consumes the invite, does not log in', async () => {
      await svc.issueInvite(
        { kind: 'platform', userId: U_PA },
        { email: ' New.Admin@Example.test', institutionId: INST },
      );
      const job = lastJob();
      expect(job).toMatchObject({
        kind: 'INVITE',
        to: 'new.admin@example.test',
        institutionId: INST,
      });
      const token = (job as { token: string }).token;
      expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
      const row = (await ownerQuery(`SELECT * FROM invites WHERE token_hash = $1`, [sha(token)]))
        .rows[0];
      expect(row.used_at).toBeNull();
      expect(JSON.stringify(row)).not.toContain(token);

      const res = await post(app, 'invites/accept', { token, password: NEW_PW, name: 'New Admin' });
      expect(res.statusCode).toBe(204);
      expect(res.headers['set-cookie']).toBeUndefined();
      const u = (await ownerQuery(`SELECT * FROM users WHERE email = 'new.admin@example.test'`))
        .rows[0];
      expect(u).toMatchObject({
        institution_id: INST,
        role: 'INSTITUTION_ADMIN',
        status: 'ACTIVE',
        name: 'New Admin',
      });
      expect(u.password_hash).toMatch(/^\$argon2id\$/);
      const used = await ownerQuery(`SELECT used_at FROM invites WHERE token_hash = $1`, [
        sha(token),
      ]);
      expect(used.rows[0].used_at).not.toBeNull();
      expect((await login('new.admin@example.test', NEW_PW)).statusCode).toBe(200);
    });

    it('is single use, and unknown/malformed/used tokens look identical', async () => {
      await svc.issueInvite(
        { kind: 'platform', userId: U_PA },
        { email: 'once@example.test', institutionId: INST },
      );
      const token = (lastJob() as { token: string }).token;
      expect((await post(app, 'invites/accept', { token, password: NEW_PW })).statusCode).toBe(204);
      const again = await post(app, 'invites/accept', { token, password: NEW_PW });
      const unknown = await post(app, 'invites/accept', {
        token: randomBytes(32).toString('base64url'),
        password: NEW_PW,
      });
      const malformed = await post(app, 'invites/accept', { token: 'nope', password: NEW_PW });
      for (const r of [again, unknown, malformed]) expect(r.statusCode).toBe(400);
      expect(new Set([again.body, unknown.body, malformed.body]).size).toBe(1);
      expect(again.json().error.code).toBe('INVALID_TOKEN');
    });

    it('rejects an expired invite', async () => {
      await svc.issueInvite(
        { kind: 'platform', userId: U_PA },
        { email: 'late@example.test', institutionId: INST },
      );
      const token = (lastJob() as { token: string }).token;
      await ownerQuery(
        `UPDATE invites SET expires_at = now() - interval '1 second' WHERE token_hash = $1`,
        [sha(token)],
      );
      const r = await post(app, 'invites/accept', { token, password: NEW_PW });
      expect(r.statusCode).toBe(400);
      expect(r.json().error.code).toBe('INVALID_TOKEN');
      expect(
        (await ownerQuery(`SELECT 1 FROM users WHERE email = 'late@example.test'`)).rowCount,
      ).toBe(0);
    });

    it('a weak password does not consume the invite', async () => {
      await svc.issueInvite(
        { kind: 'platform', userId: U_PA },
        { email: 'weak@example.test', institutionId: INST },
      );
      const token = (lastJob() as { token: string }).token;
      const r = await post(app, 'invites/accept', { token, password: 'short' });
      expect(r.statusCode).toBe(400);
      expect(r.json().error.code).toBe('WEAK_PASSWORD');
      expect((await post(app, 'invites/accept', { token, password: NEW_PW })).statusCode).toBe(204);
    });

    it('an email that already has an account fails generically and leaves the invite unused', async () => {
      await svc.issueInvite(
        { kind: 'platform', userId: U_PA },
        { email: 'other@example.test', institutionId: INST },
      );
      const token = (lastJob() as { token: string }).token;
      const r = await post(app, 'invites/accept', { token, password: NEW_PW });
      expect(r.statusCode).toBe(400);
      expect(r.json().error.code).toBe('INVALID_TOKEN');
      const row = await ownerQuery(`SELECT used_at FROM invites WHERE token_hash = $1`, [
        sha(token),
      ]);
      expect(row.rows[0].used_at).toBeNull();
      // the existing account in the other tenant is untouched
      expect((await login('other@example.test')).statusCode).toBe(200);
    });

    it('a tenant session can only invite into its own institution', async () => {
      await svc.issueInvite(
        { kind: 'tenant', userId: U_IA, institutionId: INST },
        { email: 'peer@example.test', institutionId: OTHER },
      );
      const token = (lastJob() as { token: string }).token;
      const row = await ownerQuery(`SELECT institution_id FROM invites WHERE token_hash = $1`, [
        sha(token),
      ]);
      expect(row.rows[0].institution_id).toBe(INST);
      await expect(
        svc.issueInvite({ kind: 'platform', userId: U_PA }, { email: 'x@example.test' }),
      ).rejects.toThrow();
    });

    it('rejects non-JSON content types and malformed bodies', async () => {
      const plain = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/invites/accept',
        headers: { 'content-type': 'text/plain' },
        payload: JSON.stringify({ token: 'x', password: NEW_PW }),
      });
      expect(plain.statusCode).toBe(415);
      expect((await post(app, 'invites/accept', {})).statusCode).toBe(400);
      expect((await post(app, 'invites/accept', { token: 5, password: NEW_PW })).statusCode).toBe(
        400,
      );
    });
  });

  describe('password reset', () => {
    it('request returns the same 202 for known, unknown, disabled and odd-case emails', async () => {
      const before = queue.jobs.length;
      const known = await post(app, 'password-reset', { email: 'IA@example.test' });
      const unknown = await post(app, 'password-reset', { email: 'nobody@example.test' });
      const disabled = await post(app, 'password-reset', { email: 'off@example.test' });
      for (const r of [known, unknown, disabled]) expect(r.statusCode).toBe(202);
      expect(new Set([known.body, unknown.body, disabled.body]).size).toBe(1);
      expect(known.headers['set-cookie']).toBeUndefined();
      // only the real, active account produced a mail job
      expect(queue.jobs.length - before).toBe(1);
      expect(lastJob()).toMatchObject({ kind: 'PASSWORD_RESET', to: 'ia@example.test' });
    });

    it('stores only the token hash, 256-bit, with an expiry', async () => {
      await post(app, 'password-reset', { email: 'ia@example.test' });
      const token = (lastJob() as { token: string }).token;
      expect(Buffer.from(token, 'base64url')).toHaveLength(32);
      const row = (
        await ownerQuery(`SELECT * FROM password_resets WHERE token_hash = $1`, [sha(token)])
      ).rows[0];
      expect(row.user_id).toBe(U_IA);
      expect(row.institution_id).toBe(INST);
      expect(row.used_at).toBeNull();
      expect(row.expires_at.getTime()).toBeGreaterThan(Date.now());
      expect(JSON.stringify(row)).not.toContain(token);
    });

    it('confirm sets the password, kills ALL sessions, is single use, and spares other users', async () => {
      const s1 = await login('ia@example.test');
      const s2 = await login('ia@example.test');
      const sOther = await login('other@example.test');
      const cookie = (r: { headers: Record<string, unknown> }) =>
        (r.headers['set-cookie'] as string).split(';')[0]!;
      const otherHashBefore = (
        await ownerQuery(`SELECT password_hash FROM users WHERE id = $1`, [U_OTHER])
      ).rows[0].password_hash;

      await post(app, 'password-reset', { email: 'ia@example.test' });
      const token = (lastJob() as { token: string }).token;
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/password-reset',
        headers: { ...json, cookie: cookie(s1) },
        payload: { token, password: NEW_PW },
      });
      expect(res.statusCode).toBe(204);
      expect(String(res.headers['set-cookie'])).toContain('Max-Age=0');

      for (const s of [s1, s2]) {
        const me = await app.inject({
          method: 'GET',
          url: '/api/v1/auth/me',
          headers: { cookie: cookie(s) },
        });
        expect(me.statusCode).toBe(401);
      }
      expect((await ownerQuery(`SELECT 1 FROM sessions WHERE user_id = $1`, [U_IA])).rowCount).toBe(
        0,
      );
      const me = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/me',
        headers: { cookie: cookie(sOther) },
      });
      expect(me.statusCode).toBe(200);
      expect(
        (await ownerQuery(`SELECT password_hash FROM users WHERE id = $1`, [U_OTHER])).rows[0]
          .password_hash,
      ).toBe(otherHashBefore);

      expect((await login('ia@example.test', PW)).statusCode).toBe(401);
      expect((await login('ia@example.test', NEW_PW)).statusCode).toBe(200);

      const reuse = await post(app, 'password-reset', { token, password: 'another passphrase 99' });
      expect(reuse.statusCode).toBe(400);
      expect(reuse.json().error.code).toBe('INVALID_TOKEN');
      expect((await login('ia@example.test', NEW_PW)).statusCode).toBe(200);
    });

    it('a new request voids the earlier token', async () => {
      await post(app, 'password-reset', { email: 'other@example.test' });
      const first = (lastJob() as { token: string }).token;
      await post(app, 'password-reset', { email: 'other@example.test' });
      const second = (lastJob() as { token: string }).token;
      expect(
        (await post(app, 'password-reset', { token: first, password: NEW_PW })).statusCode,
      ).toBe(400);
      expect(
        (await post(app, 'password-reset', { token: second, password: NEW_PW })).statusCode,
      ).toBe(204);
    });

    it('rejects expired, unknown and malformed tokens identically; weak passwords keep the token', async () => {
      await post(app, 'password-reset', { email: 'pa@example.test' });
      const token = (lastJob() as { token: string }).token;
      const weak = await post(app, 'password-reset', { token, password: 'short' });
      expect(weak.json().error.code).toBe('WEAK_PASSWORD');

      await ownerQuery(
        `UPDATE password_resets SET expires_at = now() - interval '1 second' WHERE token_hash = $1`,
        [sha(token)],
      );
      const expired = await post(app, 'password-reset', { token, password: NEW_PW });
      const unknown = await post(app, 'password-reset', {
        token: randomBytes(32).toString('base64url'),
        password: NEW_PW,
      });
      const bad = await post(app, 'password-reset', { token: 'zzz', password: NEW_PW });
      for (const r of [expired, unknown, bad]) expect(r.statusCode).toBe(400);
      expect(new Set([expired.body, unknown.body, bad.body]).size).toBe(1);
    });

    it('works for a platform admin (no institution) and kills their sessions', async () => {
      const s = await login('pa@example.test');
      expect(s.statusCode).toBe(200);
      await post(app, 'password-reset', { email: 'pa@example.test' });
      const token = (lastJob() as { token: string }).token;
      expect((await post(app, 'password-reset', { token, password: NEW_PW })).statusCode).toBe(204);
      expect((await ownerQuery(`SELECT 1 FROM sessions WHERE user_id = $1`, [U_PA])).rowCount).toBe(
        0,
      );
      expect((await login('pa@example.test', NEW_PW)).statusCode).toBe(200);
    });

    it('a user disabled after requesting cannot redeem the token', async () => {
      await ownerQuery(`UPDATE users SET status = 'ACTIVE', updated_at = now() WHERE id = $1`, [
        U_OFF,
      ]);
      await post(app, 'password-reset', { email: 'off@example.test' });
      const token = (lastJob() as { token: string }).token;
      await ownerQuery(`UPDATE users SET status = 'DISABLED', updated_at = now() WHERE id = $1`, [
        U_OFF,
      ]);
      const r = await post(app, 'password-reset', { token, password: NEW_PW });
      expect(r.statusCode).toBe(400);
      expect((await login('off@example.test', NEW_PW)).statusCode).toBe(401);
    });

    it('concurrent redemptions of one token: exactly one wins', async () => {
      await post(app, 'password-reset', { email: 'other@example.test' });
      const token = (lastJob() as { token: string }).token;
      const results = await Promise.all(
        ['concurrent passphrase A1', 'concurrent passphrase B2', 'concurrent passphrase C3'].map(
          (password) => post(app, 'password-reset', { token, password }),
        ),
      );
      expect(results.filter((r) => r.statusCode === 204)).toHaveLength(1);
      expect(results.filter((r) => r.statusCode === 400)).toHaveLength(2);
      // restore a known password for later tests
      await ownerQuery(`UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1`, [
        U_OTHER,
        await hashPassword(NEW_PW),
      ]);
    });

    it('a failing mail queue does not change the response', async () => {
      const broken = await buildApp({
        config: {
          logLevel: 'silent',
          rateLimit: { login: BIG, reset: BIG, token: { ipMax: 100, windowSeconds: 60 } },
        },
        db,
        accountMail: { enqueue: () => Promise.reject(new Error('queue down')) },
      });
      const r = await post(broken, 'password-reset', { email: 'ia@example.test' });
      expect(r.statusCode).toBe(202);
      await broken.close();
    });

    it('rejects bad content types and bodies', async () => {
      const plain = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/password-reset',
        headers: { 'content-type': 'text/plain' },
        payload: '{"email":"ia@example.test"}',
      });
      expect(plain.statusCode).toBe(415);
      expect((await post(app, 'password-reset', {})).statusCode).toBe(400);
      expect((await post(app, 'password-reset', { email: 7 })).statusCode).toBe(400);
    });
  });

  describe('rate limiting', () => {
    it('locks an account after N attempts, even for the right password, with Retry-After', async () => {
      const a = await newAccountApp({ login: { ipMax: 100, accountMax: 3, windowSeconds: 900 } });
      for (let i = 0; i < 3; i++)
        expect((await login('ia@example.test', 'wrong password', a)).statusCode).toBe(401);
      const blocked = await login('ia@example.test', NEW_PW, a);
      expect(blocked.statusCode).toBe(429);
      expect(blocked.json().error.code).toBe('RATE_LIMITED');
      expect(Number(blocked.headers['retry-after'])).toBeGreaterThan(0);
      // another account is unaffected, and unknown emails are limited the same way
      expect((await login('other@example.test', NEW_PW, a)).statusCode).toBe(200);
      for (let i = 0; i < 3; i++)
        expect((await login('ghost@example.test', 'x', a)).statusCode).toBe(401);
      expect((await login('ghost@example.test', 'x', a)).statusCode).toBe(429);
      await a.close();
    });

    it('a successful login clears the account counter', async () => {
      const a = await newAccountApp({ login: { ipMax: 100, accountMax: 3, windowSeconds: 900 } });
      for (let round = 0; round < 3; round++) {
        expect((await login('ia@example.test', 'wrong', a)).statusCode).toBe(401);
        expect((await login('ia@example.test', 'wrong', a)).statusCode).toBe(401);
        expect((await login('ia@example.test', NEW_PW, a)).statusCode).toBe(200);
      }
      await a.close();
    });

    it('limits per IP across accounts, independently per address', async () => {
      const a = await newAccountApp({ login: { ipMax: 4, accountMax: 100, windowSeconds: 900 } });
      for (let i = 0; i < 4; i++) {
        expect((await login(`u${i}@example.test`, 'x', a, '10.0.0.1')).statusCode).toBe(401);
      }
      const blocked = await login('u9@example.test', 'x', a, '10.0.0.1');
      expect(blocked.statusCode).toBe(429);
      expect(blocked.headers['retry-after']).toBeDefined();
      expect((await login('u9@example.test', 'x', a, '10.0.0.2')).statusCode).toBe(401);
      await a.close();
    });

    it('limits reset requests per address and per IP, identically for unknown emails', async () => {
      const a = await newAccountApp({ reset: { ipMax: 100, accountMax: 2, windowSeconds: 900 } });
      for (const email of ['ia@example.test', 'ghost@example.test']) {
        expect((await post(a, 'password-reset', { email })).statusCode).toBe(202);
        expect((await post(a, 'password-reset', { email })).statusCode).toBe(202);
        const r = await post(a, 'password-reset', { email });
        expect(r.statusCode).toBe(429);
        expect(r.headers['retry-after']).toBeDefined();
      }
      await a.close();
      const b = await newAccountApp({ reset: { ipMax: 2, accountMax: 100, windowSeconds: 900 } });
      expect((await post(b, 'password-reset', { email: 'a@example.test' })).statusCode).toBe(202);
      expect((await post(b, 'password-reset', { email: 'b@example.test' })).statusCode).toBe(202);
      expect((await post(b, 'password-reset', { email: 'c@example.test' })).statusCode).toBe(429);
      await b.close();
    });

    it('limits token redemption attempts per IP', async () => {
      const a = await newAccountApp({ token: { ipMax: 2, windowSeconds: 900 } });
      const bad = () =>
        post(a, 'invites/accept', {
          token: randomBytes(32).toString('base64url'),
          password: NEW_PW,
        });
      expect((await bad()).statusCode).toBe(400);
      expect((await bad()).statusCode).toBe(400);
      expect((await bad()).statusCode).toBe(429);
      expect(
        (
          await post(a, 'password-reset', {
            token: randomBytes(32).toString('base64url'),
            password: NEW_PW,
          })
        ).statusCode,
      ).toBe(429);
      await a.close();
    });
  });

  describe('hardening', () => {
    it('withLookup only accepts allowlisted keys', async () => {
      for (const key of ['app.institution_id', 'app.is_platform_admin', 'app.anything', 'x']) {
        await expect(db.withLookup({ [key]: INST } as never, async () => 1)).rejects.toThrow(
          TypeError,
        );
      }
      await expect(db.withLookup({ 'app.login_email': 'a@b.c' }, async () => 1)).resolves.toBe(1);
    });

    it('verifyPassword with no stored hash is false and uses the precomputed dummy hash', async () => {
      expect(await verifyPassword(null, 'whatever')).toBe(false);
      expect(await verifyPassword('garbage', 'whatever')).toBe(false);
    });

    it('never logs tokens, passwords or emails from reset/invite flows', async () => {
      await post(app, 'password-reset', { email: 'ia@example.test' });
      const t = (lastJob() as { token: string }).token;
      await post(app, 'password-reset', { token: t, password: 'logged-password-marker-1' });
      await post(app, 'invites/accept', { token: t, password: 'logged-password-marker-2' });
      const all = logs.join('');
      expect(all.length).toBeGreaterThan(0);
      for (const secret of [t, sha(t), 'logged-password-marker-1', 'logged-password-marker-2']) {
        expect(all).not.toContain(secret);
      }
      expect(all).not.toContain('ia@example.test');
    });
  });
});
