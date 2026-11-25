// Integration tests for login / logout / me (T-009). Skipped when DATABASE_URL is unset. Applies
// every migration into a scratch schema and connects the API pool as the restricted igaro_app role.
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { Writable } from 'node:stream';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import type { FastifyInstance } from 'fastify';
import { buildApp } from './app.js';
import { csrfTokenFor, hashPassword } from './auth.js';
import { Db } from './db.js';

const url = process.env.DATABASE_URL;
const migrationsDir = new URL('../../../packages/db/prisma/migrations/', import.meta.url);

const INST = '11111111-1111-4111-8111-111111111111';
const OTHER = '22222222-2222-4222-8222-222222222222';
const U_IA = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const U_PA = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const U_OFF = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const U_NOPW = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const U_OTHER = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';

const PW = 'correct horse battery staple';
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const json = { 'content-type': 'application/json' };

describe.skipIf(!url)('auth: login, logout, me (needs Postgres at DATABASE_URL)', () => {
  const schema = `t009_${randomBytes(4).toString('hex')}`;
  let owner: pg.Client;
  let db: Db;
  let app: FastifyInstance;
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

  const login = (email = 'ia@example.test', password = PW, headers: Record<string, string> = {}) =>
    app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      headers: { ...json, ...headers },
      payload: { email, password },
    });

  const cookieOf = (res: { headers: Record<string, unknown> }) => {
    const sc = res.headers['set-cookie'];
    const line = Array.isArray(sc) ? sc[0] : (sc as string);
    return { line: line as string, pair: (line as string).split(';')[0]! };
  };

  const tokenOf = (res: { headers: Record<string, unknown> }) => cookieOf(res).pair.split('=')[1]!;

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
    const insUser = (
      id: string,
      inst: string | null,
      email: string,
      role: string,
      hash: string | null,
      status = 'ACTIVE',
    ) =>
      ownerQuery(
        `INSERT INTO users (id, institution_id, email, name, password_hash, role, status, updated_at)
         VALUES ($1,$2,$3,'Name',$4,$5,$6,now())`,
        [id, inst, email, hash, role, status],
      );
    await insUser(U_IA, INST, 'ia@example.test', 'INSTITUTION_ADMIN', pwHash);
    await insUser(U_PA, null, 'pa@example.test', 'PLATFORM_ADMIN', pwHash);
    await insUser(U_OFF, INST, 'off@example.test', 'INSTITUTION_ADMIN', pwHash, 'DISABLED');
    await insUser(U_NOPW, INST, 'nopw@example.test', 'INSTITUTION_ADMIN', null);
    await insUser(U_OTHER, OTHER, 'other@example.test', 'INSTITUTION_ADMIN', pwHash);

    db = new Db({
      connectionString: url!,
      max: 4,
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
        cookie: { name: 'igaro_session', secure: true, sameSite: 'lax', domain: undefined },
        session: { idleSeconds: 1800, maxSeconds: 8 * 3600 },
        // These tests log in and fail on purpose many times from one address; limits are tested in
        // account.test.ts.
        rateLimit: {
          login: { ipMax: 10000, accountMax: 10000, windowSeconds: 900 },
          reset: { ipMax: 10000, accountMax: 10000, windowSeconds: 900 },
          token: { ipMax: 10000, windowSeconds: 900 },
        },
      },
      db,
      logStream,
    });
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

  describe('login', () => {
    it('logs an institution admin in: cookie flags, body, hashed token at rest', async () => {
      const res = await login('  IA@Example.test ');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.user).toEqual({
        id: U_IA,
        email: 'ia@example.test',
        name: 'Name',
        role: 'INSTITUTION_ADMIN',
      });
      expect(body.institution).toMatchObject({ id: INST, slug: 'one', status: 'ACTIVE' });
      const { line } = cookieOf(res);
      expect(line).toMatch(/^igaro_session=[A-Za-z0-9_-]{43};/);
      expect(line).toContain('HttpOnly');
      expect(line).toContain('Secure');
      expect(line).toContain('SameSite=Lax');
      expect(line).toContain('Path=/');
      expect(res.headers['cache-control']).toBe('no-store');
      const token = tokenOf(res);
      expect(body.csrfToken).toBe(csrfTokenFor(token));
      expect(JSON.stringify(body)).not.toContain(token);
      expect(JSON.stringify(body)).not.toContain('password');

      const rows = (await ownerQuery(`SELECT * FROM sessions WHERE user_id = $1`, [U_IA])).rows;
      const row = rows.find((r) => r.token_hash === sha(token));
      expect(row).toBeTruthy();
      expect(row.institution_id).toBe(INST);
      expect(JSON.stringify(rows)).not.toContain(token);
      // The client IP is stored hashed (ADR 0003), never raw.
      expect(row.ip).toMatch(/^[0-9a-f]{32}$/);
    });

    it('logs a platform admin in with no institution', async () => {
      const res = await login('pa@example.test');
      expect(res.statusCode).toBe(200);
      expect(res.json().user.role).toBe('PLATFORM_ADMIN');
      expect(res.json().institution).toBeNull();
      const me = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/me',
        headers: { cookie: cookieOf(res).pair },
      });
      expect(me.statusCode).toBe(200);
      expect(me.json().institution).toBeNull();
    });

    it('returns the identical generic 401 for unknown user, wrong password, disabled and no-password users', async () => {
      const results = [
        await login('nobody@example.test'),
        await login('ia@example.test', 'wrong password'),
        await login('off@example.test'),
        await login('nopw@example.test'),
      ];
      for (const r of results) {
        expect(r.statusCode).toBe(401);
        expect(r.headers['set-cookie']).toBeUndefined();
      }
      const bodies = new Set(results.map((r) => r.body));
      expect(bodies.size).toBe(1);
      expect(results[0]!.json()).toEqual({
        error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password' },
      });
    });

    it('rejects malformed bodies with 400 and non-JSON content types with 415', async () => {
      for (const payload of [
        {},
        { email: 'a@b.c' },
        { email: 1, password: 'x' },
        { email: 'a@b.c', password: 'x'.repeat(300) },
      ]) {
        const r = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/login',
          headers: json,
          payload,
        });
        expect(r.statusCode).toBe(400);
      }
      const form = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        payload: 'email=ia@example.test&password=x',
      });
      expect(form.statusCode).toBe(415);
      const plain = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        headers: { 'content-type': 'text/plain' },
        payload: JSON.stringify({ email: 'ia@example.test', password: PW }),
      });
      expect(plain.statusCode).toBe(415);
    });

    it('replaces the session the browser already holds', async () => {
      const first = await login();
      const second = await login('ia@example.test', PW, { cookie: cookieOf(first).pair });
      expect(second.statusCode).toBe(200);
      const old = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/me',
        headers: { cookie: cookieOf(first).pair },
      });
      expect(old.statusCode).toBe(401);
    });

    it('omits Secure when the cookie config says so (dev/test)', async () => {
      const dev = await buildApp({
        config: {
          logLevel: 'silent',
          cookie: { name: 'sid', secure: false, sameSite: 'lax', domain: 'example.test' },
        },
        db,
      });
      const res = await dev.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        headers: json,
        payload: { email: 'ia@example.test', password: PW },
      });
      const { line } = cookieOf(res);
      expect(line).toMatch(/^sid=/);
      expect(line).not.toContain('Secure');
      expect(line).toContain('HttpOnly');
      expect(line).toContain('Domain=example.test');
      await dev.close();
    });
  });

  describe('me and session handling', () => {
    it('401 without a cookie, with a garbage cookie, and with a well-formed unknown token', async () => {
      for (const cookie of [
        undefined,
        'igaro_session=garbage',
        `igaro_session=${randomBytes(32).toString('base64url')}`,
      ]) {
        const r = await app.inject({
          method: 'GET',
          url: '/api/v1/auth/me',
          headers: cookie ? { cookie } : {},
        });
        expect(r.statusCode).toBe(401);
        expect(r.json().error.code).toBe('UNAUTHENTICATED');
      }
    });

    it('a stored hash is not usable as a cookie value', async () => {
      const res = await login();
      const hash = sha(tokenOf(res));
      const r = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/me',
        headers: { cookie: `igaro_session=${hash}` },
      });
      expect(r.statusCode).toBe(401);
    });

    it('me returns user, role, institution and a stable csrf token', async () => {
      const res = await login();
      const me = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/me',
        headers: { cookie: cookieOf(res).pair },
      });
      expect(me.statusCode).toBe(200);
      expect(me.json()).toEqual(res.json());
    });

    it('tenant scope comes from the session row: each admin sees only their own institution', async () => {
      const a = await login();
      const b = await login('other@example.test');
      const meA = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/me',
        headers: { cookie: cookieOf(a).pair },
      });
      const meB = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/me',
        headers: { cookie: cookieOf(b).pair },
      });
      expect(meA.json().institution.id).toBe(INST);
      expect(meB.json().institution.id).toBe(OTHER);
    });

    it('enforces the idle timeout and deletes the expired row', async () => {
      const res = await login();
      const token = tokenOf(res);
      await ownerQuery(
        `UPDATE sessions SET expires_at = now() - interval '1 second' WHERE token_hash = $1`,
        [sha(token)],
      );
      const r = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/me',
        headers: { cookie: cookieOf(res).pair },
      });
      expect(r.statusCode).toBe(401);
      const left = await ownerQuery(`SELECT 1 FROM sessions WHERE token_hash = $1`, [sha(token)]);
      expect(left.rowCount).toBe(0);
    });

    it('enforces the absolute lifetime even if the idle deadline keeps sliding', async () => {
      const res = await login();
      const token = tokenOf(res);
      await ownerQuery(
        `UPDATE sessions SET created_at = now() - interval '9 hours', expires_at = now() + interval '1 hour' WHERE token_hash = $1`,
        [sha(token)],
      );
      const r = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/me',
        headers: { cookie: cookieOf(res).pair },
      });
      expect(r.statusCode).toBe(401);
    });

    it('slides the idle deadline on use, never past the absolute limit', async () => {
      const res = await login();
      const token = tokenOf(res);
      await ownerQuery(
        `UPDATE sessions SET expires_at = now() + interval '5 seconds' WHERE token_hash = $1`,
        [sha(token)],
      );
      const r = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/me',
        headers: { cookie: cookieOf(res).pair },
      });
      expect(r.statusCode).toBe(200);
      const row = (
        await ownerQuery(
          `SELECT extract(epoch from (expires_at - now())) AS left_s FROM sessions WHERE token_hash = $1`,
          [sha(token)],
        )
      ).rows[0];
      expect(Number(row.left_s)).toBeGreaterThan(1700);

      await ownerQuery(
        `UPDATE sessions SET created_at = now() - interval '7 hours 59 minutes 30 seconds', expires_at = now() + interval '5 seconds' WHERE token_hash = $1`,
        [sha(token)],
      );
      await app.inject({
        method: 'GET',
        url: '/api/v1/auth/me',
        headers: { cookie: cookieOf(res).pair },
      });
      const capped = (
        await ownerQuery(
          `SELECT extract(epoch from (expires_at - now())) AS left_s FROM sessions WHERE token_hash = $1`,
          [sha(token)],
        )
      ).rows[0];
      expect(Number(capped.left_s)).toBeLessThan(60);
    });

    it('a user disabled after login loses the session', async () => {
      await ownerQuery(`UPDATE users SET status = 'ACTIVE', updated_at = now() WHERE id = $1`, [
        U_OFF,
      ]);
      const res = await login('off@example.test');
      expect(res.statusCode).toBe(200);
      await ownerQuery(`UPDATE users SET status = 'DISABLED', updated_at = now() WHERE id = $1`, [
        U_OFF,
      ]);
      const r = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/me',
        headers: { cookie: cookieOf(res).pair },
      });
      expect(r.statusCode).toBe(401);
    });

    it('the app role cannot rewrite token_hash, user_id or institution_id of a session', async () => {
      await login();
      for (const col of ['token_hash', 'user_id', 'institution_id']) {
        await expect(
          db.withTenant({ kind: 'platform', userId: U_PA }, (c) =>
            c.query(`UPDATE sessions SET ${col} = ${col}`),
          ),
        ).rejects.toMatchObject({ code: '42501' });
      }
    });
  });

  describe('logout and CSRF', () => {
    it('requires the CSRF header for a live session and does not delete it without it', async () => {
      const res = await login();
      const cookie = cookieOf(res).pair;
      for (const headers of [
        { cookie },
        { cookie, 'x-csrf-token': 'wrong' },
        { cookie, 'x-csrf-token': csrfTokenFor('x'.repeat(43)) },
      ]) {
        const r = await app.inject({ method: 'POST', url: '/api/v1/auth/logout', headers });
        expect(r.statusCode).toBe(403);
        expect(r.json().error.code).toBe('CSRF_REQUIRED');
      }
      const still = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/me',
        headers: { cookie },
      });
      expect(still.statusCode).toBe(200);
    });

    it('logs out: deletes the row, clears the cookie, and the token stops working', async () => {
      const res = await login();
      const cookie = cookieOf(res).pair;
      const out = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/logout',
        headers: { cookie, 'x-csrf-token': res.json().csrfToken },
      });
      expect(out.statusCode).toBe(204);
      const cleared = cookieOf(out).line;
      expect(cleared).toMatch(/^igaro_session=;/);
      expect(cleared).toContain('Max-Age=0');
      expect(cleared).toContain('HttpOnly');
      const after = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/me',
        headers: { cookie },
      });
      expect(after.statusCode).toBe(401);
      const rows = await ownerQuery(`SELECT 1 FROM sessions WHERE token_hash = $1`, [
        sha(tokenOf(res)),
      ]);
      expect(rows.rowCount).toBe(0);
    });

    it('logout is idempotent without a session and clears a stale cookie', async () => {
      const r = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/logout',
        headers: { cookie: `igaro_session=${randomUUID()}` },
      });
      expect(r.statusCode).toBe(204);
      expect(cookieOf(r).line).toContain('Max-Age=0');
    });

    it("one session's CSRF token does not work for another session", async () => {
      const a = await login();
      const b = await login();
      const r = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/logout',
        headers: { cookie: cookieOf(a).pair, 'x-csrf-token': b.json().csrfToken },
      });
      expect(r.statusCode).toBe(403);
    });
  });

  describe('logging', () => {
    it('never writes passwords, session tokens, csrf tokens or cookies to the logs', async () => {
      const res = await login();
      const token = tokenOf(res);
      const csrf = res.json().csrfToken as string;
      await app.inject({
        method: 'GET',
        url: '/api/v1/auth/me',
        headers: { cookie: cookieOf(res).pair },
      });
      await login('ia@example.test', 'a-wrong-password-marker');
      await app.inject({
        method: 'POST',
        url: '/api/v1/auth/logout',
        headers: { cookie: cookieOf(res).pair, 'x-csrf-token': csrf },
      });
      const all = logs.join('');
      expect(all.length).toBeGreaterThan(0);
      for (const secret of [token, csrf, PW, 'a-wrong-password-marker', sha(token)]) {
        expect(all).not.toContain(secret);
      }
    });
  });
});
