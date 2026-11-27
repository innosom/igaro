// Postgres-backed rate limiter (T-052, ADR 0040). Skipped when DATABASE_URL is unset.
// Runs as igaro_app in a scratch schema. Includes two app instances sharing one database.
import { randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import pg from 'pg';
import { buildApp } from './app.js';
import { Db } from './db.js';
import { AppError } from './errors.js';
import { PgRateLimiter } from './rate-limit.js';

const url = process.env.DATABASE_URL;
const migrationsDir = new URL('../../../packages/db/prisma/migrations/', import.meta.url);
const json = { 'content-type': 'application/json' };
const BIG = { ipMax: 10000, accountMax: 10000, windowSeconds: 900 };
const ipHashKey = randomBytes(32);

describe.skipIf(!url)('Postgres rate limiter (needs Postgres)', () => {
  const schema = `t052_${randomBytes(4).toString('hex')}`;
  let owner: pg.Client;
  let db: Db;
  const rows = async () => (await owner.query('SELECT "key", "count" FROM rate_limit_counters ORDER BY "key"')).rows as { key: string; count: number }[];

  beforeAll(async () => {
    owner = new pg.Client({ connectionString: url });
    await owner.connect();
    await owner.query(`CREATE SCHEMA "${schema}"`);
    await owner.query(`SET search_path TO "${schema}"`);
    const dirs = readdirSync(migrationsDir, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name).sort();
    for (const d of dirs) await owner.query(readFileSync(new URL(`${d}/migration.sql`, migrationsDir), 'utf8'));
    await owner.query(`GRANT USAGE ON SCHEMA "${schema}" TO igaro_app`);
    db = new Db({ connectionString: url!, max: 8, poolConfig: { options: `-c search_path=${schema} -c role=igaro_app` } });
  });

  afterAll(async () => {
    await db?.close();
    if (!owner) return;
    await owner.query('RESET search_path');
    await owner.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    await owner.end();
  });

  const mk = (family: string, max: number, extra: Partial<ConstructorParameters<typeof PgRateLimiter>[0]> = {}) =>
    new PgRateLimiter({ db, family, max, windowSeconds: 60, onError: 'closed', ...extra });

  it('allows max attempts, then returns seconds to wait; blocked attempts do not extend the window', async () => {
    let t = 1_800_000_000_000;
    const l = mk('u1', 2, { now: () => t });
    expect(await l.consume('a')).toBe(0);
    expect(await l.consume('a')).toBe(0);
    expect(await l.consume('a')).toBe(60);
    t += 30_000;
    expect(await l.consume('a')).toBe(30);
    expect(await l.consume('a')).toBe(30);
    expect(await l.consume('b')).toBe(0); // other keys are independent
    t += 31_000;
    expect(await l.consume('a')).toBe(0); // new window
  });

  it('reset clears a key', async () => {
    const l = mk('u2', 1);
    expect(await l.consume('a')).toBe(0);
    expect(await l.consume('a')).toBeGreaterThan(0);
    await l.reset('a');
    expect(await l.consume('a')).toBe(0);
  });

  it('namespaces keys per family and stores nothing but the namespaced key', async () => {
    const a = mk('fam-a', 1);
    const b = mk('fam-b', 1);
    const key = 'deadbeef'.repeat(8);
    expect(await a.consume(key)).toBe(0);
    expect(await b.consume(key)).toBe(0); // same key, other family: separate counter
    expect(await a.consume(key)).toBeGreaterThan(0);
    const keys = (await rows()).map((r) => r.key);
    expect(keys).toContain(`fam-a:${key}`);
    expect(keys).toContain(`fam-b:${key}`);
  });

  it('is atomic under concurrency: exactly max of N parallel attempts are allowed', async () => {
    const l = mk('u3', 5);
    const out = await Promise.all(Array.from({ length: 40 }, () => l.consume('k')));
    expect(out.filter((w) => w === 0).length).toBe(5);
    expect(out.filter((w) => w > 0).length).toBe(35);
    const row = (await rows()).find((r) => r.key === 'u3:k')!;
    expect(row.count).toBe(6); // saturates at max + 1
  });

  it('opportunistically deletes expired rows in a bounded table', async () => {
    await db.pool.query(`INSERT INTO rate_limit_counters ("key", "count", "reset_at") VALUES ('old:1', 3, now() - interval '1 hour'), ('old:2', 3, now() - interval '1 hour')`);
    const l = mk('u4', 5, { cleanupRate: 1 });
    await l.consume('x');
    for (let i = 0; i < 50 && (await rows()).some((r) => r.key.startsWith('old:')); i++) await new Promise((r) => setTimeout(r, 20));
    const keys = (await rows()).map((r) => r.key);
    expect(keys.some((k) => k.startsWith('old:'))).toBe(false);
    expect(keys).toContain('u4:x');
  });

  it('fails closed (503) or open (memory fallback) when the counters are unreachable', async () => {
    const broken = new Db({ connectionString: url!, max: 2, poolConfig: { options: '-c search_path=t052_does_not_exist -c role=igaro_app' } });
    try {
      const closed = new PgRateLimiter({ db: broken, family: 'f', max: 1, windowSeconds: 60, onError: 'closed' });
      const err = await closed.consume('a').catch((e: unknown) => e);
      expect(err).toBeInstanceOf(AppError);
      expect((err as AppError).statusCode).toBe(503);
      const open = new PgRateLimiter({ db: broken, family: 'f', max: 1, windowSeconds: 60, onError: 'open' });
      expect(await open.consume('a')).toBe(0);
      expect(await open.consume('a')).toBeGreaterThan(0);
    } finally {
      await broken.close();
    }
  });

  describe('blocked-key cache, timeout and single-flight cleanup (T-054)', () => {
    const spyQueries = () => {
      const texts: string[] = [];
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const orig = db.limiterPool.query.bind(db.limiterPool) as any;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const spy = vi.spyOn(db.limiterPool, 'query').mockImplementation(((q: any, ...rest: unknown[]) => {
        texts.push(typeof q === 'string' ? q : q.text);
        return orig(q, ...rest);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      }) as any);
      return { texts, restore: () => spy.mockRestore() };
    };
    const consumeCalls = (texts: string[]) => texts.filter((t) => t.includes('ON CONFLICT')).length;

    it('rejected requests skip the database until the window ends, then the cache never blocks', async () => {
      let t = 1_900_000_000_000;
      const l = mk('c1', 1, { now: () => t });
      expect(await l.consume('a')).toBe(0);
      expect(await l.consume('a')).toBe(60); // from the DB, now cached
      const spy = spyQueries();
      try {
        t += 10_000;
        expect(await l.consume('a')).toBe(50);
        expect(await l.consume('a')).toBe(50);
        expect(consumeCalls(spy.texts)).toBe(0);
        t += 49_999;
        expect(await l.consume('a')).toBe(1); // still inside the window
        expect(consumeCalls(spy.texts)).toBe(0);
        t += 2; // window over: the DB decides and starts a new window
        expect(await l.consume('a')).toBe(0);
        expect(consumeCalls(spy.texts)).toBe(1);
      } finally {
        spy.restore();
      }
    });

    it('reset clears the cache entry', async () => {
      const l = mk('c2', 1);
      expect(await l.consume('a')).toBe(0);
      expect(await l.consume('a')).toBeGreaterThan(0);
      await l.reset('a');
      expect(await l.consume('a')).toBe(0);
    });

    it('a reset that races an in-flight blocked consume is not re-cached', async () => {
      const l = mk('c3', 1);
      expect(await l.consume('a')).toBe(0);
      const inflight = l.consume('a'); // will come back blocked
      await l.reset('a');
      expect(await inflight).toBeGreaterThan(0);
      expect(await l.consume('a')).toBe(0); // not served from a stale cache entry
    });

    it('the cache is bounded', async () => {
      const l = mk('c4', 1, { maxCachedKeys: 3 });
      for (const k of ['a', 'b', 'c', 'd', 'e']) {
        await l.consume(k);
        await l.consume(k);
      }
      expect(((l as unknown as { blocked: Map<string, number> }).blocked).size).toBe(3);
    });

    it('a stuck database hits the query timeout: closed -> 503, open -> memory fallback', async () => {
      await owner.query('BEGIN');
      try {
        await owner.query('LOCK TABLE rate_limit_counters IN ACCESS EXCLUSIVE MODE');
        const started = Date.now();
        const closed = mk('c5', 1, { queryTimeoutMs: 200 });
        const err = await closed.consume('a').catch((e: unknown) => e);
        expect(err).toBeInstanceOf(AppError);
        expect((err as AppError).statusCode).toBe(503);
        expect(Date.now() - started).toBeLessThan(3000);
        const open = mk('c5o', 1, { queryTimeoutMs: 200, onError: 'open' });
        expect(await open.consume('a')).toBe(0);
        expect(await open.consume('a')).toBeGreaterThan(0);
      } finally {
        await owner.query('ROLLBACK');
      }
    });

    it('the limiter pool sets server-side timeouts and Postgres cancels a stuck statement (T-055)', async () => {
      const c = await db.limiterPool.connect();
      try {
        const r = await c.query(`SELECT current_setting('statement_timeout') AS st, current_setting('lock_timeout') AS lt`);
        expect(r.rows[0]).toEqual({ st: '2s', lt: '2s' });
      } finally {
        c.release();
      }
      const short = new Db({
        connectionString: url!,
        max: 2,
        limiterTimeoutMs: 300,
        poolConfig: { options: `-c search_path=${schema} -c role=igaro_app` },
      });
      await owner.query('BEGIN');
      try {
        await owner.query('LOCK TABLE rate_limit_counters IN ACCESS EXCLUSIVE MODE');
        const l = new PgRateLimiter({ db: short, family: 'c7', max: 1, windowSeconds: 60, onError: 'closed', queryTimeoutMs: 60_000 });
        const started = Date.now();
        // The client timeout is far away: only the server-side lock_timeout can end this.
        const err = await l.consume('a').catch((e: unknown) => e);
        expect((err as AppError).statusCode).toBe(503);
        expect(Date.now() - started).toBeLessThan(3000);
        const waiting = await owner.query(`SELECT count(*)::int AS n FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query LIKE '%rate_limit_counters%' AND pid <> pg_backend_pid()`);
        expect(waiting.rows[0].n).toBe(0); // the server dropped the statement, it is not left waiting
      } finally {
        await owner.query('ROLLBACK');
        await short.close();
      }
    });

    it('runs at most one cleanup at a time per process', async () => {
      const seen: string[] = [];
      const orig = db.limiterPool.query.bind(db.limiterPool) as unknown as (...a: unknown[]) => Promise<unknown>;
      // Make cleanup slow so the overlap is certain.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      vi.spyOn(db.limiterPool, 'query').mockImplementation(((q: any, ...rest: unknown[]) => {
        const text = typeof q === 'string' ? q : q.text;
        seen.push(text);
        const p = orig(q, ...rest);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        return text.includes('FOR UPDATE SKIP LOCKED') ? p.then(async (r) => (await new Promise((res) => setTimeout(res, 300)), r)) : p;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      }) as any);
      try {
        const l = mk('c6', 100, { cleanupRate: 1 });
        await Promise.all(Array.from({ length: 10 }, (_, i) => l.consume(`k${i}`)));
        const cleanups = () => seen.filter((t) => t.includes('FOR UPDATE SKIP LOCKED')).length;
        expect(cleanups()).toBe(1);
        await new Promise((r) => setTimeout(r, 450)); // the slow cleanup finishes
        await l.consume('again');
        expect(cleanups()).toBe(2);
      } finally {
        vi.restoreAllMocks();
      }
    });
  });

  it('igaro_app has only SELECT/INSERT/UPDATE/DELETE on the table; PUBLIC has nothing', async () => {
    const r = await owner.query(
      `SELECT grantee, privilege_type FROM information_schema.role_table_grants
        WHERE table_schema = $1 AND table_name = 'rate_limit_counters' AND grantee <> current_user`,
      [schema],
    );
    const byGrantee = new Map<string, string[]>();
    for (const x of r.rows) byGrantee.set(x.grantee, [...(byGrantee.get(x.grantee) ?? []), x.privilege_type].sort());
    expect([...byGrantee.keys()]).toEqual(['igaro_app']);
    expect(byGrantee.get('igaro_app')).toEqual(['DELETE', 'INSERT', 'SELECT', 'UPDATE']);
  });

  describe('two API instances sharing one database', () => {
    const cfg = (login: typeof BIG, verify: { ipMax: number; tokenMax: number; windowSeconds: number }) => ({
      logLevel: 'silent' as const,
      ipHashKey,
      masterKey: randomBytes(32),
      rateLimit: { login, reset: BIG, token: { ipMax: 10000, windowSeconds: 900 }, verify },
    });
    const login = (a: Awaited<ReturnType<typeof buildApp>>, ip: string, email = 'nobody@example.test') =>
      a.inject({ method: 'POST', url: '/api/v1/auth/login', headers: json, remoteAddress: ip, payload: { email, password: 'wrong password 123' } });
    const verifyReq = (a: Awaited<ReturnType<typeof buildApp>>, ip: string, token: string) =>
      a.inject({ method: 'GET', url: `/api/v1/verify/${token}`, remoteAddress: ip });

    it('a login limit consumed on instance A blocks instance B', async () => {
      const lim = cfg({ ipMax: 2, accountMax: 10000, windowSeconds: 900 }, { ipMax: 10000, tokenMax: 10000, windowSeconds: 60 });
      const a = await buildApp({ config: lim, db });
      const b = await buildApp({ config: lim, db });
      try {
        expect((await login(a, '192.0.2.10')).statusCode).toBe(401);
        expect((await login(a, '192.0.2.10')).statusCode).toBe(401);
        const blocked = await login(b, '192.0.2.10');
        expect(blocked.statusCode).toBe(429);
        expect(Number(blocked.headers['retry-after'])).toBeGreaterThan(0);
        expect((await login(b, '192.0.2.11')).statusCode).toBe(401); // another IP is unaffected
      } finally {
        await a.close();
        await b.close();
      }
    });

    it('a per-account login limit is shared too', async () => {
      const lim = cfg({ ipMax: 10000, accountMax: 1, windowSeconds: 900 }, { ipMax: 10000, tokenMax: 10000, windowSeconds: 60 });
      const a = await buildApp({ config: lim, db });
      const b = await buildApp({ config: lim, db });
      try {
        expect((await login(a, '192.0.2.20', 'acct@example.test')).statusCode).toBe(401);
        expect((await login(b, '192.0.2.21', 'acct@example.test')).statusCode).toBe(429);
      } finally {
        await a.close();
        await b.close();
      }
    });

    it('verify per-IP and per-token limits are shared across instances', async () => {
      const lim = cfg(BIG, { ipMax: 3, tokenMax: 2, windowSeconds: 60 });
      const a = await buildApp({ config: lim, db });
      const b = await buildApp({ config: lim, db });
      try {
        const ip = '198.51.100.50';
        expect((await verifyReq(a, ip, randomBytes(16).toString('base64url'))).statusCode).toBe(200);
        expect((await verifyReq(b, ip, randomBytes(16).toString('base64url'))).statusCode).toBe(200);
        expect((await verifyReq(a, ip, randomBytes(16).toString('base64url'))).statusCode).toBe(200);
        expect((await verifyReq(b, ip, randomBytes(16).toString('base64url'))).statusCode).toBe(429);
        expect((await verifyReq(a, ip, randomBytes(16).toString('base64url'))).statusCode).toBe(429);

        // Per token (misses): two misses on A, the third on B from a fresh IP is refused.
        const tok = randomBytes(16).toString('base64url');
        expect((await verifyReq(a, '198.51.100.60', tok)).statusCode).toBe(200);
        expect((await verifyReq(a, '198.51.100.61', tok)).statusCode).toBe(200);
        expect((await verifyReq(b, '198.51.100.62', tok)).statusCode).toBe(429);
      } finally {
        await a.close();
        await b.close();
      }
    });

    it('no raw IP, email or token is stored in the counters', async () => {
      const text = JSON.stringify(await rows());
      for (const raw of ['192.0.2.10', '198.51.100.50', 'nobody@example.test']) expect(text).not.toContain(raw);
    });
  });
});
