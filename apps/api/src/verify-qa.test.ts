// QA tests for W4 verification (T-037). White paper section 15 / docs/acceptance/W4.md. Skipped when DATABASE_URL is unset.
//   W4 "1000 verify requests -> p95 < 300 ms"            : 'p95 ...'
//   W4 "repeated requests -> 429, hashed IP in the log"  : 'enumeration ...'
//   W4 "credential.json + keys.json, verify-cli offline" : 'CLI vs API ...'
//   W4 "signed field edited in DB -> VERIFICATION FAILED": 'DB tamper ...'
// Runs as igaro_app (RLS on) in a scratch schema. Test values only.
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Writable } from 'node:stream';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import type { FastifyInstance } from 'fastify';
import { generateSigningKey } from '@igaro/core';
import { buildApp } from './app.js';
import { csrfTokenFor, hashPassword } from './auth.js';
import { Db } from './db.js';
import { DEFAULT_VERIFY_LIMIT } from './config.js';

const url = process.env.DATABASE_URL;
// The CLI lives outside this package's tsc rootDir, so it is loaded by path at run time (the typed surface is just `main`).
type CliMain = (argv: readonly string[], io: { stdout: (s: string) => void; stderr: (s: string) => void; fetch?: typeof fetch }) => Promise<number>;
const cliPath = fileURLToPath(new URL('../../../tools/verify-cli/src/cli.ts', import.meta.url));
let cliMainFn: CliMain | undefined;
const cliMain: CliMain = async (argv, io) => {
  cliMainFn ??= ((await import(/* @vite-ignore */ cliPath)) as { main: CliMain }).main;
  return cliMainFn(argv, io);
};
const migrationsDir = new URL('../../../packages/db/prisma/migrations/', import.meta.url);

const PW = 'correct horse battery staple';
const json = { 'content-type': 'application/json' };
const BIG = { ipMax: 10000, accountMax: 10000, windowSeconds: 900 };
const PHOTO_SHA = createHash('sha256').update('photo-qa').digest('hex');
const ipHashKey = randomBytes(32);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

type Tag = 'A' | 'C';
const ID = (n: number) => `${n}${n}${n}${n}${n}${n}${n}${n}-${n}${n}${n}${n}-4${n}${n}${n}-8${n}${n}${n}-${String(n).repeat(12)}`;
const INST: Record<Tag, string> = { A: ID(1), C: ID(2) };
const USER: Record<Tag, string> = { A: ID(3), C: ID(4) };
const HOLDER: Record<Tag, string> = { A: ID(5), C: ID(6) };

interface Client { headers: Record<string, string> }
interface Issued { id: string; verificationToken: string; holderToken: string; credentialNumber: string; payload: { salt: string; issuerKeyId: string } }
type Body = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

describe.skipIf(!url)('W4 verification QA (needs Postgres)', () => {
  const schema = `t037_${randomBytes(4).toString('hex')}`;
  const master = randomBytes(32);
  const lines: string[] = [];
  const logStream = new Writable({ write(chunk, _e, cb) { lines.push(String(chunk)); cb(); } });
  const tmp = mkdtempSync(join(tmpdir(), 'igaro-t037-'));
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
  const verify = (token: string, ip = '203.0.113.9', a: FastifyInstance = app) =>
    a.inject({ method: 'GET', url: `/api/v1/verify/${token}`, remoteAddress: ip });
  const result = async (token: string) => ((await verify(token)).json() as Body).result as string;
  const tamper = (id: string, sql: string, params: unknown[] = []) => ownerQuery(`UPDATE credentials SET ${sql} WHERE id = $1`, [id, ...params], true);

  /** Download credential.json and keys.json through the public API and run the offline CLI on them (no verify API call). */
  const runCli = async (c: Issued, slug: string, mutate?: (text: string) => string) => {
    const credRes = await app.inject({ method: 'GET', url: `/api/v1/verify/${c.verificationToken}/credential.json` });
    expect(credRes.statusCode).toBe(200);
    const keysRes = await app.inject({ method: 'GET', url: `/i/${slug}/keys.json` });
    expect(keysRes.statusCode).toBe(200);
    const dir = mkdtempSync(join(tmp, 'run-'));
    const credPath = join(dir, 'credential.json');
    const keysPath = join(dir, 'keys.json');
    writeFileSync(credPath, mutate ? mutate(credRes.body) : credRes.body);
    writeFileSync(keysPath, keysRes.body);
    let out = '';
    let err = '';
    const code = await cliMain([credPath, '--keys', keysPath, '--json'], {
      stdout: (s) => { out += s; },
      stderr: (s) => { err += s; },
      fetch: (() => { throw new Error('network disabled'); }) as unknown as typeof fetch, // the CLI must never need the network
    });
    return { code, out, err, parsed: out ? (JSON.parse(out) as Body) : ({} as Body), credText: credRes.body };
  };

  beforeAll(async () => {
    owner = new pg.Client({ connectionString: url });
    await owner.connect();
    await owner.query(`CREATE SCHEMA "${schema}"`);
    await owner.query(`SET search_path TO "${schema}"`);
    const dirs = readdirSync(migrationsDir, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name).sort();
    for (const d of dirs) await owner.query(readFileSync(new URL(`${d}/migration.sql`, migrationsDir), 'utf8'));
    await owner.query(`GRANT USAGE ON SCHEMA "${schema}" TO igaro_app`);

    const pwHash = await hashPassword(PW);
    for (const t of ['A', 'C'] as const) {
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
      config: { logLevel: 'info', ipHashKey, masterKey: master, rateLimit: { login: BIG, reset: BIG, token: { ipMax: 10000, windowSeconds: 900 }, verify: { ipMax: 100000, tokenMax: 100000, windowSeconds: 60 } } },
      db,
      logStream,
    });
    for (const t of ['A', 'C'] as const) client[t] = await loginAs(`${t.toLowerCase()}@example.test`);
  });

  afterAll(async () => {
    await app?.close();
    await db?.close();
    rmSync(tmp, { recursive: true, force: true });
    if (!owner) return;
    await owner.query('ROLLBACK').catch(() => undefined);
    await owner.query('RESET search_path');
    await owner.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    await owner.end();
  });

  // ---------------------------------------------------------------- performance (W4: 1000 requests, p95 < 300 ms)
  it('p95 latency of GET /verify/:token is under 300 ms over 1000 real HTTP requests (20 concurrent)', async () => {
    const real = await issue('A');
    const quiet = await buildApp({
      config: { logLevel: 'silent', ipHashKey, masterKey: master, rateLimit: { login: BIG, reset: BIG, token: { ipMax: 10000, windowSeconds: 900 }, verify: { ipMax: 100000, tokenMax: 100000, windowSeconds: 60 } } },
      db,
    });
    try {
      const address = await quiet.listen({ port: 0, host: '127.0.0.1' });
      const target = `${address}/api/v1/verify/${real.verificationToken}`;
      const N = 1000;
      const CONCURRENCY = 20;
      const times: number[] = [];
      let sent = 0;
      let nonVerified = 0;
      const worker = async () => {
        while (sent < N) {
          sent++;
          const t0 = performance.now();
          const res = await fetch(target);
          const body = (await res.json()) as Body;
          times.push(performance.now() - t0);
          if (res.status !== 200 || body.result !== 'VERIFIED') nonVerified++;
        }
      };
      await fetch(target); // warm-up (pool connections, JIT)
      await Promise.all(Array.from({ length: CONCURRENCY }, worker));
      times.sort((a, b) => a - b);
      const p = (q: number) => times[Math.min(times.length - 1, Math.ceil(q * times.length) - 1)]!;
      console.info(`verify latency over ${times.length} requests: p50=${p(0.5).toFixed(1)}ms p95=${p(0.95).toFixed(1)}ms p99=${p(0.99).toFixed(1)}ms max=${times[times.length - 1]!.toFixed(1)}ms`);
      expect(times).toHaveLength(N);
      expect(nonVerified).toBe(0);
      expect(p(0.95)).toBeLessThan(300);
    } finally {
      await quiet.close();
    }
  }, 120_000);

  // ---------------------------------------------------------------- enumeration and rate limits
  describe('enumeration and rate limits', () => {
    it('verification tokens are 128-bit random: 22 chars of base64url, unique, no shared structure', async () => {
      const toks: string[] = [];
      for (let i = 0; i < 12; i++) toks.push((await issue('A')).verificationToken);
      expect(new Set(toks).size).toBe(toks.length);
      for (const t of toks) {
        expect(t).toMatch(/^[A-Za-z0-9_-]{22}$/);
        expect(Buffer.from(t, 'base64url')).toHaveLength(16);
      }
      // No sequential/shared prefix: first 4 characters (24 bits) should differ across 12 random tokens.
      expect(new Set(toks.map((t) => t.slice(0, 4))).size).toBeGreaterThan(10);
      // Distinct from the holder token (separate secret) and from the human credential number.
      const c = await issue('A');
      expect(c.verificationToken).not.toBe(c.holderToken);
      expect(c.verificationToken).not.toContain(c.credentialNumber);
    });

    it('only the verification token finds a credential: credential number, id, holder token, near-miss tokens are NOT_FOUND', async () => {
      const c = await issue('A');
      const flip = c.verificationToken.slice(0, -1) + (c.verificationToken.endsWith('A') ? 'B' : 'A');
      const miss = [c.credentialNumber, c.id, c.holderToken, flip, c.verificationToken.toUpperCase(), c.verificationToken + 'A', ' ' + c.verificationToken];
      const shapes = new Set<string>();
      for (const [i, t] of miss.entries()) {
        const res = await verify(encodeURIComponent(t), `198.51.100.${i + 1}`);
        expect(res.statusCode).toBe(200);
        const b = res.json() as Body;
        expect(b.result).toBe('NOT_FOUND');
        shapes.add(JSON.stringify(b));
      }
      expect(shapes.size).toBe(1); // identical bodies: no oracle between "malformed" and "well-formed but unknown"
      expect(await result(c.verificationToken)).toBe('VERIFIED');
      // credential.json: same rule.
      for (const t of [c.credentialNumber, c.id, c.holderToken]) {
        expect((await app.inject({ method: 'GET', url: `/api/v1/verify/${encodeURIComponent(t)}/credential.json` })).statusCode).toBe(404);
      }
    });

    it('a DRAFT is indistinguishable from an unknown token', async () => {
      const c = await issue('A');
      await ownerQuery(`UPDATE credentials SET status = 'DRAFT' WHERE id = $1`, [c.id], true);
      const draft = (await verify(c.verificationToken)).json() as Body;
      const unknown = (await verify(randomBytes(16).toString('base64url'))).json() as Body;
      expect(draft).toEqual(unknown);
      expect(draft.result).toBe('NOT_FOUND');
      expect((await app.inject({ method: 'GET', url: `/api/v1/verify/${c.verificationToken}/credential.json` })).statusCode).toBe(404);
    });

    it('default limits: one IP sweeping random tokens gets 429 after the per-IP budget, with Retry-After and no token echoed', async () => {
      const limited = await buildApp({ config: { logLevel: 'silent', ipHashKey, masterKey: master, rateLimit: { login: BIG, reset: BIG, token: { ipMax: 100, windowSeconds: 900 } } }, db });
      try {
        // verify limits omitted on purpose: the shipped defaults apply.
        const budget = DEFAULT_VERIFY_LIMIT.ipMax;
        const statuses: number[] = [];
        let last: Awaited<ReturnType<typeof verify>> | undefined;
        const lastTok = randomBytes(16).toString('base64url');
        for (let i = 0; i < budget + 10; i++) {
          last = await verify(i === budget + 9 ? lastTok : randomBytes(16).toString('base64url'), '192.0.2.50', limited);
          statuses.push(last.statusCode);
        }
        expect(statuses.slice(0, budget).every((s) => s === 200)).toBe(true);
        expect(statuses.slice(budget).every((s) => s === 429)).toBe(true);
        expect(Number(last!.headers['retry-after'])).toBeGreaterThan(0);
        expect(last!.body).not.toContain(lastTok);
        // A different client is not affected by that IP's lockout.
        expect((await verify(randomBytes(16).toString('base64url'), '192.0.2.51', limited)).statusCode).toBe(200);
      } finally {
        await limited.close();
      }
    });

    it('default limits: hammering one unknown token from rotating IPs is stopped by the per-token miss budget', async () => {
      const limited = await buildApp({ config: { logLevel: 'silent', ipHashKey, masterKey: master, rateLimit: { login: BIG, reset: BIG, token: { ipMax: 100, windowSeconds: 900 }, verify: { ipMax: 100000, tokenMax: DEFAULT_VERIFY_LIMIT.tokenMax, windowSeconds: 60 } } }, db });
      try {
        const tok = randomBytes(16).toString('base64url');
        let blockedAt = -1;
        for (let i = 0; i < DEFAULT_VERIFY_LIMIT.tokenMax + 5; i++) {
          const res = await verify(tok, `10.${i >> 8}.${i & 255}.1`, limited);
          if (res.statusCode === 429) { blockedAt = i; break; }
        }
        expect(blockedAt).toBe(DEFAULT_VERIFY_LIMIT.tokenMax);
      } finally {
        await limited.close();
      }
    });

    it('every check is logged with a keyed IP hash and neither the raw IP nor the token appears in logs or the table', async () => {
      const ip = '198.51.100.222';
      const c = await issue('A');
      lines.length = 0;
      const before = (await ownerQuery(`SELECT count(*)::int AS n FROM verification_logs`)).rows[0].n as number;
      await verify(c.verificationToken, ip);
      await verify('definitely-not-a-token-0', ip);
      const rows = (await ownerQuery(`SELECT * FROM verification_logs ORDER BY created_at, id OFFSET $1`, [before])).rows as Body[];
      expect(rows).toHaveLength(2);
      for (const r of rows) {
        expect(r.ip_hash).toMatch(/^[0-9a-f]{32,64}$/);
        expect(JSON.stringify(r)).not.toContain(ip);
        expect(JSON.stringify(r)).not.toContain(c.verificationToken);
      }
      expect(rows[0]!.ip_hash).toBe(rows[1]!.ip_hash);
      for (const l of lines) {
        expect(l).not.toContain(ip);
        expect(l).not.toContain(c.verificationToken);
      }
    });
  });

  // ---------------------------------------------------------------- CLI vs API
  describe('CLI vs API agreement', () => {
    it('ACTIVE: API VERIFIED and offline CLI VALID (exit 0), with the network disabled', async () => {
      const c = await issue('A');
      expect(await result(c.verificationToken)).toBe('VERIFIED');
      const r = await runCli(c, 'inst-a');
      expect(r.code).toBe(0);
      expect(r.parsed.result).toBe('VALID');
      expect(r.parsed.exitCode).toBe(0);
      // Output never carries the salt, token or signature.
      for (const secret of [c.payload.salt, c.verificationToken, c.holderToken, JSON.parse(r.credText).signature]) expect(r.out + r.err).not.toContain(secret);
    });

    it('one-byte change in the downloaded file: CLI fails (exit 1) while the API still says VERIFIED for the untouched DB row', async () => {
      const c = await issue('A');
      const flipped = await runCli(c, 'inst-a', (text) => {
        const d = JSON.parse(text);
        d.payload.holder.fullName = d.payload.holder.fullName.replace('Holder', 'Holdex');
        return JSON.stringify(d);
      });
      expect(flipped.code).toBe(1);
      expect(flipped.parsed.result).toBe('VERIFICATION_FAILED');
      const sig = await runCli(c, 'inst-a', (text) => {
        const d = JSON.parse(text);
        const s = d.signature as string;
        d.signature = (s[0] === 'A' ? 'B' : 'A') + s.slice(1);
        return JSON.stringify(d);
      });
      expect(sig.code).toBe(1);
      expect(await result(c.verificationToken)).toBe('VERIFIED');
    });

    it('DB tampered: API VERIFICATION_FAILED and CLI VERIFICATION FAILED agree', async () => {
      const c = await issue('A');
      await tamper(c.id, `payload = jsonb_set(payload, '{holder,fullName}', '"Mallory"')`);
      expect(await result(c.verificationToken)).toBe('VERIFICATION_FAILED');
      const r = await runCli(c, 'inst-a');
      expect(r.code).toBe(1);
      expect(r.parsed.result).toBe('VERIFICATION_FAILED');
    });

    it('COMPROMISED key: both say failed (agreement for key status)', async () => {
      const c = await issue('C');
      expect(await result(c.verificationToken)).toBe('VERIFIED');
      expect((await runCli(c, 'inst-c')).code).toBe(0);
      await ownerQuery(`UPDATE institution_keys SET status = 'COMPROMISED', retired_at = now() WHERE institution_id = $1`, [INST.C]);
      expect(await result(c.verificationToken)).toBe('VERIFICATION_FAILED');
      const r = await runCli(c, 'inst-c');
      expect(r.code).toBe(1);
      expect(r.parsed.result).toBe('VERIFICATION_FAILED');
    });

    it('EXPIRED: API EXPIRED and CLI EXPIRED (exit 2)', async () => {
      const c = await issue('A', { expiresAt: new Date(Date.now() + 1500).toISOString().slice(0, 19) + 'Z' });
      expect(await result(c.verificationToken)).toBe('VERIFIED');
      expect((await runCli(c, 'inst-a')).code).toBe(0);
      await sleep(2600);
      expect(await result(c.verificationToken)).toBe('EXPIRED');
      const r = await runCli(c, 'inst-a');
      expect(r.code).toBe(2);
      expect(r.parsed.result).toBe('EXPIRED');
    });

    it('SUSPENDED / REVOKED: status is not signed, so the API reports it and the CLI documents that it cannot (still VALID offline)', async () => {
      const s = await issue('A');
      const r = await issue('A');
      expect((await post(client.A, `/credentials/${s.id}/suspend`, { reason: 'qa' })).statusCode).toBe(200);
      expect((await post(client.A, `/credentials/${r.id}/revoke`, { reason: 'qa' })).statusCode).toBe(200);
      expect(await result(s.verificationToken)).toBe('SUSPENDED');
      expect(await result(r.verificationToken)).toBe('REVOKED');
      for (const c of [s, r]) {
        const out = await runCli(c, 'inst-a');
        expect(out.code).toBe(0);
        expect(out.parsed.result).toBe('VALID');
      }
    });
  });

  // ---------------------------------------------------------------- DB tamper
  describe('DB tamper returns VERIFICATION FAILED (W4: signed field edited directly in the DB)', () => {
    const cases: Array<[string, string]> = [
      ['holder full name', `payload = jsonb_set(payload, '{holder,fullName}', '"Mallory"')`],
      ['holder photoSha256', `payload = jsonb_set(payload, '{holder,photoSha256}', '"${'0'.repeat(64)}"')`],
      ['credential number', `payload = jsonb_set(payload, '{credentialNumber}', '"IGR-FORGED-0001"')`],
      ['attribute', `payload = jsonb_set(payload, '{attributes,program}', '"Medicine"')`],
      ['salt', `payload = jsonb_set(payload, '{salt}', '"${'ab'.repeat(32)}"')`],
      ['issuerKeyId in payload', `payload = jsonb_set(payload, '{issuerKeyId}', '"kid-other"')`],
      ['expiresAt (extend validity)', `payload = jsonb_set(payload, '{expiresAt}', '"2099-01-01T00:00:00Z"')`],
      ['added payload field', `payload = payload || '{"extra":"x"}'::jsonb`],
      ['removed payload field', `payload = payload - 'salt'`],
      ['data_hash', `data_hash = '${'0'.repeat(64)}'`],
      ['signature (garbage)', `signature = '${'A'.repeat(86)}'`],
      ['signature (first char)', `signature = (CASE WHEN left(signature,1) = 'A' THEN 'B' ELSE 'A' END) || substr(signature, 2)`],
    ];

    it.each(cases)('%s', async (_name, set) => {
      const c = await issue('A');
      expect(await result(c.verificationToken)).toBe('VERIFIED');
      lines.length = 0;
      await tamper(c.id, set);
      const res = await verify(c.verificationToken);
      expect(res.statusCode).toBe(200);
      const b = res.json() as Body;
      expect(b.result).toBe('VERIFICATION_FAILED');
      // Nothing from the altered row is shown.
      expect(b).toMatchObject({ institution: null, holder: null, type: null, status: null, proof: null });
      expect(res.body).not.toContain('Mallory');
      // Ops alert fired exactly once with internal ids only.
      const alerts = lines.map((l) => JSON.parse(l)).filter((l) => l.event === 'VERIFICATION_INTEGRITY_FAILURE');
      expect(alerts).toHaveLength(1);
      expect(alerts[0]).toMatchObject({ alert: 'ops', level: 50, institutionId: INST.A, credentialId: c.id });
      for (const l of lines) for (const secret of [c.verificationToken, c.payload.salt]) expect(l).not.toContain(secret);
      // Logged as a failure in verification_logs.
      const last = (await ownerQuery(`SELECT result::text AS result FROM verification_logs WHERE credential_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1`, [c.id])).rows[0];
      expect(last.result).toBe('VERIFICATION_FAILED');
    });

    it('tampered AND revoked/suspended/superseded still reports VERIFICATION_FAILED (integrity before status, invariant 7)', async () => {
      const rev = await issue('A');
      const sus = await issue('A');
      const old = await issue('A');
      expect((await post(client.A, `/credentials/${rev.id}/revoke`, { reason: 'qa' })).statusCode).toBe(200);
      expect((await post(client.A, `/credentials/${sus.id}/suspend`, { reason: 'qa' })).statusCode).toBe(200);
      expect((await post(client.A, `/credentials/${old.id}/reissue`, { reason: 'qa', attributes: { program: 'Law' } })).statusCode).toBe(201);
      for (const c of [rev, sus, old]) await tamper(c.id, `payload = jsonb_set(payload, '{holder,fullName}', '"Mallory"')`);
      for (const c of [rev, sus, old]) expect(await result(c.verificationToken)).toBe('VERIFICATION_FAILED');
    });

    it('a normal (non-bypassed) UPDATE of signed columns is refused by the database for the app role', async () => {
      const c = await issue('A');
      await expect(
        db.withLookup({ 'app.verification_token': c.verificationToken }, async (cl) => {
          await cl.query(`UPDATE credentials SET signature = $2 WHERE id = $1`, [c.id, 'A'.repeat(86)]);
        }),
      ).rejects.toThrow();
      expect(await result(c.verificationToken)).toBe('VERIFIED');
    });
  });
});
