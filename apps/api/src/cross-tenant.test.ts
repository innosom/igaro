// T-020: cross-tenant 404 tests for institutions, keys, holders and credential types through the real
// HTTP routes (white paper section 15). Also builds a real credential row for the TYPE_HAS_CREDENTIALS
// guard (T-019 follow-up L1). Skipped when DATABASE_URL is unset. Test values only.
import { randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import type { FastifyInstance } from 'fastify';
import { buildApp } from './app.js';
import { csrfTokenFor, hashPassword } from './auth.js';
import { Db } from './db.js';
import { MemoryObjectStorage } from './storage.js';

const url = process.env.DATABASE_URL;
const migrationsDir = new URL('../../../packages/db/prisma/migrations/', import.meta.url);
const INST_A = '11111111-1111-4111-8111-111111111111';
const INST_B = '22222222-2222-4222-8222-222222222222';
const PW = 'correct horse battery staple';
const json = { 'content-type': 'application/json' };
const BIG = { ipMax: 10000, accountMax: 10000, windowSeconds: 900 };
const rateLimit = { login: BIG, reset: BIG, token: { ipMax: 10000, windowSeconds: 900 } };
const NOT_FOUND = { error: { code: 'NOT_FOUND', message: 'Not found' } };
const MISSING = '99999999-9999-4999-8999-999999999999';
// Must match the production kid format (signing-keys.ts KID_RE), or the route 404s on shape alone.
const KID_A = 'kid_00000000000000a1';
const KID_B = 'kid_00000000000000b1';
const MISSING_KID = 'kid_00000000000000ff';

interface Client {
  headers: Record<string, string>;
}
type Method = 'GET' | 'POST' | 'PATCH' | 'DELETE';

describe.skipIf(!url)('cross-tenant 404 across the MVP admin routes (needs Postgres)', () => {
  const schema = `t020_${randomBytes(4).toString('hex')}`;
  let owner: pg.Client;
  let db: Db;
  let app: FastifyInstance;
  let pa: Client;
  let a: Client;
  let b: Client;

  const ownerTx = async (fn: (c: pg.Client) => Promise<void>) => {
    await owner.query('BEGIN');
    await owner.query(`SELECT set_config('app.is_platform_admin','true',true)`);
    try {
      await fn(owner);
      await owner.query('COMMIT');
    } catch (e) {
      await owner.query('ROLLBACK');
      throw e;
    }
  };
  const ownerRows = async (sql: string, params: unknown[] = []) => {
    let rows: Record<string, unknown>[] = [];
    await ownerTx(async (c) => {
      rows = (await c.query(sql, params)).rows;
    });
    return rows;
  };

  const loginAs = async (email: string): Promise<Client> => {
    const res = await app.inject({ method: 'POST', url: '/api/v1/auth/login', headers: json, payload: { email, password: PW } });
    expect(res.statusCode).toBe(200);
    const cookie = String(res.headers['set-cookie']).split(';')[0]!;
    return { headers: { cookie, 'x-csrf-token': csrfTokenFor(cookie.slice(cookie.indexOf('=') + 1)) } };
  };
  const call = (c: Client, method: Method, path: string, payload?: unknown) =>
    app.inject({
      method,
      url: `/api/v1${path}`,
      headers: { ...c.headers, ...(payload === undefined ? {} : json) },
      ...(payload === undefined ? {} : { payload: payload as Record<string, unknown> }),
    });
  const expect404 = async (c: Client, method: Method, path: string, payload?: unknown) => {
    const res = await call(c, method, path, payload);
    expect(res.statusCode, `${method} ${path}`).toBe(404);
    expect(res.json(), `${method} ${path}`).toEqual(NOT_FOUND);
  };

  const typeBody = {
    code: 'WORKER_ID',
    name: 'Worker ID',
    kind: 'ID_CARD',
    attributes: [{ key: 'dept', label: 'Dept', type: 'string', required: true }],
    defaultValidityDays: 30,
  };

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
    await ownerTx(async (c) => {
      for (const [id, slug] of [
        [INST_A, 'inst-a'],
        [INST_B, 'inst-b'],
      ]) {
        await c.query(`INSERT INTO institutions (id, name, slug, updated_at) VALUES ($1,$2,$3,now())`, [id, `Inst ${slug}`, slug]);
      }
      for (const [inst, kid] of [
        [INST_A, KID_A],
        [INST_B, KID_B],
      ]) {
        await c.query(
          `INSERT INTO institution_keys (id, institution_id, kid, algorithm, public_key, encrypted_private_key, status)
           VALUES (gen_random_uuid(), $1, $2, 'Ed25519', 'test-public', 'test-wrapped', 'ACTIVE')`,
          [inst, kid],
        );
      }
      for (const [id, inst, email, role] of [
        ['bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', null, 'pa@example.test', 'PLATFORM_ADMIN'],
        ['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', INST_A, 'a@example.test', 'INSTITUTION_ADMIN'],
        ['cccccccc-cccc-4ccc-8ccc-cccccccccccc', INST_B, 'b@example.test', 'INSTITUTION_ADMIN'],
      ]) {
        await c.query(
          `INSERT INTO users (id, institution_id, email, name, password_hash, role, status, updated_at)
           VALUES ($1,$2,$3,'Name',$4,$5,'ACTIVE',now())`,
          [id, inst, email, pwHash, role],
        );
      }
    });

    db = new Db({ connectionString: url!, max: 6, poolConfig: { options: `-c search_path=${schema} -c role=igaro_app` } });
    app = await buildApp({ config: { logLevel: 'silent', rateLimit, masterKey: randomBytes(32) }, db, storage: new MemoryObjectStorage() });
    pa = await loginAs('pa@example.test');
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

  it('institutions: a tenant admin cannot reach platform routes; unknown ids are 404 for the platform', async () => {
    expect((await call(a, 'GET', '/institutions')).statusCode).toBe(403);
    expect((await call(a, 'PATCH', `/institutions/${INST_B}/status`, { status: 'SUSPENDED', reason: 'x' })).statusCode).toBe(403);
    await expect404(pa, 'PATCH', `/institutions/${MISSING}/status`, { status: 'ACTIVE' });
    await expect404(pa, 'PATCH', '/institutions/not-a-uuid/status', { status: 'ACTIVE' });
    const rows = await ownerRows(`SELECT id, status FROM institutions ORDER BY id`);
    expect(rows.every((r) => r.status === 'ACTIVE')).toBe(true);
  });

  it('own institution: the session decides the target; ids smuggled into the body are ignored', async () => {
    const smuggle = await call(a, 'PATCH', '/institution', { id: INST_B, institutionId: INST_B, cardTitle: 'Smuggled' });
    expect(smuggle.statusCode).toBe(400);
    expect(smuggle.json().error.code).toBe('UNKNOWN_PROPERTY');
    const titles = async () =>
      Object.fromEntries((await ownerRows(`SELECT id, card_title FROM institutions`)).map((r) => [r.id as string, r.card_title]));
    expect((await titles())[INST_B]).toBeNull();
    // A valid patch from A changes only A.
    expect((await call(a, 'PATCH', '/institution', { cardTitle: 'Only A' })).statusCode).toBe(200);
    const after = await titles();
    expect(after[INST_A]).toBe('Only A');
    expect(after[INST_B]).toBeNull();
    expect(JSON.stringify((await call(b, 'GET', '/institution')).json())).not.toContain('Only A');
  });

  it("keys: each tenant lists only its own keys; compromising the other tenant's kid is 404 and changes nothing", async () => {
    const kids = async (c: Client) => ((await call(c, 'GET', '/institution/keys')).json().items as { kid: string }[]).map((k) => k.kid);
    const listA = await kids(a);
    const listB = await kids(b);
    expect(listA).toContain(KID_A);
    expect(listA).not.toContain(KID_B);
    expect(listB).toContain(KID_B);
    expect(listB).not.toContain(KID_A);
    await expect404(a, 'POST', `/institution/keys/${KID_B}/compromise`, { reason: 'attack' });
    await expect404(b, 'POST', `/institution/keys/${KID_A}/compromise`, { reason: 'attack' });
    await expect404(a, 'POST', `/institution/keys/${MISSING_KID}/compromise`, { reason: 'attack' });
    // Positive control: the same well-formed kid works for its own tenant, so the 404s above are tenancy, not shape.
    expect((await call(a, 'POST', `/institution/keys/${KID_A}/compromise`, { reason: 'control' })).statusCode).toBe(200);
    // B's key must be untouched by everything A did (the control above only compromised A's own key).
    const rows = await ownerRows(`SELECT status FROM institution_keys WHERE kid = $1`, [KID_B]);
    expect(rows.map((r) => r.status)).toEqual(['ACTIVE']);
  });

  it("holders: read, update, delete and photo upload on another tenant's holder are 404 and change nothing", async () => {
    const h = (await call(a, 'POST', '/holders', { fullName: 'Holder Of A' })).json() as { id: string };
    await expect404(b, 'GET', `/holders/${h.id}`);
    await expect404(b, 'PATCH', `/holders/${h.id}`, { fullName: 'hijacked' });
    await expect404(b, 'DELETE', `/holders/${h.id}`);
    const boundary = '----t020';
    const photo = await app.inject({
      method: 'POST',
      url: `/api/v1/holders/${h.id}/photo`,
      headers: { ...b.headers, 'content-type': `multipart/form-data; boundary=${boundary}` },
      payload: `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="p.png"\r\nContent-Type: image/png\r\n\r\nx\r\n--${boundary}--\r\n`,
    });
    expect(photo.statusCode).toBe(404);
    expect(photo.json()).toEqual(NOT_FOUND);
    const listB = (await call(b, 'GET', '/holders')).json().items as { id: string }[];
    expect(listB.some((x) => x.id === h.id)).toBe(false);
    expect((await call(a, 'GET', `/holders/${h.id}`)).json().fullName).toBe('Holder Of A');
  });

  it('credential types: other tenant gets 404 for GET/PATCH/DELETE; an in-use type is protected with 409', async () => {
    const t = (await call(a, 'POST', '/credential-types', typeBody)).json() as { id: string };
    await expect404(b, 'GET', `/credential-types/${t.id}`);
    await expect404(b, 'PATCH', `/credential-types/${t.id}`, { name: 'hijack' });
    await expect404(b, 'DELETE', `/credential-types/${t.id}`);
    expect((await call(a, 'GET', `/credential-types/${t.id}`)).json().name).toBe('Worker ID');
    const listB = (await call(b, 'GET', '/credential-types')).json().items as { id: string }[];
    expect(listB.some((x) => x.id === t.id)).toBe(false);
    for (const id of [MISSING, 'not-a-uuid']) {
      await expect404(a, 'GET', `/credential-types/${id}`);
      await expect404(a, 'GET', `/holders/${id}`);
    }

    // A real credential row with its ISSUED event, in one transaction as the lifecycle triggers require.
    const h = (await call(a, 'POST', '/holders', { fullName: 'Credentialed' })).json() as { id: string };
    const credId = '88888888-8888-4888-8888-888888888888';
    await ownerTx(async (c) => {
      await c.query(
        `INSERT INTO credentials (id, institution_id, holder_id, type_id, credential_number, status,
           payload, data_hash, issuer_kid, signature, verification_token, holder_token_hash, updated_at)
         VALUES ($1,$2,$3,$4,'A-000001','ACTIVE','{}','test-hash',$5,'test-sig','test-vtoken-a','test-holder-hash-a',now())`,
        [credId, INST_A, h.id, t.id, KID_A],
      );
      await c.query(`INSERT INTO credential_events (id, institution_id, credential_id, type) VALUES (gen_random_uuid(),$1,$2,'ISSUED')`, [
        INST_A,
        credId,
      ]);
    });
    const res = await call(a, 'DELETE', `/credential-types/${t.id}`);
    expect(res.statusCode).toBe(409);
    expect(res.json().error.code).toBe('TYPE_HAS_CREDENTIALS');
    await expect404(b, 'DELETE', `/credential-types/${t.id}`);
  });
});
