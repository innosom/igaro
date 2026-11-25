// Integration tests for holders CRUD and photo upload (T-018). Skipped when DATABASE_URL is unset. Runs as the
// restricted igaro_app role in a scratch schema, so RLS is enforced for real.
import { createHash, randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { Writable } from 'node:stream';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import type { FastifyInstance } from 'fastify';
import { buildApp } from './app.js';
import { csrfTokenFor, hashPassword } from './auth.js';
import { Db } from './db.js';
import { MemoryObjectStorage } from './storage.js';
import { JPEG, PNG } from './test-images.js';

const url = process.env.DATABASE_URL;
const migrationsDir = new URL('../../../packages/db/prisma/migrations/', import.meta.url);

const INST_A = '11111111-1111-4111-8111-111111111111';
const INST_B = '22222222-2222-4222-8222-222222222222';
const U_PA = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const U_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const U_B = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const PW = 'correct horse battery staple';
const json = { 'content-type': 'application/json' };
const BIG = { ipMax: 10000, accountMax: 10000, windowSeconds: 900 };
const rateLimit = { login: BIG, reset: BIG, token: { ipMax: 10000, windowSeconds: 900 } };
const MAX = 2048;
const MISSING = '99999999-9999-4999-8999-999999999999';

interface Client {
  headers: Record<string, string>;
}

const multipartBody = (parts: { name: string; filename?: string; type?: string; data: Buffer | string }[]) => {
  const boundary = `----t018${randomBytes(6).toString('hex')}`;
  const bufs: Buffer[] = [];
  for (const p of parts) {
    bufs.push(
      Buffer.from(
        `--${boundary}\r\nContent-Disposition: form-data; name="${p.name}"` +
          (p.filename ? `; filename="${p.filename}"` : '') +
          `\r\n` +
          (p.type ? `Content-Type: ${p.type}\r\n` : '') +
          `\r\n`,
      ),
      Buffer.from(p.data),
      Buffer.from('\r\n'),
    );
  }
  bufs.push(Buffer.from(`--${boundary}--\r\n`));
  return { payload: Buffer.concat(bufs), contentType: `multipart/form-data; boundary=${boundary}` };
};

describe.skipIf(!url)('holders (needs Postgres)', () => {
  const schema = `t018_${randomBytes(4).toString('hex')}`;
  let owner: pg.Client;
  let db: Db;
  let app: FastifyInstance;
  let pa: Client;
  let a: Client;
  let b: Client;
  const storage = new MemoryObjectStorage();
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
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      headers: json,
      payload: { email, password: PW },
    });
    expect(res.statusCode).toBe(200);
    const cookie = String(res.headers['set-cookie']).split(';')[0]!;
    const token = cookie.slice(cookie.indexOf('=') + 1);
    return { headers: { cookie, 'x-csrf-token': csrfTokenFor(token) } };
  };

  const call = (c: Client | null, method: 'GET' | 'POST' | 'PATCH' | 'DELETE', path: string, payload?: unknown) =>
    app.inject({
      method,
      url: `/api/v1${path}`,
      headers: { ...(c?.headers ?? {}), ...(payload === undefined ? {} : json) },
      ...(payload === undefined ? {} : { payload: payload as Record<string, unknown> }),
    });

  const upload = (c: Client | null, id: string, parts: Parameters<typeof multipartBody>[0], extra = {}) => {
    // A part without a filename is a text field to the parser; give file parts one by default.
    const m = multipartBody(parts.map((p) => (p.name === 'file' && !p.filename ? { ...p, filename: 'p.bin' } : p)));
    return app.inject({
      method: 'POST',
      url: `/api/v1/holders/${id}/photo`,
      headers: { ...(c?.headers ?? {}), 'content-type': m.contentType, ...extra },
      payload: m.payload,
    });
  };

  const create = async (c: Client, body: Record<string, unknown>) => {
    const res = await call(c, 'POST', '/holders', body);
    expect(res.statusCode).toBe(201);
    return res.json() as { id: string };
  };

  const holderRow = async (id: string) =>
    (await ownerQuery(`SELECT * FROM credential_holders WHERE id = $1`, [id])).rows[0];

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
    for (const [id, slug] of [
      [INST_A, 'inst-a'],
      [INST_B, 'inst-b'],
    ]) {
      await ownerQuery(`INSERT INTO institutions (id, name, slug, updated_at) VALUES ($1,$2,$3,now())`, [
        id,
        `Inst ${slug}`,
        slug,
      ]);
    }
    for (const [id, inst, email, role] of [
      [U_PA, null, 'pa@example.test', 'PLATFORM_ADMIN'],
      [U_A, INST_A, 'a@example.test', 'INSTITUTION_ADMIN'],
      [U_B, INST_B, 'b@example.test', 'INSTITUTION_ADMIN'],
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
    app = await buildApp({
      config: { logLevel: 'debug', rateLimit, photoMaxBytes: MAX },
      db,
      storage,
      logStream: new Writable({
        write(c, _e, cb) {
          logs.push(String(c));
          cb();
        },
      }),
    });
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

  describe('authorization', () => {
    it('401 without a session, 403 for a platform admin', async () => {
      for (const [m, p] of [
        ['GET', '/holders'],
        ['POST', '/holders'],
        ['GET', `/holders/${MISSING}`],
        ['PATCH', `/holders/${MISSING}`],
        ['DELETE', `/holders/${MISSING}`],
      ] as const) {
        expect((await call(null, m, p, m === 'GET' || m === 'DELETE' ? undefined : { fullName: 'x' })).statusCode).toBe(401);
        expect((await call(pa, m, p, m === 'GET' || m === 'DELETE' ? undefined : { fullName: 'x' })).statusCode).toBe(403);
      }
      expect((await upload(null, MISSING, [{ name: 'file', data: PNG() }])).statusCode).toBe(401);
      expect((await upload(pa, MISSING, [{ name: 'file', data: PNG() }])).statusCode).toBe(403);
    });

    it('mutating routes need the CSRF header', async () => {
      const noCsrf: Client = { headers: { cookie: a.headers.cookie! } };
      expect((await call(noCsrf, 'POST', '/holders', { fullName: 'No Csrf' })).statusCode).toBe(403);
      const h = await create(a, { fullName: 'Csrf Target' });
      expect((await call(noCsrf, 'PATCH', `/holders/${h.id}`, { fullName: 'Changed' })).statusCode).toBe(403);
      expect((await call(noCsrf, 'DELETE', `/holders/${h.id}`)).statusCode).toBe(403);
      expect((await upload(noCsrf, h.id, [{ name: 'file', data: PNG() }])).statusCode).toBe(403);
      expect((await holderRow(h.id)).full_name).toBe('Csrf Target');
      expect(storage.objects.size).toBe(0);
    });
  });

  describe('create and read', () => {
    it('creates a holder in the session institution with a lower-cased email', async () => {
      const res = await call(a, 'POST', '/holders', {
        fullName: '  Ada Lovelace ',
        externalId: 'S-100',
        email: ' Ada.Lovelace@Example.TEST ',
      });
      expect(res.statusCode).toBe(201);
      expect(res.headers['cache-control']).toBe('no-store');
      const body = res.json();
      expect(body).toMatchObject({
        fullName: 'Ada Lovelace',
        externalId: 'S-100',
        email: 'ada.lovelace@example.test',
        hasPhoto: false,
        photoSha256: null,
        credentialCount: 0,
      });
      expect(JSON.stringify(body)).not.toMatch(/institution_?id|photo_?key|photoUrl/i);
      const r = await holderRow(body.id);
      expect(r.institution_id).toBe(INST_A);
      expect(r.email).toBe('ada.lovelace@example.test');
    });

    it('ignores nothing: tenant hints and unknown properties are rejected', async () => {
      for (const extra of [{ institutionId: INST_B }, { institution_id: INST_B }, { id: MISSING }, { photoKey: 'x' }]) {
        const res = await call(a, 'POST', '/holders', { fullName: 'Hint', ...extra });
        expect(res.statusCode).toBe(400);
        expect(res.json().error.code).toBe('UNKNOWN_PROPERTY');
      }
      expect((await ownerQuery(`SELECT 1 FROM credential_holders WHERE full_name = 'Hint'`)).rowCount).toBe(0);
    });

    it.each([
      [{}, 'INVALID_FULL_NAME'],
      [{ fullName: '' }, 'INVALID_FULL_NAME'],
      [{ fullName: '   ' }, 'INVALID_FULL_NAME'],
      [{ fullName: 'x'.repeat(201) }, 'INVALID_FULL_NAME'],
      [{ fullName: 'bad\u0000name' }, 'INVALID_FULL_NAME'],
      [{ fullName: 5 }, 'INVALID_FULL_NAME'],
      [{ fullName: 'Ok', email: 'not-an-email' }, 'INVALID_EMAIL'],
      [{ fullName: 'Ok', email: 'a b@example.test' }, 'INVALID_EMAIL'],
      [{ fullName: 'Ok', email: 42 }, 'INVALID_EMAIL'],
      [{ fullName: 'Ok', externalId: '' }, 'INVALID_EXTERNAL_ID'],
      [{ fullName: 'Ok', externalId: 'x'.repeat(101) }, 'INVALID_EXTERNAL_ID'],
      [{ fullName: 'Ok', externalId: 7 }, 'INVALID_EXTERNAL_ID'],
    ])('rejects invalid input %j', async (body, code) => {
      const res = await call(a, 'POST', '/holders', body);
      expect(res.statusCode).toBe(400);
      expect(res.json().error.code).toBe(code);
    });

    it('rejects a non-object body', async () => {
      expect((await call(a, 'POST', '/holders', [])).statusCode).toBe(400);
      expect((await call(a, 'POST', '/holders', 'x')).statusCode).toBe(400);
    });

    it('external id is unique per institution (409) but may repeat across institutions', async () => {
      await create(a, { fullName: 'First', externalId: 'DUP-1' });
      const dup = await call(a, 'POST', '/holders', { fullName: 'Second', externalId: 'DUP-1' });
      expect(dup.statusCode).toBe(409);
      expect(dup.json().error.code).toBe('DUPLICATE_EXTERNAL_ID');
      expect((await call(b, 'POST', '/holders', { fullName: 'Other tenant', externalId: 'DUP-1' })).statusCode).toBe(201);
    });

    it('GET /holders/:id returns the holder; unknown and malformed ids are 404', async () => {
      const h = await create(a, { fullName: 'Grace Hopper' });
      const res = await call(a, 'GET', `/holders/${h.id}`);
      expect(res.statusCode).toBe(200);
      expect(res.json()).toMatchObject({ id: h.id, fullName: 'Grace Hopper' });
      expect((await call(a, 'GET', `/holders/${MISSING}`)).statusCode).toBe(404);
      expect((await call(a, 'GET', '/holders/not-a-uuid')).statusCode).toBe(404);
      expect((await call(a, 'GET', `/holders/${h.id}'--`)).statusCode).toBe(404);
    });
  });

  describe('list', () => {
    it('lists only own holders, newest first, with search and paging', async () => {
      await create(a, { fullName: 'Zed Searchable', email: 'zed@example.test' });
      await create(a, { fullName: '100% Match_Me' });
      const all = (await call(a, 'GET', '/holders')).json();
      expect(all.total).toBe(all.items.length);
      expect(all.items.length).toBeGreaterThan(3);
      for (const it of all.items) expect((await holderRow(it.id)).institution_id).toBe(INST_A);

      const q = (await call(a, 'GET', '/holders?q=SEARCHABLE')).json();
      expect(q.items.map((i: { fullName: string }) => i.fullName)).toEqual(['Zed Searchable']);
      const byEmail = (await call(a, 'GET', '/holders?q=zed@')).json();
      expect(byEmail.total).toBe(1);
      // LIKE wildcards in the search term are literal.
      expect((await call(a, 'GET', '/holders?q=%25')).json().total).toBe(1);
      expect((await call(a, 'GET', '/holders?q=_')).json().total).toBe(1);

      const p1 = (await call(a, 'GET', '/holders?limit=2&offset=0')).json();
      const p2 = (await call(a, 'GET', '/holders?limit=2&offset=2')).json();
      expect(p1.items).toHaveLength(2);
      expect(p1.items[0].id).not.toBe(p2.items[0].id);
      expect(p1.total).toBe(all.total);
    });

    it("never shows another tenant's holders", async () => {
      const bh = await create(b, { fullName: 'Only In B' });
      const list = (await call(a, 'GET', '/holders?q=Only%20In%20B')).json();
      expect(list.total).toBe(0);
      expect(JSON.stringify((await call(a, 'GET', '/holders?limit=200')).json())).not.toContain(bh.id);
    });

    it('rejects bad paging and unknown query parameters', async () => {
      for (const qs of ['limit=0', 'limit=201', 'limit=x', 'offset=-1', 'institutionId=' + INST_B, 'limit=1&limit=2']) {
        expect((await call(a, 'GET', `/holders?${qs}`)).statusCode).toBe(400);
      }
    });
  });

  describe('PATCH', () => {
    it('updates fields, lower-cases email, and clears with null', async () => {
      const h = await create(a, { fullName: 'Patch Me', externalId: 'P-1', email: 'p@example.test' });
      const res = await call(a, 'PATCH', `/holders/${h.id}`, { fullName: 'Patched', email: 'NEW@Example.test' });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toMatchObject({ fullName: 'Patched', email: 'new@example.test', externalId: 'P-1' });
      const cleared = await call(a, 'PATCH', `/holders/${h.id}`, { email: null, externalId: null });
      expect(cleared.json()).toMatchObject({ email: null, externalId: null });
    });

    it('rejects empty, unknown and invalid patches without writing', async () => {
      const h = await create(a, { fullName: 'Stay Same' });
      expect((await call(a, 'PATCH', `/holders/${h.id}`, {})).statusCode).toBe(400);
      expect((await call(a, 'PATCH', `/holders/${h.id}`, { institutionId: INST_B })).statusCode).toBe(400);
      expect((await call(a, 'PATCH', `/holders/${h.id}`, { photoSha256: 'a'.repeat(64) })).statusCode).toBe(400);
      expect((await call(a, 'PATCH', `/holders/${h.id}`, { fullName: null })).statusCode).toBe(400);
      expect((await holderRow(h.id)).full_name).toBe('Stay Same');
    });

    it('duplicate external id on patch is 409', async () => {
      const x = await create(a, { fullName: 'X', externalId: 'PX-1' });
      await create(a, { fullName: 'Y', externalId: 'PY-1' });
      const res = await call(a, 'PATCH', `/holders/${x.id}`, { externalId: 'PY-1' });
      expect(res.statusCode).toBe(409);
      expect((await holderRow(x.id)).external_id).toBe('PX-1');
    });
  });

  describe('cross-tenant access is 404, never 403, and changes nothing', () => {
    it('GET, PATCH, DELETE and photo on another tenant holder', async () => {
      const bh = await create(b, { fullName: 'Tenant B Person', email: 'bp@example.test' });
      const absent = await call(a, 'GET', `/holders/${MISSING}`);

      const get = await call(a, 'GET', `/holders/${bh.id}`);
      expect(get.statusCode).toBe(404);
      expect(get.json()).toEqual(absent.json()); // indistinguishable from a missing id

      const patch = await call(a, 'PATCH', `/holders/${bh.id}`, { fullName: 'Hijacked' });
      expect(patch.statusCode).toBe(404);
      expect((await call(a, 'DELETE', `/holders/${bh.id}`)).statusCode).toBe(404);
      const before = storage.objects.size;
      expect((await upload(a, bh.id, [{ name: 'file', data: PNG() }])).statusCode).toBe(404);
      expect(storage.objects.size).toBe(before);

      const r = await holderRow(bh.id);
      expect(r.full_name).toBe('Tenant B Person');
      expect(r.photo_key).toBeNull();
      expect((await call(b, 'GET', `/holders/${bh.id}`)).statusCode).toBe(200);
    });

    it('a holder cannot be created into another institution via body or header', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/holders',
        headers: { ...a.headers, ...json, 'x-institution-id': INST_B },
        payload: { fullName: 'Header Hint' },
      });
      expect(res.statusCode).toBe(201);
      expect((await holderRow(res.json().id)).institution_id).toBe(INST_A);
    });
  });

  describe('POST /holders/:id/photo', () => {
    it('strips metadata, stores privately, records the SHA-256 of the stored bytes, returns a short-lived URL', async () => {
      const h = await create(a, { fullName: 'Photo Person' });
      const src = PNG(0, ['eXIf', 'GPS-SECRET'], ['tEXt', 'Author\0me']);
      const res = await upload(a, h.id, [
        { name: 'file', filename: '../../etc/passwd.svg', type: 'text/html', data: src },
      ]);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.hasPhoto).toBe(true);

      const r = await holderRow(h.id);
      expect(r.photo_key).toMatch(new RegExp(`^institutions/${INST_A}/holders/${h.id}/photo/[0-9a-f]{64}\\.png$`));
      expect(r.photo_key).toContain(`/${r.photo_sha256}.`);
      const stored = storage.objects.get(r.photo_key)!;
      expect(stored.contentType).toBe('image/png');
      expect(stored.body.includes('GPS-SECRET')).toBe(false);
      expect(stored.body.includes('eXIf')).toBe(false);
      expect(stored.body.equals(src)).toBe(false);
      // The hash covers the STORED (stripped) bytes, not the upload.
      const storedHash = createHash('sha256').update(stored.body).digest('hex');
      expect(r.photo_sha256).toBe(storedHash);
      expect(body.photoSha256).toBe(storedHash);
      expect(storedHash).not.toBe(createHash('sha256').update(src).digest('hex'));

      expect(body.photoUrl).toMatch(/^memory:\/\/.*expires=300$/);
      expect(JSON.stringify(body)).not.toContain('passwd');
      expect(JSON.stringify(body)).not.toContain('photo_key');
      // GET also returns a fresh signed URL, the list does not.
      expect((await call(a, 'GET', `/holders/${h.id}`)).json().photoUrl).toMatch(/^memory:\/\//);
      const listed = (await call(a, 'GET', '/holders?q=Photo%20Person')).json().items[0];
      expect(listed.hasPhoto).toBe(true);
      expect(listed.photoUrl).toBeUndefined();
    });

    it('replacing the photo deletes the old object and updates the hash', async () => {
      const h = await create(a, { fullName: 'Replace Photo' });
      await upload(a, h.id, [{ name: 'file', data: PNG() }]);
      const first = await holderRow(h.id);
      const res = await upload(a, h.id, [{ name: 'file', data: JPEG() }]);
      expect(res.statusCode).toBe(200);
      const second = await holderRow(h.id);
      expect(second.photo_key).toMatch(/\.jpg$/);
      expect(second.photo_sha256).not.toBe(first.photo_sha256);
      expect(storage.objects.has(first.photo_key)).toBe(false);
      expect(second.photo_sha256).toBe(
        createHash('sha256').update(storage.objects.get(second.photo_key)!.body).digest('hex'),
      );
    });

    it('rejects non-images, damaged and oversized files without touching the holder or storage', async () => {
      const h = await create(a, { fullName: 'Reject Photo' });
      const before = storage.objects.size;
      const bad: [string, Buffer, number][] = [
        ['GIF', Buffer.from('GIF89a\x01\x00\x01\x00\x00\x00\x00;'), 415],
        ['SVG', Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>1</script></svg>'), 415],
        ['HTML', Buffer.from('<html><script>alert(1)</script></html>'), 415],
        ['truncated PNG', PNG().subarray(0, 40), 400],
        ['PNG with bad CRC', Buffer.concat([PNG().subarray(0, PNG().length - 1), Buffer.from([0])]), 400],
        ['too large', PNG(MAX), 413],
      ];
      for (const [, data, status] of bad) {
        expect((await upload(a, h.id, [{ name: 'file', filename: 'p.png', type: 'image/png', data }])).statusCode).toBe(status);
      }
      expect((await upload(a, h.id, [{ name: 'file', data: Buffer.alloc(0) }])).statusCode).toBe(400);
      expect((await upload(a, h.id, [{ name: 'photo', data: PNG() }])).statusCode).toBe(400);
      expect(
        (await upload(a, h.id, [{ name: 'x', data: 'y' }, { name: 'file', data: PNG() }])).statusCode,
      ).toBeGreaterThanOrEqual(400);
      const r = await app.inject({
        method: 'POST',
        url: `/api/v1/holders/${h.id}/photo`,
        headers: { ...a.headers, ...json },
        payload: { file: 'x' },
      });
      expect(r.statusCode).toBe(415);
      expect((await holderRow(h.id)).photo_key).toBeNull();
      expect(storage.objects.size).toBe(before);
    });

    it('a stripped-then-stored JPEG has no data after EOI', async () => {
      const h = await create(a, { fullName: 'Jpeg Trailer' });
      const withTrailer = Buffer.concat([JPEG(), Buffer.from('TRAILING-SECRET')]);
      expect((await upload(a, h.id, [{ name: 'file', data: withTrailer }])).statusCode).toBe(200);
      const stored = storage.objects.get((await holderRow(h.id)).photo_key)!;
      expect(stored.body.includes('TRAILING-SECRET')).toBe(false);
      expect(stored.body.subarray(-2).equals(Buffer.from([0xff, 0xd9]))).toBe(true);
    });

    it('answers 503 and keeps the old photo when storage fails; unknown holder is 404 first', async () => {
      const h = await create(a, { fullName: 'Storage Fail' });
      await upload(a, h.id, [{ name: 'file', data: PNG() }]);
      const before = await holderRow(h.id);
      storage.failPut = true;
      try {
        const res = await upload(a, h.id, [{ name: 'file', data: JPEG() }]);
        expect(res.statusCode).toBe(503);
        expect(res.json().error.code).toBe('STORAGE_UNAVAILABLE');
      } finally {
        storage.failPut = false;
      }
      const after = await holderRow(h.id);
      expect(after.photo_key).toBe(before.photo_key);
      expect(after.photo_sha256).toBe(before.photo_sha256);
      expect((await upload(a, MISSING, [{ name: 'file', data: PNG() }])).statusCode).toBe(404);
    });
  });

  describe('DELETE', () => {
    it('deletes a holder without credentials, and its photo object', async () => {
      const h = await create(a, { fullName: 'Delete Me' });
      await upload(a, h.id, [{ name: 'file', data: PNG() }]);
      const key = (await holderRow(h.id)).photo_key as string;
      expect(storage.objects.has(key)).toBe(true);
      const res = await call(a, 'DELETE', `/holders/${h.id}`);
      expect(res.statusCode).toBe(204);
      expect(await holderRow(h.id)).toBeUndefined();
      expect(storage.objects.has(key)).toBe(false);
      expect((await call(a, 'GET', `/holders/${h.id}`)).statusCode).toBe(404);
      expect((await call(a, 'DELETE', `/holders/${h.id}`)).statusCode).toBe(404);
    });

    it('refuses with 409 when the holder has any credential, whatever its status', async () => {
      const h = await create(a, { fullName: 'Has Credential' });
      await upload(a, h.id, [{ name: 'file', data: PNG() }]);
      const key = (await holderRow(h.id)).photo_key as string;
      const typeId = '33333333-3333-4333-8333-333333333333';
      await ownerQuery(
        `INSERT INTO credential_types (id, institution_id, code, name, kind, updated_at)
         VALUES ($1, $2, 'T', 'Type', 'CERTIFICATE', now())`,
        [typeId, INST_A],
      );
      await ownerQuery(
        `INSERT INTO institution_keys (id, institution_id, kid, public_key, encrypted_private_key)
         VALUES (gen_random_uuid(), $1, 'kid_0000000000000001', 'pk', 'sk')`,
        [INST_A],
      );
      await ownerQuery(
        `INSERT INTO credentials (id, institution_id, holder_id, type_id, credential_number, status, payload,
           data_hash, issuer_kid, signature, verification_token, holder_token_hash, updated_at)
         VALUES (gen_random_uuid(), $1, $2, $3, 'N-1', 'DRAFT', '{}', 'h', 'kid_0000000000000001', 's',
           'vt-t018', 'ht-t018', now())`,
        [INST_A, h.id, typeId],
      );
      const res = await call(a, 'DELETE', `/holders/${h.id}`);
      expect(res.statusCode).toBe(409);
      expect(res.json().error.code).toBe('HOLDER_HAS_CREDENTIALS');
      expect(await holderRow(h.id)).toBeDefined();
      expect(storage.objects.has(key)).toBe(true);
      expect((await call(a, 'GET', `/holders/${h.id}`)).json().credentialCount).toBe(1);
    });
  });

  describe('logging', () => {
    it('never logs PII, file bytes, storage keys or tokens', () => {
      const all = logs.join('');
      expect(all).toContain('holder created');
      expect(all).not.toMatch(/lovelace|ada\.|@example\.test|GPS-SECRET|institutions\/|photo\/|memory:|igaro_session|x-csrf/i);
    });
  });
});
