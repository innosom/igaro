// Integration tests for own-institution GET/PATCH and logo upload (T-016). Skipped when DATABASE_URL is
// unset. Runs as the restricted igaro_app role in a scratch schema, so RLS is enforced for real.
import { randomBytes } from 'node:crypto';
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

interface Client {
  headers: Record<string, string>;
}

const multipartBody = (
  parts: { name: string; filename?: string; type?: string; data: Buffer | string }[],
) => {
  const boundary = `----t016${randomBytes(6).toString('hex')}`;
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

describe.skipIf(!url)('own institution profile (needs Postgres)', () => {
  const schema = `t016_${randomBytes(4).toString('hex')}`;
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

  const call = (c: Client | null, method: 'GET' | 'PATCH', payload?: unknown, extra = {}) =>
    app.inject({
      method,
      url: '/api/v1/institution',
      headers: { ...(c?.headers ?? {}), ...json, ...extra },
      ...(payload === undefined ? {} : { payload: payload as Record<string, unknown> }),
    });

  const upload = (
    c: Client | null,
    parts: Parameters<typeof multipartBody>[0],
    extra: Record<string, string> = {},
  ) => {
    const m = multipartBody(parts);
    return app.inject({
      method: 'POST',
      url: '/api/v1/institution/logo',
      headers: { ...(c?.headers ?? {}), 'content-type': m.contentType, ...extra },
      payload: m.payload,
    });
  };

  const row = async (id: string) =>
    (await ownerQuery(`SELECT * FROM institutions WHERE id = $1`, [id])).rows[0];

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
      await ownerQuery(
        `INSERT INTO institutions (id, name, slug, updated_at) VALUES ($1,$2,$3,now())`,
        [id, `Inst ${slug}`, slug],
      );
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
      config: { logLevel: 'debug', rateLimit, logoMaxBytes: MAX },
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
    it('401 without a session', async () => {
      expect((await call(null, 'GET')).statusCode).toBe(401);
      expect((await call(null, 'PATCH', { cardTitle: 'x' })).statusCode).toBe(401);
      expect((await upload(null, [{ name: 'file', filename: 'l.png', data: PNG() }])).statusCode).toBe(401);
    });

    it('403 for a platform admin, nothing written', async () => {
      expect((await call(pa, 'GET')).statusCode).toBe(403);
      expect((await call(pa, 'PATCH', { cardTitle: 'x' })).statusCode).toBe(403);
      expect((await upload(pa, [{ name: 'file', filename: 'l.png', data: PNG() }])).statusCode).toBe(403);
      expect(storage.objects.size).toBe(0);
    });

    it('PATCH and upload need the CSRF header', async () => {
      const noCsrf: Client = { headers: { cookie: a.headers.cookie! } };
      expect((await call(noCsrf, 'PATCH', { cardTitle: 'x' })).statusCode).toBe(403);
      expect((await upload(noCsrf, [{ name: 'file', filename: 'l.png', data: PNG() }])).statusCode).toBe(403);
      expect((await row(INST_A)).card_title).toBeNull();
      expect(storage.objects.size).toBe(0);
    });
  });

  describe('GET /institution', () => {
    it('returns own profile without key material or storage paths', async () => {
      const res = await call(a, 'GET');
      expect(res.statusCode).toBe(200);
      expect(res.headers['cache-control']).toBe('no-store');
      expect(res.json()).toEqual({
        id: INST_A,
        name: 'Inst inst-a',
        slug: 'inst-a',
        status: 'ACTIVE',
        cardTitle: null,
        primaryColor: '#1d4ed8',
        secondaryColor: '#0f172a',
        publicFields: [],
        hasLogo: false,
        updatedAt: expect.any(String),
      });
    });
  });

  describe('PATCH /institution', () => {
    it('updates branding and publicFields (deduped, canonical order, colours lower-cased)', async () => {
      const res = await call(a, 'PATCH', {
        cardTitle: '  Student ID  ',
        primaryColor: '#AABBCC',
        secondaryColor: '#001122',
        publicFields: ['attributes', 'photo', 'attributes'],
      });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toMatchObject({
        cardTitle: 'Student ID',
        primaryColor: '#aabbcc',
        secondaryColor: '#001122',
        publicFields: ['photo', 'attributes'],
      });
      expect((await call(a, 'GET')).json().publicFields).toEqual(['photo', 'attributes']);
    });

    it('partial update leaves other fields; null clears the card title; [] clears publicFields', async () => {
      const res = await call(a, 'PATCH', { cardTitle: null, publicFields: [] });
      expect(res.json()).toMatchObject({ cardTitle: null, primaryColor: '#aabbcc', publicFields: [] });
    });

    it.each([
      ['named colour', { primaryColor: 'red' }],
      ['short hex', { primaryColor: '#abc' }],
      ['no hash', { secondaryColor: 'aabbcc' }],
      ['8-digit hex', { primaryColor: '#aabbccdd' }],
      ['non-hex digits', { primaryColor: '#gggggg' }],
      ['trailing newline', { primaryColor: '#aabbcc\n' }],
      ['css injection', { primaryColor: '#aabbcc;background:url(x)' }],
      ['number', { primaryColor: 123456 }],
      ['null colour', { primaryColor: null }],
    ])('rejects bad colour: %s', async (_n, body) => {
      const before = await row(INST_A);
      const res = await call(a, 'PATCH', body);
      expect(res.statusCode).toBe(400);
      expect(res.json().error.code).toBe('INVALID_COLOR');
      expect((await row(INST_A)).updated_at).toEqual(before.updated_at);
    });

    it.each([
      ['unknown field name', { publicFields: ['photo', 'email'] }],
      ['not an array', { publicFields: 'photo' }],
      ['non-string member', { publicFields: [1] }],
      ['name is always shown, not configurable', { publicFields: ['name'] }],
      ['too-long card title', { cardTitle: 'x'.repeat(101) }],
      ['empty card title', { cardTitle: '  ' }],
      ['control chars in card title', { cardTitle: 'a\u0000b' }],
      ['empty body', {}],
    ])('rejects: %s', async (_n, body) => {
      expect((await call(a, 'PATCH', body)).statusCode).toBe(400);
    });

    it.each([
      ['id', { id: INST_B }],
      ['institutionId', { institutionId: INST_B }],
      ['institution_id', { institution_id: INST_B }],
      ['name', { name: 'Hijack' }],
      ['slug', { slug: 'hijack' }],
      ['status', { status: 'SUSPENDED' }],
      ['logoKey', { logoKey: 'institutions/x/logo/evil.png' }],
      ['mixed valid + unknown', { cardTitle: 'ok', extra: 1 }],
    ])('rejects unknown/forbidden property: %s, and writes nothing', async (_n, body) => {
      const before = await row(INST_A);
      const res = await call(a, 'PATCH', body);
      expect(res.statusCode).toBe(400);
      expect(res.json().error.code).toBe('UNKNOWN_PROPERTY');
      expect(await row(INST_A)).toEqual(before);
      expect(await row(INST_B)).toMatchObject({ name: 'Inst inst-b', status: 'ACTIVE' });
    });

    it('rejects non-object bodies', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: '/api/v1/institution',
        headers: { ...a.headers, ...json },
        payload: '[1]',
      });
      expect(res.statusCode).toBe(400);
    });
  });

  describe('tenancy', () => {
    it('an admin of tenant A never reads or changes tenant B, even when naming it', async () => {
      const bBefore = await row(INST_B);
      const res = await call(a, 'PATCH', { cardTitle: 'A only', institutionId: INST_B });
      expect(res.statusCode).toBe(400);
      const ok = await call(a, 'PATCH', { cardTitle: 'A only' });
      expect(ok.json().id).toBe(INST_A);
      expect(await row(INST_B)).toEqual(bBefore);
      const getB = await call(b, 'GET');
      expect(getB.json()).toMatchObject({ id: INST_B, cardTitle: null });
      // Query string / header attempts to pick another tenant are ignored.
      const viaQuery = await app.inject({
        method: 'GET',
        url: `/api/v1/institution?institutionId=${INST_B}`,
        headers: { ...a.headers, 'x-institution-id': INST_B },
      });
      expect(viaQuery.json().id).toBe(INST_A);
    });

    it('a logo upload by A only touches A', async () => {
      const bBefore = await row(INST_B);
      const res = await upload(a, [{ name: 'file', filename: 'l.png', type: 'image/png', data: PNG() }]);
      expect(res.statusCode).toBe(200);
      expect(await row(INST_B)).toEqual(bBefore);
      expect((await row(INST_A)).logo_key).toMatch(
        new RegExp(`^institutions/${INST_A}/logo/[0-9a-f-]{36}\\.png$`),
      );
      expect((await call(b, 'GET')).json().hasLogo).toBe(false);
    });
  });

  describe('POST /institution/logo', () => {
    it('stores a PNG privately, strips metadata, returns no URL or key, replaces and deletes the old one', async () => {
      const first = (await row(INST_A)).logo_key as string;
      expect(storage.objects.has(first)).toBe(true);

      const src = PNG(0, ['eXIf', 'GPS-SECRET'], ['tEXt', 'Author\0me']);
      const res = await upload(a, [
        // Hostile name and a lying content-type: both are ignored, the bytes decide.
        { name: 'file', filename: '../../etc/passwd.svg', type: 'text/html', data: src },
      ]);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.hasLogo).toBe(true);
      const text = JSON.stringify(body);
      expect(text).not.toMatch(/institutions\/|logo_key|logoKey|https?:|memory:/);

      const key = (await row(INST_A)).logo_key as string;
      expect(key).not.toBe(first);
      expect(key).toMatch(new RegExp(`^institutions/${INST_A}/logo/[0-9a-f-]{36}\\.png$`));
      expect(key).not.toContain('passwd');
      const stored = storage.objects.get(key)!;
      expect(stored.contentType).toBe('image/png');
      expect(stored.body.includes('GPS-SECRET')).toBe(false);
      expect(stored.body.includes('eXIf')).toBe(false);
      expect(storage.objects.has(first)).toBe(false); // previous object removed
    });

    it('accepts JPEG', async () => {
      const res = await upload(a, [{ name: 'file', filename: 'l.jpg', type: 'image/jpeg', data: JPEG() }]);
      expect(res.statusCode).toBe(200);
      const key = (await row(INST_A)).logo_key as string;
      expect(key).toMatch(/\.jpg$/);
      expect(storage.objects.get(key)!.contentType).toBe('image/jpeg');
    });

    it.each([
      ['GIF', Buffer.from('GIF89a\x01\x00\x01\x00\x00\x00\x00;')],
      ['SVG', Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>1</script></svg>')],
      ['HTML', Buffer.from('<html><script>alert(1)</script></html>')],
      ['PHP-ish text', Buffer.from('<?php system($_GET[0]); ?>')],
      ['PDF', Buffer.from('%PDF-1.4\n')],
    ])('rejects %s even when labelled image/png', async (_n, data) => {
      const before = storage.objects.size;
      const res = await upload(a, [{ name: 'file', filename: 'logo.png', type: 'image/png', data }]);
      expect(res.statusCode).toBe(415);
      expect(res.json().error.code).toBe('UNSUPPORTED_IMAGE_TYPE');
      expect(storage.objects.size).toBe(before);
    });

    it('rejects damaged images and an empty file', async () => {
      expect(
        (await upload(a, [{ name: 'file', filename: 'l.png', data: PNG().subarray(0, 40) }])).statusCode,
      ).toBe(400);
      expect((await upload(a, [{ name: 'file', filename: 'l.png', data: '' }])).statusCode).toBe(400);
    });

    it('rejects files over the cap (413) and stores nothing', async () => {
      const keyBefore = (await row(INST_A)).logo_key;
      const before = storage.objects.size;
      const big = PNG(MAX); // pixel chunk alone exceeds the cap
      const res = await upload(a, [{ name: 'file', filename: 'l.png', type: 'image/png', data: big }]);
      expect(res.statusCode).toBe(413);
      expect(res.json().error.code).toBe('PAYLOAD_TOO_LARGE');
      expect((await row(INST_A)).logo_key).toBe(keyBefore);
      expect(storage.objects.size).toBe(before);
    });

    it('rejects wrong field name, extra fields, no file, and non-multipart', async () => {
      expect((await upload(a, [{ name: 'logo', filename: 'l.png', data: PNG() }])).statusCode).toBe(400);
      expect((await upload(a, [{ name: 'note', data: 'hello' }])).statusCode).toBe(400);
      expect(
        (
          await upload(a, [
            { name: 'x', data: 'y' }, // a text field before the file is refused (fields limit 0)
            { name: 'file', filename: 'l.png', data: PNG() },
          ])
        ).statusCode,
      ).toBeGreaterThanOrEqual(400);
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/institution/logo',
        headers: { ...a.headers, 'content-type': 'image/png' },
        payload: PNG(),
      });
      expect([400, 415]).toContain(res.statusCode);
    });

    it('does not change the logo when storage fails, and answers 503 without detail', async () => {
      const keyBefore = (await row(INST_A)).logo_key;
      storage.failPut = true;
      try {
        const res = await upload(a, [{ name: 'file', filename: 'l.png', data: PNG() }]);
        expect(res.statusCode).toBe(503);
        expect(res.json().error.code).toBe('STORAGE_UNAVAILABLE');
      } finally {
        storage.failPut = false;
      }
      expect((await row(INST_A)).logo_key).toBe(keyBefore);
    });

    it('answers 503 when storage is not configured', async () => {
      const bare = await buildApp({ config: { logLevel: 'silent', rateLimit }, db });
      try {
        const login = await bare.inject({
          method: 'POST',
          url: '/api/v1/auth/login',
          headers: json,
          payload: { email: 'b@example.test', password: PW },
        });
        const cookie = String(login.headers['set-cookie']).split(';')[0]!;
        const res = await bare.inject({
          method: 'POST',
          url: '/api/v1/institution/logo',
          headers: {
            cookie,
            'x-csrf-token': csrfTokenFor(cookie.slice(cookie.indexOf('=') + 1)),
            ...multipartHeaders(),
          },
          payload: multipartBody([{ name: 'file', filename: 'l.png', data: PNG() }]).payload,
        });
        expect([503, 400]).toContain(res.statusCode);
        expect(res.statusCode).toBe(503);
      } finally {
        await bare.close();
      }
    });

    it('never logs key paths, file bytes or tokens', () => {
      const all = logs.join('');
      expect(all).not.toContain('GPS-SECRET');
      expect(all).not.toMatch(/institutions\/[0-9a-f-]{36}\/logo/);
      expect(all).not.toContain(a.headers['x-csrf-token']!);
      expect(all).toContain('institution.logo_updated');
    });
  });
});

// Only used by the 503 test: the boundary value is irrelevant because the route refuses before parsing.
function multipartHeaders(): Record<string, string> {
  return { 'content-type': 'multipart/form-data; boundary=----x' };
}
