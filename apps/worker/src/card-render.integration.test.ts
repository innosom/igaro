// Integration for card.render (T-039): real Postgres (scratch schema, igaro_worker role, RLS) and, when a
// Chrome executable exists, a real headless render of PNG and PDF. Skipped without DATABASE_URL; the Chrome
// tests are skipped without Chrome. No external network is used.
import { createHash, randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { deflateSync } from 'node:zlib';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import { createHarness, hasDatabase, type Harness } from '@igaro/db/testing';
import { runCardRender, CardRenderNotFoundError, ChromeCardRenderer, type CardRenderer } from './card-render.js';
import { cardStorageKeys } from './card-render-job.js';
import { MemoryWorkerStorage } from './card-storage.js';
import { findChrome } from './config.js';
import { createLogger } from './logger.js';
import { renderCardHtml } from './card-template.js';

const chrome = findChrome();
const url = process.env.DATABASE_URL;

function crc32(buf: Buffer): number {
  let c = ~0;
  for (const b of buf) {
    c ^= b;
    for (let k = 0; k < 8; k++) c = c & 1 ? (c >>> 1) ^ 0xedb88320 : c >>> 1;
  }
  return ~c >>> 0;
}
const chunk = (type: string, data: Buffer): Buffer => {
  const t = Buffer.from(type, 'latin1');
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([t, data])));
  return Buffer.concat([len, t, data, crc]);
};
/** A real, decodable solid-colour PNG. */
function solidPng(w: number, h: number, rgb: [number, number, number]): Buffer {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8;
  ihdr[9] = 2;
  const row = Buffer.concat([Buffer.from([0]), Buffer.from(Array.from({ length: w }, () => rgb).flat())]);
  const raw = Buffer.concat(Array.from({ length: h }, () => row));
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}
const sha = (b: Buffer): string => createHash('sha256').update(b).digest('hex');

describe.skipIf(!hasDatabase)('card.render against Postgres', () => {
  let h: Harness;
  let pool: pg.Pool;
  const lines: string[] = [];
  const logger = createLogger('debug', { write: (s: string) => void lines.push(s) });
  const storage = new MemoryWorkerStorage();
  const photo = solidPng(40, 50, [200, 30, 30]);
  const TOKEN = randomBytes(16).toString('base64url');
  const seen: string[] = [];
  const fake: CardRenderer = {
    render: (html) => (seen.push(html), Promise.resolve({ png: Buffer.from('PNG'), pdf: Buffer.from('PDF'), blockedRequests: 0 })),
  };
  let credId: string;
  let holderId: string;

  const deps = (renderer: CardRenderer) => ({
    pool,
    storage,
    renderer,
    verifyBaseUrl: 'https://verify.igaro.app',
    logger,
    assumeRole: 'igaro_worker',
  });

  async function addCredential(photoSha: string, status = 'ACTIVE'): Promise<string> {
    const id = h.uid();
    const t = h.A;
    const payload = {
      schemaVersion: 'igaro.credential.v1',
      credentialId: id,
      credentialNumber: 'IG-CARD-1',
      institutionId: t.institutionId,
      issuerKeyId: t.kid,
      credentialType: 'STUDENT_ID',
      holder: { fullName: 'Ada <b>Lovelace</b>', externalId: 'S-1001', photoSha256: photoSha },
      attributes: { Programme: 'Mathematics' },
      issuedAt: '2026-11-26T10:00:00.000Z',
      expiresAt: null,
      salt: randomBytes(32).toString('base64url'),
    };
    // The lifecycle triggers want ACTIVE rows with an ISSUED event in the same transaction; other states are
    // reached through events, so the non-ACTIVE case is a DRAFT row.
    await h.owner.query('BEGIN');
    try {
      await h.owner.query(
        `INSERT INTO credentials (id, institution_id, holder_id, type_id, credential_number, status, payload, data_hash,
           issuer_kid, signature, verification_token, holder_token_hash, issued_at, updated_at)
         VALUES ($1,$2,$3,$4,$10,$5,$6,'h',$7,'s',$8,$9,now(),now())`,
        [id, t.institutionId, holderId, t.typeId, status, JSON.stringify(payload), t.kid, randomBytes(16).toString('base64url'), `hh-${id}`, `IG-${id.slice(-6)}`],
      );
      if (status === 'ACTIVE') {
        await h.owner.query(`INSERT INTO credential_events (id, institution_id, credential_id, type) VALUES ($1,$2,$3,'ISSUED')`, [h.uid(), t.institutionId, id]);
      }
      await h.owner.query('COMMIT');
    } catch (e) {
      await h.owner.query('ROLLBACK');
      throw e;
    }
    return id;
  }

  beforeAll(async () => {
    h = await createHarness('t039');
    pool = new pg.Pool({ connectionString: url, options: `-c search_path=${h.schema}`, max: 3 });
    holderId = h.A.holderId;
    const key = `institutions/${h.A.institutionId}/holders/${holderId}/photo/p.png`;
    await storage.put(key, photo, 'image/png');
    await h.owner.query(`UPDATE credential_holders SET photo_key = $1, photo_sha256 = $2 WHERE id = $3`, [key, sha(photo), holderId]);
    await h.owner.query(`UPDATE institutions SET card_title = 'Campus <i>Pass</i>', primary_color = '#b91c1c' WHERE id = $1`, [h.A.institutionId]);
  }, 60000);

  afterAll(async () => {
    await pool?.end();
    await h?.close();
  });

  it('stores PNG and PDF under institution-scoped keys, using the photo that matches the signed hash', async () => {
    credId = await addCredential(sha(photo));
    seen.length = 0;
    const out = await runCardRender(deps(fake), { institutionId: h.A.institutionId, credentialId: credId });
    expect(out).toBe('rendered');
    const keys = cardStorageKeys(h.A.institutionId, credId);
    expect(keys.png.startsWith(`institutions/${h.A.institutionId}/`)).toBe(true);
    expect(storage.objects.has(keys.png) && storage.objects.has(keys.pdf)).toBe(true);
    expect(seen[0]).toContain('class="photo" alt="" src="data:image/png');
    expect(seen[0]).toContain('Ada &lt;b&gt;Lovelace&lt;/b&gt;');
    expect(seen[0]).toContain('Campus &lt;i&gt;Pass&lt;/i&gt;');
    expect(seen[0]).toContain('--primary: #b91c1c');
    const tok = (await h.owner.query<{ t: string }>(`SELECT verification_token AS t FROM credentials WHERE id = $1`, [credId])).rows[0]!.t;
    expect(seen[0]).not.toContain(tok); // the token is only inside the QR modules, never as text
    expect(lines.join('\n')).not.toContain(tok);
  });

  it('omits the photo when the stored bytes differ from the signed hash', async () => {
    const id = await addCredential(sha(Buffer.from('the photo as issued')));
    seen.length = 0;
    expect(await runCardRender(deps(fake), { institutionId: h.A.institutionId, credentialId: id })).toBe('rendered');
    expect(seen[0]).toContain('class="photo ph"');
    expect(seen[0]).not.toContain('class="photo" alt=""');
  });

  it('is tenant scoped: another institution cannot render this credential, and the DB read is column limited', async () => {
    seen.length = 0;
    await expect(runCardRender(deps(fake), { institutionId: h.B.institutionId, credentialId: credId })).rejects.toBeInstanceOf(CardRenderNotFoundError);
    expect(seen).toHaveLength(0);
    // the worker role cannot read the signature
    await h.asWorker({ 'app.institution_id': h.A.institutionId }, async (c) => {
      expect(await h.code(() => c.query('SELECT signature FROM credentials'))).toBe('42501');
    });
  });

  it('skips credentials that are not ACTIVE', async () => {
    const id = await addCredential(sha(photo), 'DRAFT');
    seen.length = 0;
    expect(await runCardRender(deps(fake), { institutionId: h.A.institutionId, credentialId: id })).toBe('skipped_not_active');
    expect(seen).toHaveLength(0);
  });

  describe.skipIf(!chrome)('with headless Chrome', () => {
    const renderer = new ChromeCardRenderer({
      executablePath: chrome ?? '/nonexistent',
      // CI containers often lack user namespaces. Only the test's own trusted HTML is loaded, so this is safe here.
      noSandbox: process.env.CHROME_NO_SANDBOX !== 'false',
    });

    it('renders a real PNG and PDF end to end', async () => {
      const id = await addCredential(sha(photo));
      const out = await runCardRender(deps(renderer), { institutionId: h.A.institutionId, credentialId: id });
      expect(out).toBe('rendered');
      const keys = cardStorageKeys(h.A.institutionId, id);
      const png = storage.objects.get(keys.png)!.body;
      const pdf = storage.objects.get(keys.pdf)!.body;
      expect(png.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))).toBe(true);
      expect(png.readUInt32BE(16)).toBe(856 * 2); // IHDR width at device scale 2
      expect(png.readUInt32BE(20)).toBe(540 * 2);
      expect(png.length).toBeGreaterThan(5_000);
      expect(pdf.subarray(0, 5).toString()).toBe('%PDF-');
      expect(pdf.length).toBeGreaterThan(1_000);
    }, 60000);

    it('blocks every request that is not a data: URL', async () => {
      let hits = 0;
      const srv: Server = createServer((_q, r) => {
        hits += 1;
        r.end('x');
      });
      await new Promise<void>((ok) => srv.listen(0, '127.0.0.1', ok));
      const port = (srv.address() as { port: number }).port;
      try {
        // Raw HTML (not the template) that tries to load a remote image and stylesheet.
        const html = `<!doctype html><html><body><img src="http://127.0.0.1:${port}/a.png"><link rel="stylesheet" href="http://127.0.0.1:${port}/s.css"><p>x</p></body></html>`;
        // JS is disabled and the page has no CSP here, so only interception and the resolver rules stop it.
        const r = await renderer.render(html, 'ID_CARD');
        expect(hits).toBe(0);
        expect(r.blockedRequests).toBeGreaterThanOrEqual(1);
        // the real template never produces a blocked request
        const ok = await renderer.render(renderCardHtml({
          kind: 'CERTIFICATE', institutionName: 'U', cardTitle: null, primaryColor: '#123456', secondaryColor: '#654321',
          logo: null, photo: { mime: 'image/png', bytes: photo }, holderName: 'A', idNumber: null, credentialTypeName: 'T',
          credentialNumber: 'N', issuedAt: null, expiresAt: null, attributes: {}, verifyUrl: `https://verify.igaro.app/v/${TOKEN}`,
        }), 'CERTIFICATE');
        expect(ok.blockedRequests).toBe(0);
        expect(ok.png.length).toBeGreaterThan(5_000);
      } finally {
        await new Promise((ok) => srv.close(ok));
      }
    }, 60000);
  });
});
