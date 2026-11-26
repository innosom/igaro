// Unit tests for card.render (T-039): template escaping, QR content, photo hash binding, job contract,
// handler flow with a fake pool and renderer. No browser, no database.
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import { createLogger } from './logger.js';
import {
  CARD_CSP,
  assertVerifyUrl,
  esc,
  qrMatrix,
  qrSvg,
  renderCardHtml,
  safeColor,
  sniffImage,
  type CardModel,
} from './card-template.js';
import {
  CardRenderNotFoundError,
  photoIfHashMatches,
  readSignedView,
  runCardRender,
  type CardRenderer,
} from './card-render.js';
import {
  CARD_RENDER_QUEUE,
  cardRenderSingletonKey,
  cardStorageKeys,
  enqueueCardRender,
  parseCardRenderJobData,
} from './card-render-job.js';
import { MemoryWorkerStorage } from './card-storage.js';
import { loadWorkerConfig } from './config.js';

const TOKEN = 'AbCdEfGhIjKlMnOpQrStUv';
const URL_OK = `https://verify.igaro.app/v/${TOKEN}`;
const INST = '11111111-1111-4111-8111-111111111111';
const CRED = '22222222-2222-4222-8222-222222222222';
const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.from('rest-of-image')]);
const sha = (b: Buffer): string => createHash('sha256').update(b).digest('hex');

const model = (over: Partial<CardModel> = {}): CardModel => ({
  kind: 'ID_CARD',
  institutionName: 'Example University',
  cardTitle: 'Student ID',
  primaryColor: '#1d4ed8',
  secondaryColor: '#0f172a',
  logo: null,
  photo: null,
  holderName: 'Ada Lovelace',
  idNumber: 'S-1001',
  credentialTypeName: 'Student ID',
  credentialNumber: 'IG-2026-000001',
  issuedAt: '2026-11-26T10:00:00.000Z',
  expiresAt: null,
  attributes: { Programme: 'Mathematics' },
  verifyUrl: URL_OK,
  ...over,
});

describe('template escaping', () => {
  it('escapes every dynamic text field', () => {
    const evil = `<script>alert(1)</script><img src=x onerror=alert(2)>"'&\``;
    const html = renderCardHtml(
      model({
        institutionName: evil,
        cardTitle: evil,
        holderName: evil,
        idNumber: evil,
        credentialTypeName: evil,
        credentialNumber: evil,
        attributes: { [evil]: evil },
      }),
    );
    expect(html).not.toContain('<script');
    expect(html).not.toMatch(/<img[^>]*onerror/i);
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    // the only <img> tags are ours (none here: no logo and no photo)
    expect(html).not.toMatch(/<img\b/);
    expect(html).toContain(`content="${CARD_CSP}"`);
  });

  it('strips bidi and control characters', () => {
    expect(esc('A‮B​C\u0000D')).toBe('ABCD');
  });

  it('colours: only #rgb or #rrggbb survive, anything else falls back', () => {
    expect(safeColor('#ABC', '#000000')).toBe('#aabbcc');
    expect(safeColor('#12ab34', '#000000')).toBe('#12ab34');
    for (const bad of ['red', 'url(http://x)', '#12345', '#1234567', 'expression(1)', '#fff;}</style><script>', '']) {
      expect(safeColor(bad, '#111111')).toBe('#111111');
    }
    const html = renderCardHtml(model({ primaryColor: 'red;}</style><script>x</script>', secondaryColor: 'url(http://evil/)' }));
    expect(html).not.toContain('evil');
    expect(html).not.toContain('<script');
  });

  it('images become data: URLs with a sniffed type, never the stored name or type', () => {
    const html = renderCardHtml(model({ photo: { mime: 'image/png', bytes: PNG }, logo: { mime: 'image/png', bytes: PNG } }));
    const srcs = [...html.matchAll(/src="([^"]*)"/g)].map((m) => m[1]);
    expect(srcs).toHaveLength(2);
    for (const s of srcs) expect(s).toMatch(/^data:image\/png;base64,[A-Za-z0-9+/=]+$/);
    expect(sniffImage(Buffer.from('<svg onload=alert(1)>'))).toBeNull();
    expect(sniffImage(Buffer.from('GIF89a'))).toBeNull();
  });

  it('shows the fixed verification text and the host of the verify URL', () => {
    expect(renderCardHtml(model())).toContain('Verify only at verify.igaro.app');
    expect(renderCardHtml(model({ kind: 'CERTIFICATE' }))).toContain('Verify only at verify.igaro.app');
  });
});

describe('QR content', () => {
  it('encodes only the public /v/<token> URL', () => {
    // Changing every holder and credential field must not change a single module.
    const a = qrMatrix(URL_OK);
    const html1 = renderCardHtml(model());
    const html2 = renderCardHtml(model({ holderName: 'Someone Else', credentialNumber: 'X', idNumber: 'Y', attributes: {} }));
    const path = (h: string): string => /<path d="([^"]*)"/.exec(h)![1]!;
    expect(path(html1)).toBe(path(html2));
    expect(html1).toContain(qrSvg(URL_OK));
    // and a different token does change it
    expect(path(renderCardHtml(model({ verifyUrl: `https://verify.igaro.app/v/${TOKEN.replace('A', 'B')}` })))).not.toBe(path(html1));
    expect(a.length).toBeGreaterThan(20);
  });

  it('refuses anything that is not exactly /v/<token>', () => {
    for (const bad of [
      `https://verify.igaro.app/v/${TOKEN}?name=Ada`,
      `https://verify.igaro.app/v/${TOKEN}#x`,
      `https://verify.igaro.app/h/${TOKEN}`,
      `https://verify.igaro.app/v/short`,
      `https://u:p@verify.igaro.app/v/${TOKEN}`,
      `javascript:alert(1)`,
      `ftp://verify.igaro.app/v/${TOKEN}`,
      `https://verify.igaro.app/v/${TOKEN}/extra`,
      'not a url',
    ]) {
      expect(() => assertVerifyUrl(bad), bad).toThrow();
      expect(() => qrSvg(bad), bad).toThrow();
    }
    expect(() => assertVerifyUrl(URL_OK)).not.toThrow();
  });
});

describe('photo bound to the signed hash', () => {
  it('uses the photo only when SHA-256(bytes) equals payload.holder.photoSha256', () => {
    expect(photoIfHashMatches(PNG, sha(PNG))).toEqual({ mime: 'image/png', bytes: PNG });
    expect(photoIfHashMatches(PNG, sha(PNG).toUpperCase())).toBeNull(); // payload hashes are lower-case; readSignedView lower-cases
    expect(photoIfHashMatches(PNG, sha(Buffer.from('another photo')))).toBeNull();
    expect(photoIfHashMatches(null, sha(PNG))).toBeNull();
    expect(photoIfHashMatches(PNG, 'nothex')).toBeNull();
  });

  it('refuses a hash-matching blob that is not an image', () => {
    const b = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>');
    expect(photoIfHashMatches(b, sha(b))).toBeNull();
  });
});

describe('signed payload view', () => {
  const payload = {
    credentialId: CRED,
    institutionId: INST,
    credentialNumber: 'IG-1',
    holder: { fullName: 'Ada', externalId: null, photoSha256: sha(PNG).toUpperCase() },
    attributes: { a: 'b', n: 5 },
    issuedAt: '2026-01-01T00:00:00.000Z',
    expiresAt: null,
  };
  it('reads display fields from the payload and drops non-string attributes', () => {
    const v = readSignedView(payload, { institutionId: INST, credentialId: CRED });
    expect(v).toMatchObject({ holderName: 'Ada', idNumber: null, photoSha256: sha(PNG), attributes: { a: 'b' } });
  });
  it('rejects a payload that belongs to another credential or tenant', () => {
    expect(() => readSignedView(payload, { institutionId: INST, credentialId: INST })).toThrow(CardRenderNotFoundError);
    expect(() => readSignedView(payload, { institutionId: CRED, credentialId: CRED })).toThrow(CardRenderNotFoundError);
    expect(() => readSignedView({}, { institutionId: INST, credentialId: CRED })).toThrow(CardRenderNotFoundError);
  });
});

describe('job contract', () => {
  it('validates ids and builds institution-scoped keys', () => {
    expect(parseCardRenderJobData({ institutionId: INST, credentialId: CRED, extra: 'x' })).toEqual({ institutionId: INST, credentialId: CRED });
    expect(() => parseCardRenderJobData({ institutionId: 'x', credentialId: CRED })).toThrow();
    expect(() => parseCardRenderJobData(null)).toThrow();
    expect(cardStorageKeys(INST, CRED)).toEqual({
      png: `institutions/${INST}/credentials/${CRED}/card.png`,
      pdf: `institutions/${INST}/credentials/${CRED}/card.pdf`,
    });
  });
  it('enqueue uses a per-credential singleton key and carries ids only', async () => {
    const sent: unknown[] = [];
    const ok = await enqueueCardRender(
      { send: (n, d, o) => (sent.push([n, d, o]), Promise.resolve('job-1')) },
      { institutionId: INST, credentialId: CRED },
    );
    expect(ok).toBe(true);
    expect(sent[0]).toEqual([CARD_RENDER_QUEUE, { institutionId: INST, credentialId: CRED }, { singletonKey: cardRenderSingletonKey(CRED) }]);
    expect(await enqueueCardRender({ send: () => Promise.resolve(null) }, { institutionId: INST, credentialId: CRED })).toBe(false);
  });
});

describe('config', () => {
  const base = { APP_DATABASE_URL: 'postgresql://u:p@localhost/db', SMTP_HOST: 'localhost', SMTP_FROM: 'a@b.test', WEB_BASE_URL: 'http://localhost:3000' };
  const s3 = { S3_BUCKET: 'igaro', S3_ACCESS_KEY: 'k', S3_SECRET_KEY: 's3cr3t-value', S3_ENDPOINT: 'http://localhost:9000' };
  it('is off without S3 and on with S3 + CHROME_PATH', () => {
    expect(loadWorkerConfig({ ...base, CHROME_PATH: '/x/chrome' }).cardRender).toBeUndefined();
    const c = loadWorkerConfig({ ...base, ...s3, CHROME_PATH: '/x/chrome', CHROME_NO_SANDBOX: 'true' }).cardRender;
    expect(c).toMatchObject({ chromePath: '/x/chrome', chromeNoSandbox: true, verifyBaseUrl: 'http://localhost:3000' });
  });
  it('rejects a relative CHROME_PATH and a partial S3 config', () => {
    expect(() => loadWorkerConfig({ ...base, ...s3, CHROME_PATH: 'chrome' })).toThrow(/absolute/);
    expect(() => loadWorkerConfig({ ...base, S3_BUCKET: 'igaro' })).toThrow(/together/);
  });
});

describe('runCardRender handler', () => {
  const logs: string[] = [];
  const logger = createLogger('debug', { write: (s: string) => void logs.push(s) });
  const payload = (photoSha256: string) => ({
    credentialId: CRED,
    institutionId: INST,
    credentialNumber: 'IG-1',
    holder: { fullName: 'Ada', externalId: 'S-1', photoSha256 },
    attributes: {},
    issuedAt: '2026-01-01T00:00:00.000Z',
    expiresAt: null,
    salt: 'SALT-MUST-NOT-BE-LOGGED',
  });
  const fakePool = (row: Record<string, unknown> | undefined, queries: string[] = []): Pool =>
    ({
      connect: () =>
        Promise.resolve({
          query: (sql: string, params?: unknown[]) => {
            queries.push(`${sql.split('\n')[0]}|${JSON.stringify(params ?? [])}`);
            return Promise.resolve({ rows: /FROM credentials/.test(sql) && row ? [row] : [] });
          },
          release: () => undefined,
        }),
    }) as unknown as Pool;
  const rowFor = (p: unknown, status = 'ACTIVE') => ({
    credential_number: 'IG-1', status, payload: p, verification_token: TOKEN, type_name: 'Student ID', kind: 'ID_CARD',
    photo_key: `institutions/${INST}/holders/h/photo/p.png`, inst_name: 'Uni', logo_key: null,
    primary_color: '#1d4ed8', secondary_color: '#0f172a', card_title: null,
  });
  const renderer = (seen: string[]): CardRenderer => ({
    render: (html) => (seen.push(html), Promise.resolve({ png: Buffer.from('PNG'), pdf: Buffer.from('PDF'), blockedRequests: 0 })),
  });

  it('renders, scopes to the job institution and stores both files', async () => {
    const storage = new MemoryWorkerStorage();
    await storage.put(`institutions/${INST}/holders/h/photo/p.png`, PNG, 'image/png');
    const seen: string[] = [];
    const queries: string[] = [];
    const out = await runCardRender(
      { pool: fakePool(rowFor(payload(sha(PNG))), queries), storage, renderer: renderer(seen), verifyBaseUrl: 'https://verify.igaro.app', logger },
      { institutionId: INST, credentialId: CRED },
    );
    expect(out).toBe('rendered');
    expect(queries.some((q) => q.includes('set_config') && q.includes(INST))).toBe(true);
    expect(seen[0]).toContain('class="photo" alt="" src="data:image/png');
    expect(seen[0]).toContain(qrSvg(URL_OK));
    const keys = cardStorageKeys(INST, CRED);
    expect(storage.objects.get(keys.png)).toMatchObject({ contentType: 'image/png' });
    expect(storage.objects.get(keys.pdf)).toMatchObject({ contentType: 'application/pdf' });
    // nothing sensitive in the logs
    const all = logs.join('\n');
    for (const secret of [TOKEN, 'SALT-MUST-NOT-BE-LOGGED']) expect(all).not.toContain(secret);
  });

  it('omits the photo when its hash does not match the signed hash', async () => {
    const storage = new MemoryWorkerStorage();
    await storage.put(`institutions/${INST}/holders/h/photo/p.png`, PNG, 'image/png');
    const seen: string[] = [];
    const out = await runCardRender(
      { pool: fakePool(rowFor(payload(sha(Buffer.from('the originally issued photo'))))), storage, renderer: renderer(seen), verifyBaseUrl: 'https://verify.igaro.app', logger },
      { institutionId: INST, credentialId: CRED },
    );
    expect(out).toBe('rendered');
    expect(seen[0]).not.toContain('class="photo" alt=""');
    expect(seen[0]).toContain('class="photo ph"');
    expect(seen[0]).not.toContain(PNG.toString('base64'));
  });

  it('skips non-ACTIVE credentials and throws for unknown ones (retryable)', async () => {
    const storage = new MemoryWorkerStorage();
    const seen: string[] = [];
    const deps = (row: ReturnType<typeof rowFor> | undefined) => ({ pool: fakePool(row), storage, renderer: renderer(seen), verifyBaseUrl: 'https://verify.igaro.app', logger });
    expect(await runCardRender(deps(rowFor(payload(sha(PNG)), 'REVOKED')), { institutionId: INST, credentialId: CRED })).toBe('skipped_not_active');
    expect(seen).toHaveLength(0);
    await expect(runCardRender(deps(undefined), { institutionId: INST, credentialId: CRED })).rejects.toBeInstanceOf(CardRenderNotFoundError);
  });
});
