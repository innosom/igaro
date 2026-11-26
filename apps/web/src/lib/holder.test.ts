import { describe, expect, it, vi } from 'vitest';
import {
  cardMagicOk,
  credentialFileHref,
  fetchHolder,
  holderCardHref,
  parseHolderResponse,
  parseSignedLocation,
  readCapped,
  statusText,
} from './holder';

const TOKEN = 'Hq3AbCdEfGhIjKlMnOpQrS';
const VT = 'Xq3AbCdEfGhIjKlMnOpQrS';
const body = (over: Record<string, unknown> = {}) => ({
  holder: { fullName: 'Amina Yusuf' },
  institution: { name: 'EAU', slug: 'eau', cardTitle: 'EAU', primaryColor: '#112233', secondaryColor: '#abc' },
  credentials: [
    {
      verificationToken: VT,
      type: { code: 'DEG', name: 'Degree', kind: 'CERT' },
      status: 'ACTIVE',
      issuedAt: '2026-01-01T00:00:00.000Z',
      expiresAt: null,
      links: { verify: '/v/x', credentialJson: '/x', publicKeys: '/i/eau/keys.json', card: '/api/v1/holder/evil/card.png', cardPdf: null },
      ...over,
    },
  ],
});
const res = (status: number, json?: unknown) =>
  ({ status, json: async () => json }) as unknown as Response;

describe('parseHolderResponse', () => {
  it('parses a full body and treats links as flags only', () => {
    const d = parseHolderResponse(body())!;
    expect(d.holderName).toBe('Amina Yusuf');
    expect(d.credential.hasCardPng).toBe(true);
    expect(d.credential.hasCardPdf).toBe(false);
    expect(d.institution.slug).toBe('eau');
  });
  it('rejects malformed bodies', () => {
    expect(parseHolderResponse(null)).toBeNull();
    expect(parseHolderResponse({})).toBeNull();
    expect(parseHolderResponse({ ...body(), credentials: [] })).toBeNull();
    expect(parseHolderResponse(body({ verificationToken: 'a/b' }))).toBeNull();
    expect(parseHolderResponse(body({ status: null }))).toBeNull();
  });
  it('drops an unsafe slug', () => {
    const b = body();
    b.institution.slug = '../x';
    expect(parseHolderResponse(b)!.institution.slug).toBe('');
  });
});

describe('hrefs', () => {
  it('builds same-origin paths from validated tokens only', () => {
    expect(holderCardHref(TOKEN, 'png')).toBe('/h/' + TOKEN + '/card.png');
    expect(holderCardHref(TOKEN, 'pdf')).toBe('/h/' + TOKEN + '/card.pdf');
    expect(holderCardHref('../x', 'png')).toBeNull();
    expect(credentialFileHref(VT)).toBe('/api/v1/verify/' + VT + '/credential.json');
    expect(credentialFileHref('bad token')).toBeNull();
  });
});

describe('fetchHolder', () => {
  it('does not call the API for an implausible token', async () => {
    const f = vi.fn();
    expect(await fetchHolder('x', { fetch: f as never })).toEqual({ kind: 'not_found' });
    expect(f).not.toHaveBeenCalled();
  });
  it('maps 200 / 404 / other / throw', async () => {
    const ok = await fetchHolder(TOKEN, { fetch: (async () => res(200, body())) as never });
    expect(ok.kind).toBe('ok');
    expect(await fetchHolder(TOKEN, { fetch: (async () => res(404)) as never })).toEqual({ kind: 'not_found' });
    expect(await fetchHolder(TOKEN, { fetch: (async () => res(429)) as never })).toEqual({ kind: 'unavailable' });
    expect(await fetchHolder(TOKEN, { fetch: (async () => res(500)) as never })).toEqual({ kind: 'unavailable' });
    expect(await fetchHolder(TOKEN, { fetch: (async () => res(200, { nope: 1 })) as never })).toEqual({ kind: 'unavailable' });
    expect(
      await fetchHolder(TOKEN, {
        fetch: (async () => {
          throw new Error('x');
        }) as never,
      }),
    ).toEqual({ kind: 'unavailable' });
  });
  it('sends no-store, no-referrer, no redirects and only a valid forwarded IP', async () => {
    const f = vi.fn(async () => res(404));
    await fetchHolder(TOKEN, { fetch: f as never, apiUrl: 'http://api:4000/', clientIp: '203.0.113.9' });
    const [url, init] = f.mock.calls[0] as unknown as [string, RequestInit & { headers: Record<string, string> }];
    expect(url).toBe('http://api:4000/api/v1/holder/' + TOKEN);
    expect(init.cache).toBe('no-store');
    expect(init.referrerPolicy).toBe('no-referrer');
    expect(init.redirect).toBe('error');
    expect(init.headers['X-Forwarded-For']).toBe('203.0.113.9');
    await fetchHolder(TOKEN, { fetch: f as never, clientIp: 'evil, 1.1.1.1' });
    expect((f.mock.calls[1] as unknown as [string, { headers: Record<string, string> }])[1].headers['X-Forwarded-For']).toBeUndefined();
  });
});

describe('card proxy helpers', () => {
  it('follows only a Location whose origin equals STORAGE_PUBLIC_ORIGIN', () => {
    const o = 'https://s3.example';
    expect(parseSignedLocation('https://s3.example/x?sig=1', o)?.hostname).toBe('s3.example');
    expect(parseSignedLocation('http://minio:9000/x', 'http://minio:9000')).not.toBeNull();
    expect(parseSignedLocation('https://evil.example/x', o)).toBeNull();
    expect(parseSignedLocation('http://s3.example/x', o)).toBeNull();
    expect(parseSignedLocation('https://s3.example:8443/x', o)).toBeNull();
    expect(parseSignedLocation('https://s3.example.evil.example/x', o)).toBeNull();
    expect(parseSignedLocation('https://s3.example@evil.example/x', o)).toBeNull();
    expect(parseSignedLocation('javascript:alert(1)', o)).toBeNull();
    expect(parseSignedLocation('/relative', o)).toBeNull();
    expect(parseSignedLocation(null, o)).toBeNull();
  });
  it('refuses every Location when STORAGE_PUBLIC_ORIGIN is unset or invalid', () => {
    expect(parseSignedLocation('https://s3.example/x', undefined)).toBeNull();
    expect(parseSignedLocation('https://s3.example/x', '')).toBeNull();
    expect(parseSignedLocation('https://s3.example/x', 'not a url')).toBeNull();
    expect(parseSignedLocation('ftp://s3.example/x', 'ftp://s3.example')).toBeNull();
  });
  it('readCapped streams and aborts past the cap', async () => {
    const mk = (chunks: number[]) => {
      let i = 0;
      let pulled = 0;
      const stream = new ReadableStream<Uint8Array>({
        pull(c) {
          if (i >= chunks.length) return c.close();
          pulled++;
          c.enqueue(new Uint8Array(chunks[i++]).fill(1));
        },
      });
      return { res: new Response(stream), pulled: () => pulled };
    };
    expect((await readCapped(mk([4, 4]).res, 10))?.byteLength).toBe(8);
    const big = mk([6, 6, 6, 6, 6, 6]);
    expect(await readCapped(big.res, 10)).toBeNull();
    expect(big.pulled()).toBeLessThan(6);
    expect(await readCapped(mk([]).res, 10)).toBeNull();
  });
  it('readCapped refuses non-numeric or oversized Content-Length', async () => {
    for (const cl of ['abc', '-1', '1e3', '0x10', '99999999999999', '11']) {
      const r = new Response(new Uint8Array(5), { headers: { 'content-length': cl } });
      expect(await readCapped(r, 10)).toBeNull();
    }
    const ok = new Response(new Uint8Array(5), { headers: { 'content-length': '5' } });
    expect((await readCapped(ok, 10))?.byteLength).toBe(5);
  });
  it('checks magic bytes', () => {
    const png = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0]);
    const pdf = new TextEncoder().encode('%PDF-1.7');
    expect(cardMagicOk(png, 'png')).toBe(true);
    expect(cardMagicOk(pdf, 'pdf')).toBe(true);
    expect(cardMagicOk(pdf, 'png')).toBe(false);
    expect(cardMagicOk(new TextEncoder().encode('<html>'), 'pdf')).toBe(false);
  });
  it('has text for every status', () => {
    for (const s of ['ACTIVE', 'SUSPENDED', 'REVOKED', 'SUPERSEDED', 'EXPIRED']) expect(statusText(s).label).not.toBe('Unknown');
    expect(statusText('???').label).toBe('Unknown');
  });
});
