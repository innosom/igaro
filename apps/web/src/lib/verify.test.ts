import { describe, expect, it, vi } from 'vitest';
import {
  RESULTS,
  RESULT_VIEWS,
  brandCss,
  buildProofRows,
  clientIpFromXff,
  contrastRatio,
  parseTrustHops,
  visitorIp,
  fetchVerification,
  parseVerifyResponse,
  readableOn,
  sanitizeHex,
  warningText,
} from './verify';

const TOKEN = 'Xq3AbCdEfGhIjKlMnOpQrS';
const full = {
  result: 'VERIFIED',
  institution: {
    name: 'East Africa University',
    slug: 'eau',
    cardTitle: 'EAU',
    primaryColor: '#112233',
    secondaryColor: '#abc',
  },
  holder: {
    fullName: 'Amina Yusuf',
    idNumber: 'X1',
    attributes: { gpa: 3.5, nested: { a: 1 } },
    photoUrl: 'https://s/x.png',
  },
  type: { code: 'DEG', name: 'Degree', kind: 'CERT' },
  status: 'ACTIVE',
  issuedAt: '2026-01-01T00:00:00.000Z',
  expiresAt: null,
  supersededBy: null,
  proof: { signedBy: 'East Africa University', kid: 'k1', anchorStatus: 'NOT_ANCHORED' },
};
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });

describe('state mapping', () => {
  it('has a distinct label, icon and class for every result', () => {
    const views = RESULTS.map((r) => RESULT_VIEWS[r]);
    expect(new Set(views.map((v) => v.label)).size).toBe(RESULTS.length);
    expect(new Set(views.map((v) => v.icon)).size).toBe(RESULTS.length);
    expect(new Set(views.map((v) => v.classes)).size).toBe(RESULTS.length);
  });
  it('parses every result and keeps supersededBy only as a plausible token', () => {
    for (const r of RESULTS) expect(parseVerifyResponse({ ...full, result: r })?.result).toBe(r);
    expect(parseVerifyResponse({ ...full, result: 'SUPERSEDED', supersededBy: TOKEN })?.supersededBy).toBe(TOKEN);
    expect(parseVerifyResponse({ ...full, result: 'SUPERSEDED', supersededBy: '../evil' })?.supersededBy).toBeNull();
  });
  it('rejects an unknown result or malformed body (fail closed)', () => {
    expect(parseVerifyResponse({ ...full, result: 'OK' })).toBeNull();
    expect(parseVerifyResponse(null)).toBeNull();
    expect(parseVerifyResponse({ ...full, holder: null })).toBeNull();
  });
  it('NOT_FOUND and VERIFICATION_FAILED reveal nothing even if the body carries row data', () => {
    for (const r of ['NOT_FOUND', 'VERIFICATION_FAILED'] as const) {
      const d = parseVerifyResponse({ ...full, result: r })!;
      expect(d.holder).toBeNull();
      expect(d.institution).toBeNull();
      expect(d.proof).toBeNull();
      expect(d.type).toBeNull();
      expect(d.issuedAt).toBeNull();
      expect(RESULT_VIEWS[r].showDetails).toBe(false);
    }
  });
  it('only shows holder fields that were returned, and scalar attributes only', () => {
    const d = parseVerifyResponse({ ...full, holder: { fullName: 'A' } })!;
    expect(d.holder).toEqual({ fullName: 'A', idNumber: null, attributes: [], photoUrl: null });
    expect(parseVerifyResponse(full)!.holder!.attributes).toEqual([['gpa', '3.5']]);
  });
  it('maps the warning code to text', () => {
    expect(warningText('INSTITUTION_SUSPENDED')).toMatch(/suspended/);
    expect(warningText(null)).toBeNull();
  });
});

describe('colour sanitising', () => {
  it('accepts hex only and falls back otherwise', () => {
    expect(sanitizeHex('#AABBCC', '#000000')).toBe('#aabbcc');
    expect(sanitizeHex('#abc', '#000000')).toBe('#aabbcc');
    const bad = ['red', 'url(x)', '#12345', '#gggggg', 'red;}</style><script>', '#aabbcc;color:red', null, 5];
    for (const b of bad) expect(sanitizeHex(b, '#010101')).toBe('#010101');
  });
  it('brandCss never contains anything but sanitised hex values', () => {
    const css = brandCss({ primaryColor: '#fff}</style><script>alert(1)</script>', secondaryColor: '#123456' });
    expect(css).toMatch(/^\.brand\{--brand:#[0-9a-f]{6};--brand-fg:#(000000|ffffff);--brand-accent:#123456\}$/);
    expect(css).not.toContain('<');
  });
  it('picks a readable foreground', () => {
    for (const bg of ['#000000', '#ffffff', '#777777', '#ffcc00', '#1e3a8a']) {
      expect(contrastRatio(bg, readableOn(bg))).toBeGreaterThanOrEqual(4.5);
    }
  });
});

describe('proof panel', () => {
  it('shows signature and "Not anchored" from data', () => {
    const rows = buildProofRows({ signedBy: 'EAU', kid: 'k1', anchorStatus: 'NOT_ANCHORED' });
    expect(rows.map((r) => r.id)).toEqual(['signature', 'anchor']);
    expect(rows[0]!.detail).toBe('Key ID: k1');
    expect(rows[1]).toMatchObject({ label: 'Blockchain', value: 'Not anchored', ok: false });
  });
  it('renders a future anchor status without code changes and never claims it is established', () => {
    const rows = buildProofRows({ signedBy: 'EAU', kid: 'k1', anchorStatus: 'PENDING_CONFIRMATION<x>' });
    expect(rows[1]!.value).toBe('Pending confirmationx');
    expect(rows[1]!.ok).toBe(false);
  });
  it('returns no rows without proof', () => {
    expect(buildProofRows(null)).toEqual([]);
  });
});

describe('visitor IP forwarding', () => {
  it('parses hops strictly, defaulting to 0', () => {
    expect(parseTrustHops(undefined)).toBe(0);
    expect(parseTrustHops('2')).toBe(2);
    expect(parseTrustHops('10')).toBe(10);
    for (const b of ['11', '-1', 'x', '1.5', '', '100']) expect(parseTrustHops(b)).toBe(0);
  });
  it('takes the Nth address from the right and ignores spoofed leftmost entries', () => {
    expect(clientIpFromXff('6.6.6.6, 1.2.3.4', 1)).toBe('1.2.3.4');
    expect(clientIpFromXff('6.6.6.6, 1.2.3.4, 10.0.0.1', 2)).toBe('1.2.3.4');
    expect(clientIpFromXff('2001:db8::1', 1)).toBe('2001:db8::1');
  });
  it('is null when untrusted, too short or invalid', () => {
    expect(clientIpFromXff('1.2.3.4', 0)).toBeNull();
    expect(clientIpFromXff('1.2.3.4', 2)).toBeNull();
    expect(clientIpFromXff('1.2.3.4, not-an-ip', 1)).toBeNull();
    expect(clientIpFromXff('1.2.3.4, 1.2.3.4\r\nX-Evil: 1', 1)).toBeNull();
    expect(clientIpFromXff(null, 1)).toBeNull();
    expect(visitorIp('1.2.3.4', undefined)).toBeNull();
    expect(visitorIp('9.9.9.9, 1.2.3.4', '1')).toBe('1.2.3.4');
  });
  it('sends a single-value X-Forwarded-For only when an IP was derived', async () => {
    const f = vi.fn().mockResolvedValue(json(200, full));
    await fetchVerification(TOKEN, { fetch: f as unknown as typeof fetch, clientIp: '1.2.3.4' });
    expect(f.mock.calls[0]![1].headers['X-Forwarded-For']).toBe('1.2.3.4');
    await fetchVerification(TOKEN, { fetch: f as unknown as typeof fetch, clientIp: null });
    expect(f.mock.calls[1]![1].headers['X-Forwarded-For']).toBeUndefined();
    await fetchVerification(TOKEN, { fetch: f as unknown as typeof fetch, clientIp: '1.1.1.1, 2.2.2.2' });
    expect(f.mock.calls[2]![1].headers['X-Forwarded-For']).toBeUndefined();
  });
});

describe('fetch handling', () => {
  it('calls the API no-store with the token and returns the parsed result', async () => {
    const f = vi.fn().mockResolvedValue(json(200, full));
    const r = await fetchVerification(TOKEN, { fetch: f as unknown as typeof fetch, apiUrl: 'http://api:4000/' });
    expect(r.kind === 'ok' && r.data.result).toBe('VERIFIED');
    const [url, init] = f.mock.calls[0]!;
    expect(url).toBe('http://api:4000/api/v1/verify/' + TOKEN);
    expect(init.cache).toBe('no-store');
    expect(init.referrerPolicy).toBe('no-referrer');
  });
  it('does not call the API for an implausible token and says NOT_FOUND', async () => {
    const f = vi.fn();
    const r = await fetchVerification('../x', { fetch: f as unknown as typeof fetch });
    expect(f).not.toHaveBeenCalled();
    expect(r.kind === 'ok' && r.data.result).toBe('NOT_FOUND');
  });
  it.each([
    ['network error', () => Promise.reject(new Error('boom'))],
    ['429', () => Promise.resolve(json(429, {}))],
    ['500', () => Promise.resolve(json(500, {}))],
    ['404', () => Promise.resolve(json(404, {}))],
    ['bad JSON', () => Promise.resolve(new Response('<html>', { status: 200 }))],
    ['unknown result', () => Promise.resolve(json(200, { result: 'FINE' }))],
  ])('%s -> unavailable, never VERIFIED', async (_n, impl) => {
    const f = vi.fn(impl);
    expect(await fetchVerification(TOKEN, { fetch: f as unknown as typeof fetch })).toEqual({ kind: 'unavailable' });
  });
});
