import { describe, expect, it, vi } from 'vitest';
import { takeTokenFromUrl } from './token-url';
import { buildCsp } from './csp';

// Same format as buildLink in apps/worker/src/account-mail.ts: `${base}${path}#token=${token}`.
const link = (path: string, token: string) => new URL(`https://web.example${path}#token=${token}`);

describe('takeTokenFromUrl', () => {
  it('reads the token from the fragment of the worker link and clears it', () => {
    const replaceState = vi.fn();
    const url = link('/invite/accept', 'abc_DEF-1xyz');
    expect(takeTokenFromUrl(url, { replaceState })).toBe('abc_DEF-1xyz');
    expect(replaceState).toHaveBeenCalledWith(null, '', '/invite/accept');
  });

  it('works for the password-reset link and keeps the query string', () => {
    const replaceState = vi.fn();
    const url = new URL('https://web.example/password-reset?a=1#token=T0k_en');
    expect(takeTokenFromUrl(url, { replaceState })).toBe('T0k_en');
    expect(replaceState).toHaveBeenCalledWith(null, '', '/password-reset?a=1');
  });

  it('ignores a ?token= query string', () => {
    const replaceState = vi.fn();
    const url = new URL('https://web.example/invite/accept?token=abc');
    expect(takeTokenFromUrl(url, { replaceState })).toBeNull();
    expect(replaceState).not.toHaveBeenCalled();
  });

  it('returns null and leaves history alone with no fragment or another fragment', () => {
    const replaceState = vi.fn();
    expect(takeTokenFromUrl(new URL('https://web.example/p'), { replaceState })).toBeNull();
    expect(takeTokenFromUrl(new URL('https://web.example/p#section'), { replaceState })).toBeNull();
    expect(replaceState).not.toHaveBeenCalled();
  });

  it('treats an empty token as missing but still clears the fragment', () => {
    const replaceState = vi.fn();
    expect(takeTokenFromUrl(link('/p', ''), { replaceState })).toBeNull();
    expect(replaceState).toHaveBeenCalledWith(null, '', '/p');
  });
});

describe('buildCsp', () => {
  it('is strict in production', () => {
    const csp = buildCsp('N0NCE');
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("'nonce-N0NCE'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain('unsafe-inline');
    expect(csp).not.toContain('unsafe-eval');
  });
  it('allows eval only in dev', () => {
    expect(buildCsp('n', true)).toContain("'unsafe-eval'");
  });
});
