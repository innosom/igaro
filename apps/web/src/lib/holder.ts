// Private holder page logic (T-042, ADR 0023, ADR 0031). Pure functions, no React, so it is unit-tested.
// The holder token is the holder's only credential: never log it, never put it in a link to another origin.

import { isIP } from 'node:net';
import { isPlausibleToken, isSafeSlug } from './verify';

export interface HolderData {
  holderName: string;
  institution: {
    name: string;
    slug: string;
    cardTitle: string | null;
    primaryColor: string | null;
    secondaryColor: string | null;
  };
  credential: {
    verificationToken: string;
    type: { code: string; name: string; kind: string };
    status: string;
    issuedAt: string | null;
    expiresAt: string | null;
    /** Whether the API offers each card download. The hrefs themselves are built here from the page token. */
    hasCardPng: boolean;
    hasCardPdf: boolean;
  };
}

export type HolderOutcome =
  | { kind: 'ok'; data: HolderData }
  | { kind: 'not_found' }
  /** Transport error, rate limit, 5xx or an unparseable body. Not the same as "unknown link". */
  | { kind: 'unavailable' };

const str = (v: unknown, max = 500): string | null =>
  typeof v === 'string' && v.length > 0 ? v.slice(0, max) : null;
const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/** Strict parse of GET /holder/:token. Anything malformed returns null. */
export function parseHolderResponse(body: unknown): HolderData | null {
  if (!isObj(body) || !isObj(body.holder) || !isObj(body.institution)) return null;
  const fullName = str(body.holder.fullName, 200);
  const name = str(body.institution.name, 200);
  if (!fullName || !name) return null;
  if (!Array.isArray(body.credentials)) return null;
  const c = body.credentials[0];
  if (!isObj(c) || !isObj(c.type)) return null;
  const vt = c.verificationToken;
  const status = str(c.status, 50);
  if (!isPlausibleToken(vt) || !status) return null;
  const links = isObj(c.links) ? c.links : {};
  const slug = str(body.institution.slug, 64);
  return {
    holderName: fullName,
    institution: {
      name,
      slug: isSafeSlug(slug) ? slug : '',
      cardTitle: str(body.institution.cardTitle, 200),
      primaryColor: str(body.institution.primaryColor, 20),
      secondaryColor: str(body.institution.secondaryColor, 20),
    },
    credential: {
      verificationToken: vt,
      type: { code: str(c.type.code, 100) ?? '', name: str(c.type.name, 200) ?? '', kind: str(c.type.kind, 100) ?? '' },
      status,
      issuedAt: str(c.issuedAt, 40),
      expiresAt: str(c.expiresAt, 40),
      hasCardPng: typeof links.card === 'string' && links.card.length > 0,
      hasCardPdf: typeof links.cardPdf === 'string' && links.cardPdf.length > 0,
    },
  };
}

export interface HolderFetchDeps {
  fetch?: typeof fetch;
  apiUrl?: string;
  clientIp?: string | null;
}

export async function fetchHolder(token: string, deps: HolderFetchDeps = {}): Promise<HolderOutcome> {
  if (!isPlausibleToken(token)) return { kind: 'not_found' };
  const base = (deps.apiUrl ?? 'http://localhost:4000').replace(/\/+$/, '');
  const doFetch = deps.fetch ?? globalThis.fetch.bind(globalThis);
  try {
    const res = await doFetch(base + '/api/v1/holder/' + encodeURIComponent(token), {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        ...(deps.clientIp && isIP(deps.clientIp) !== 0 ? { 'X-Forwarded-For': deps.clientIp } : {}),
      },
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      redirect: 'error',
      signal: AbortSignal.timeout(8000),
    });
    if (res.status === 404) return { kind: 'not_found' };
    if (res.status !== 200) return { kind: 'unavailable' };
    const data = parseHolderResponse(await res.json());
    return data ? { kind: 'ok', data } : { kind: 'unavailable' };
  } catch {
    return { kind: 'unavailable' };
  }
}

/** Same-origin hrefs. Built from the validated page token, never copied from the API response. */
export function holderCardHref(token: string, ext: 'png' | 'pdf'): string | null {
  return isPlausibleToken(token) ? '/h/' + encodeURIComponent(token) + '/card.' + ext : null;
}
export function credentialFileHref(verificationToken: string): string | null {
  return isPlausibleToken(verificationToken)
    ? '/api/v1/verify/' + encodeURIComponent(verificationToken) + '/credential.json'
    : null;
}

const STATUS_TEXT: Record<string, { label: string; note: string }> = {
  ACTIVE: { label: 'Active', note: 'This credential is in good standing.' },
  SUSPENDED: { label: 'Suspended', note: 'The institution has suspended this credential for now. The card cannot be downloaded.' },
  REVOKED: { label: 'Revoked', note: 'The institution has revoked this credential. This is final.' },
  SUPERSEDED: { label: 'Replaced', note: 'A newer credential replaced this one. Ask the institution for the new link.' },
  EXPIRED: { label: 'Expired', note: 'The validity period of this credential has ended.' },
};
export function statusText(status: string): { label: string; note: string } {
  return STATUS_TEXT[status] ?? { label: 'Unknown', note: 'Contact the institution about this credential.' };
}

// ---- Card download proxy ----

export const CARD_TYPES = { png: 'image/png', pdf: 'application/pdf' } as const;
export const CARD_MAX_BYTES = 8 * 1024 * 1024;

/**
 * The signed storage URL from the API's 302 is followed only when its origin equals the configured
 * STORAGE_PUBLIC_ORIGIN exactly (scheme, host, port). Unset, invalid or mismatched returns null (the proxy answers 503),
 * so a tampered Location can never make the web server fetch an arbitrary host (SSRF).
 */
export function parseSignedLocation(loc: string | null, allowedOrigin: string | undefined): URL | null {
  if (!loc || !allowedOrigin) return null;
  try {
    const allowed = new URL(allowedOrigin);
    if (allowed.protocol !== 'https:' && allowed.protocol !== 'http:') return null;
    const u = new URL(loc);
    return u.origin === allowed.origin ? u : null;
  } catch {
    return null;
  }
}

/**
 * Reads a body with a running byte count and aborts past maxBytes. Returns null when over the cap or empty, or when
 * Content-Length is present but not a plain non-negative integer or exceeds the cap.
 */
export async function readCapped(res: Response, maxBytes: number): Promise<Uint8Array<ArrayBuffer> | null> {
  const cl = res.headers.get('content-length');
  if (cl !== null && (!/^\d{1,12}$/.test(cl) || Number(cl) > maxBytes)) {
    await res.body?.cancel().catch(() => undefined);
    return null;
  }
  if (!res.body) return null;
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      return null;
    }
    chunks.push(value);
  }
  if (total === 0) return null;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

/** True when the leading bytes match the expected card file type (magic bytes, not just the header). */
export function cardMagicOk(bytes: Uint8Array, ext: 'png' | 'pdf'): boolean {
  const starts = (sig: number[]) => sig.every((b, i) => bytes[i] === b);
  return ext === 'png' ? starts([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) : starts([0x25, 0x50, 0x44, 0x46, 0x2d]);
}
