// Public verification page logic (T-036, ADR 0026). Pure functions, no React, so it is unit-tested.
// Never log a token or a response body from here.

import { createHash } from 'node:crypto';
import { isIP } from 'node:net';

export const RESULTS = [
  'VERIFIED',
  'VALID_WITH_WARNING',
  'SUSPENDED',
  'REVOKED',
  'SUPERSEDED',
  'EXPIRED',
  'NOT_FOUND',
  'VERIFICATION_FAILED',
] as const;
export type VerifyResult = (typeof RESULTS)[number];

export interface VerifyData {
  result: VerifyResult;
  warning: string | null;
  institution: {
    name: string;
    slug: string;
    cardTitle: string | null;
    primaryColor: string | null;
    secondaryColor: string | null;
  } | null;
  holder: {
    fullName: string;
    idNumber: string | null;
    attributes: Array<[string, string]>;
    /** Present only if the API returned one. Never rendered directly: shown through the same-origin photo route. */
    photoUrl: string | null;
    /** The SIGNED holder.photoSha256 (64 hex). The photo route refuses bytes that do not hash to it. */
    photoSha256: string | null;
  } | null;
  type: { code: string; name: string; kind: string } | null;
  status: string | null;
  issuedAt: string | null;
  expiresAt: string | null;
  supersededBy: string | null;
  proof: { signedBy: string; kid: string; anchorStatus: string } | null;
}

export type VerifyOutcome =
  | { kind: 'ok'; data: VerifyData }
  /** The check could not be completed. Never shown as VERIFIED. */
  | { kind: 'unavailable' };

/** Verification tokens are 128-bit base64url (22 chars); accept a generous shape and let the API decide. */
const TOKEN_RE = /^[A-Za-z0-9_-]{16,128}$/;
export function isPlausibleToken(t: unknown): t is string {
  return typeof t === 'string' && TOKEN_RE.test(t);
}

const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
export function isSafeSlug(s: unknown): s is string {
  return typeof s === 'string' && SLUG_RE.test(s);
}

export function blankData(result: 'NOT_FOUND' | 'VERIFICATION_FAILED'): VerifyData {
  return {
    result,
    warning: null,
    institution: null,
    holder: null,
    type: null,
    status: null,
    issuedAt: null,
    expiresAt: null,
    supersededBy: null,
    proof: null,
  };
}

const str = (v: unknown, max = 500): string | null =>
  typeof v === 'string' && v.length > 0 ? v.slice(0, max) : null;
const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/** Strictly parses the API body. Anything malformed returns null (the caller shows "cannot verify right now"). */
export function parseVerifyResponse(body: unknown): VerifyData | null {
  if (!isObj(body)) return null;
  const result = body.result;
  if (typeof result !== 'string' || !(RESULTS as readonly string[]).includes(result)) return null;
  // NOT_FOUND and VERIFICATION_FAILED reveal nothing from the row, whatever the body carries.
  if (result === 'NOT_FOUND' || result === 'VERIFICATION_FAILED') return blankData(result);

  const inst = body.institution;
  const holder = body.holder;
  if (!isObj(inst) || !isObj(holder)) return null;
  const name = str(inst.name, 200);
  const fullName = str(holder.fullName, 200);
  if (!name || !fullName) return null;
  const slug = str(inst.slug, 64);

  const attributes: Array<[string, string]> = [];
  if (isObj(holder.attributes)) {
    for (const [k, v] of Object.entries(holder.attributes).slice(0, 50)) {
      if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') {
        attributes.push([k.slice(0, 100), String(v).slice(0, 500)]);
      }
    }
  }
  const type = isObj(body.type) ? body.type : null;
  const proof = isObj(body.proof) ? body.proof : null;
  const supersededBy = isPlausibleToken(body.supersededBy) ? body.supersededBy : null;

  return {
    result: result as VerifyResult,
    warning: str(body.warning, 100),
    institution: {
      name,
      slug: isSafeSlug(slug) ? slug : '',
      cardTitle: str(inst.cardTitle, 200),
      primaryColor: str(inst.primaryColor, 20),
      secondaryColor: str(inst.secondaryColor, 20),
    },
    holder: {
      fullName,
      idNumber: str(holder.idNumber, 200),
      attributes,
      photoUrl: str(holder.photoUrl, 2048),
      photoSha256:
        typeof holder.photoSha256 === 'string' && /^[0-9a-f]{64}$/.test(holder.photoSha256) ? holder.photoSha256 : null,
    },
    type: type
      ? { code: str(type.code, 100) ?? '', name: str(type.name, 200) ?? '', kind: str(type.kind, 100) ?? '' }
      : null,
    status: str(body.status, 50),
    issuedAt: str(body.issuedAt, 40),
    expiresAt: str(body.expiresAt, 40),
    supersededBy,
    proof: proof
      ? {
          signedBy: str(proof.signedBy, 200) ?? name,
          kid: str(proof.kid, 200) ?? '',
          anchorStatus: str(proof.anchorStatus, 50) ?? 'NOT_ANCHORED',
        }
      : null,
  };
}

export interface FetchDeps {
  fetch?: typeof fetch;
  apiUrl?: string;
  /** Validated visitor IP, forwarded to the API as a single-value X-Forwarded-For. Omit if not derivable. */
  clientIp?: string | null;
}

/** True only if the bytes hash to the signed photo hash (lowercase hex SHA-256). */
export function photoMatchesSignedHash(bytes: Uint8Array, signedSha256: string | null): boolean {
  if (!signedSha256 || !/^[0-9a-f]{64}$/.test(signedSha256)) return false;
  return createHash('sha256').update(bytes).digest('hex') === signedSha256;
}

/** WEB_TRUST_PROXY_HOPS: integer 0-10; anything else (unset, junk, out of range) is 0 = untrusted. */
export function parseTrustHops(v: string | undefined): number {
  if (typeof v !== 'string' || !/^\d{1,2}$/.test(v.trim())) return 0;
  const n = Number(v.trim());
  return n >= 0 && n <= 10 ? n : 0;
}

/**
 * Derives the visitor IP from X-Forwarded-For. With N >= 1 trusted hops, the Nth address from the right is the one
 * appended by our own ingress; entries to its left are client-controlled and ignored. Returns null when untrusted,
 * too short, or not a valid IP. The raw header is never passed through.
 */
export function clientIpFromXff(header: string | null | undefined, hops: number): string | null {
  if (!header || !Number.isInteger(hops) || hops < 1 || hops > 10) return null;
  const parts = header.split(',').map((p) => p.trim());
  const candidate = parts[parts.length - hops];
  if (!candidate || candidate.length > 45) return null;
  return isIP(candidate) !== 0 ? candidate : null;
}

/** Convenience for server code: derive from the request header and the WEB_TRUST_PROXY_HOPS env value. */
export function visitorIp(xff: string | null | undefined, hopsEnv: string | undefined): string | null {
  return clientIpFromXff(xff, parseTrustHops(hopsEnv));
}

/** Server-side fetch of the verification result. Any transport/HTTP/parse problem is `unavailable`, never a result. */
export async function fetchVerification(token: string, deps: FetchDeps = {}): Promise<VerifyOutcome> {
  if (!isPlausibleToken(token)) return { kind: 'ok', data: blankData('NOT_FOUND') };
  const base = (deps.apiUrl ?? 'http://localhost:4000').replace(/\/+$/, '');
  const doFetch = deps.fetch ?? globalThis.fetch.bind(globalThis);
  try {
    const res = await doFetch(base + '/api/v1/verify/' + encodeURIComponent(token), {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        // Re-validated here so no caller can pass through arbitrary header text.
        ...(deps.clientIp && isIP(deps.clientIp) !== 0 ? { 'X-Forwarded-For': deps.clientIp } : {}),
      },
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      redirect: 'error',
      signal: AbortSignal.timeout(8000),
    });
    if (res.status !== 200) return { kind: 'unavailable' };
    const data = parseVerifyResponse(await res.json());
    return data ? { kind: 'ok', data } : { kind: 'unavailable' };
  } catch {
    return { kind: 'unavailable' };
  }
}

// ---- Colours ----

export const DEFAULT_PRIMARY = '#1e3a8a';
export const DEFAULT_SECONDARY = '#475569';
const HEX6 = /^#[0-9a-fA-F]{6}$/;
const HEX3 = /^#[0-9a-fA-F]{3}$/;

/** Returns a lower-case `#rrggbb` or the fallback. The only colour values ever placed in CSS come through here. */
export function sanitizeHex(v: unknown, fallback: string): string {
  if (typeof v !== 'string') return fallback;
  const s = v.trim();
  if (HEX6.test(s)) return s.toLowerCase();
  if (HEX3.test(s)) {
    return ('#' + [...s.slice(1)].map((c) => c + c).join('')).toLowerCase();
  }
  return fallback;
}

function luminance(hex: string): number {
  const ch = [1, 3, 5].map((i) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * ch[0]! + 0.7152 * ch[1]! + 0.0722 * ch[2]!;
}
export function contrastRatio(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}
/** Black or white, whichever reads better on the background (one of them is always >= 4.5:1). */
export function readableOn(bg: string): '#000000' | '#ffffff' {
  return contrastRatio(bg, '#ffffff') >= contrastRatio(bg, '#000000') ? '#ffffff' : '#000000';
}

/** CSS custom properties for the institution brand. Inline style attributes are blocked by the CSP, so this goes in a nonce'd style tag. */
export function brandCss(inst: { primaryColor: string | null; secondaryColor: string | null } | null): string {
  const p = sanitizeHex(inst?.primaryColor, DEFAULT_PRIMARY);
  const s = sanitizeHex(inst?.secondaryColor, DEFAULT_SECONDARY);
  return `.brand{--brand:${p};--brand-fg:${readableOn(p)};--brand-accent:${s}}`;
}

// ---- Result presentation ----

export interface ResultView {
  label: string;
  icon: string;
  summary: string;
  /** Tailwind classes; fixed palette independent of institution colours. Text/background pairs meet AA. */
  classes: string;
  /** Show institution and credential details. */
  showDetails: boolean;
}

export const RESULT_VIEWS: Record<VerifyResult, ResultView> = {
  VERIFIED: {
    label: 'VERIFIED',
    icon: '✓',
    summary: 'This credential is authentic and in good standing.',
    classes: 'border-green-950 bg-green-800 text-white',
    showDetails: true,
  },
  VALID_WITH_WARNING: {
    label: 'VALID, WITH WARNING',
    icon: '⚠',
    summary: 'The signature is valid, but the issuing institution’s account is suspended on iGARO.',
    classes: 'border-amber-950 bg-amber-300 text-black',
    showDetails: true,
  },
  SUSPENDED: {
    label: 'SUSPENDED',
    icon: '⏸',
    summary: 'Temporarily suspended by the issuing institution. Do not rely on it for now.',
    classes: 'border-orange-950 bg-orange-200 text-black',
    showDetails: true,
  },
  REVOKED: {
    label: 'REVOKED',
    icon: '✕',
    summary: 'Revoked by the issuing institution. This is final.',
    classes: 'border-red-950 bg-red-800 text-white',
    showDetails: true,
  },
  SUPERSEDED: {
    label: 'SUPERSEDED',
    icon: '↻',
    summary: 'Replaced by a newer credential. This one is no longer current.',
    classes: 'border-indigo-950 bg-indigo-800 text-white',
    showDetails: true,
  },
  EXPIRED: {
    label: 'EXPIRED',
    icon: '⌛',
    summary: 'The validity period of this credential has ended.',
    classes: 'border-stone-950 bg-stone-300 text-black',
    showDetails: true,
  },
  NOT_FOUND: {
    label: 'NOT FOUND',
    icon: '?',
    summary: 'This credential does not exist in the iGARO registry. Check that you scanned the original QR code.',
    classes: 'border-slate-950 bg-slate-700 text-white',
    showDetails: false,
  },
  VERIFICATION_FAILED: {
    label: 'VERIFICATION FAILED',
    icon: '!',
    summary: 'The data does not match the institution’s signature. Do not trust this credential.',
    classes: 'border-red-950 bg-black text-white',
    showDetails: false,
  },
};

/** Shown when the check itself could not be completed. Deliberately not a verification result. */
export const UNAVAILABLE_VIEW = {
  label: 'CANNOT VERIFY RIGHT NOW',
  icon: '…',
  summary: 'We could not complete the check. This is not a verification result. Please try again in a moment.',
  classes: 'border-slate-950 bg-slate-200 text-black',
};

const WARNING_TEXT: Record<string, string> = {
  INSTITUTION_SUSPENDED:
    'The issuing institution is currently suspended on iGARO. The credential is correctly signed, but confirm with the institution before relying on it.',
};
export function warningText(code: string | null): string | null {
  if (!code) return null;
  return WARNING_TEXT[code] ?? 'Confirm this credential with the issuing institution before relying on it.';
}

export function formatDate(iso: string | null): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return d.toLocaleDateString('en-GB', { timeZone: 'UTC', day: 'numeric', month: 'long', year: 'numeric' });
}

// ---- Proof panel (data driven) ----

export interface ProofRow {
  id: string;
  label: string;
  value: string;
  detail?: string;
  /** Whether this proof is established. Shown as text as well as an icon. */
  ok: boolean;
}

/** Known anchor statuses. An unlisted status is still rendered (generic row), so a new one needs no restructure. */
export const ANCHOR_LABELS: Record<string, { value: string; ok: boolean }> = {
  NOT_ANCHORED: { value: 'Not anchored', ok: false },
};

function humanise(s: string): string {
  const t = s
    .replace(/[^A-Za-z0-9_ -]/g, '')
    .replace(/_/g, ' ')
    .trim()
    .toLowerCase();
  return t ? t.charAt(0).toUpperCase() + t.slice(1) : 'Unknown';
}

/** Turns the API proof object into display rows, one per proof type. Nothing here assumes a chain. */
export function buildProofRows(proof: VerifyData['proof']): ProofRow[] {
  if (!proof) return [];
  const known = ANCHOR_LABELS[proof.anchorStatus];
  return [
    {
      id: 'signature',
      label: 'Signature',
      value: 'Ed25519, signed by ' + proof.signedBy,
      detail: proof.kid ? 'Key ID: ' + proof.kid : undefined,
      ok: true,
    },
    {
      id: 'anchor',
      label: 'Blockchain',
      value: known ? known.value : humanise(proof.anchorStatus),
      ok: known ? known.ok : false,
    },
  ];
}
