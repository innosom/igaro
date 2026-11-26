// Loading credential.json and keys.json from local files or public URLs. The only network requests the verifier ever makes are
// plain GETs of these two public documents; it never calls the iGARO verify API (`/verify/:token`).
// A credential.json URL contains the verification token, so URLs are never echoed: messages name only the origin.
import { readFile as fsReadFile } from 'node:fs/promises';

/** Upper bound on any document read, local or remote (a real credential file is a few KB). */
export const MAX_DOCUMENT_BYTES = 1024 * 1024;
export const FETCH_TIMEOUT_MS = 10_000;

/** An input problem (missing file, bad URL, network error): exit code 3, not a verification verdict. */
export class InputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InputError';
  }
}

/** The remote credential document does not exist (HTTP 404): invariant 7 step 1, NOT FOUND. */
export class NotFoundError extends Error {
  constructor() {
    super('credential not found');
    this.name = 'NotFoundError';
  }
}

export interface SourceDeps {
  fetch?: typeof fetch;
  readFile?: (path: string) => Promise<Buffer>;
}

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);

export function isUrlArg(arg: string): boolean {
  return /^https?:\/\//i.test(arg);
}

/** Parse and restrict a URL: https anywhere, http only to loopback (local development). No credentials in the URL. */
export function parseSafeUrl(raw: string, what: string): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new InputError(`${what}: not a valid URL`);
  }
  if (u.username || u.password) throw new InputError(`${what}: URLs with embedded credentials are not allowed`);
  if (u.protocol === 'https:') return u;
  if (u.protocol === 'http:' && LOOPBACK.has(u.hostname)) return u;
  throw new InputError(`${what}: only https URLs are allowed (http only for localhost)`);
}

/** Where a document came from, safe to print (never the full credential URL, which carries the verification token). */
export function describeSource(src: string, isCredential: boolean): string {
  if (!isUrlArg(src)) return src;
  try {
    const u = new URL(src);
    return isCredential ? `${u.origin} (remote credential file)` : `${u.origin}${u.pathname}`;
  } catch {
    return '(invalid URL)';
  }
}

async function readLimitedBody(res: Response, what: string): Promise<string> {
  const declared = Number(res.headers.get('content-length') ?? '0');
  if (declared > MAX_DOCUMENT_BYTES) throw new InputError(`${what}: response too large`);
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_DOCUMENT_BYTES) {
      await reader.cancel();
      throw new InputError(`${what}: response too large`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/** Read a document as text from a local path or a public URL. */
export async function loadText(src: string, what: string, isCredential: boolean, deps: SourceDeps = {}): Promise<string> {
  if (isUrlArg(src)) {
    const url = parseSafeUrl(src, what);
    const doFetch = deps.fetch ?? globalThis.fetch;
    let res: Response;
    try {
      res = await doFetch(url, {
        method: 'GET',
        headers: { accept: 'application/json' },
        redirect: 'error', // never follow a redirect elsewhere with a token-bearing URL
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
    } catch {
      // Deliberately generic: fetch errors can embed the URL.
      throw new InputError(`${what}: could not fetch from ${url.origin}`);
    }
    if (res.status === 404 && isCredential) throw new NotFoundError();
    if (!res.ok) throw new InputError(`${what}: ${url.origin} answered HTTP ${res.status}`);
    return readLimitedBody(res, what);
  }
  const doRead = deps.readFile ?? ((p: string) => fsReadFile(p));
  let buf: Buffer;
  try {
    buf = await doRead(src);
  } catch {
    throw new InputError(`${what}: cannot read file ${src}`);
  }
  if (buf.byteLength > MAX_DOCUMENT_BYTES) throw new InputError(`${what}: file too large`);
  return buf.toString('utf8');
}

/** JSON.parse that returns `undefined` instead of throwing (a malformed credential file fails verification). */
export function tryParseJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

/**
 * Resolve the keys URL advertised by a remote credential file (`publicKeysUrl`, site-relative `/i/<slug>/keys.json`) against the
 * credential's own origin. Only a same-origin `/i/<slug>/keys.json` path is accepted, so a file cannot point the verifier at an
 * arbitrary host.
 */
export function resolvePublishedKeysUrl(credentialUrl: string, publicKeysUrl: unknown): string {
  if (typeof publicKeysUrl !== 'string' || !/^\/i\/[a-z0-9-]{3,40}\/keys\.json$/.test(publicKeysUrl)) {
    throw new InputError('credential file has no usable publicKeysUrl; pass --keys or --keys-url');
  }
  const base = parseSafeUrl(credentialUrl, 'credential');
  return new URL(publicKeysUrl, base.origin).toString();
}
