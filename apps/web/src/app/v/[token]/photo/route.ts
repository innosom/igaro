import process from 'node:process';
import { fetchVerification, isPlausibleToken, photoMatchesSignedHash, visitorIp } from '../../../../lib/verify';

// Same-origin photo proxy (ADR 0026): the API returns a short-lived signed storage URL on another origin, which the
// strict CSP (img-src 'self') would block. The server re-checks the verification result, so the photo is shown only
// when the institution's public-field settings allow it, then streams the bytes with a locked-down content type.
export const dynamic = 'force-dynamic';

const MAX_BYTES = 2 * 1024 * 1024;
const TYPES = new Set(['image/png', 'image/jpeg', 'image/webp']);
const NOT_FOUND = () => new Response(null, { status: 404, headers: { 'Cache-Control': 'no-store' } });

/** Reads the body up to `max` bytes; returns null (and cancels the stream) if it is larger. */
async function readCapped(res: Response, max: number): Promise<Uint8Array<ArrayBuffer> | null> {
  if (!res.body) return null;
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(new ArrayBuffer(total));
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

export async function GET(req: Request, ctx: { params: Promise<{ token: string }> }): Promise<Response> {
  const { token } = await ctx.params;
  if (!isPlausibleToken(token)) return NOT_FOUND();
  const clientIp = visitorIp(req.headers.get('x-forwarded-for'), process.env.WEB_TRUST_PROXY_HOPS);
  const outcome = await fetchVerification(token, { apiUrl: process.env.API_URL, clientIp });
  if (outcome.kind !== 'ok') return NOT_FOUND();
  const d = outcome.data;
  if (d.result === 'NOT_FOUND' || d.result === 'VERIFICATION_FAILED') return NOT_FOUND();
  const raw = d.holder?.photoUrl;
  if (!raw) return NOT_FOUND();

  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return NOT_FOUND();
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return NOT_FOUND();

  try {
    const res = await fetch(url, { cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(8000) });
    const type = (res.headers.get('content-type') ?? '').split(';')[0]!.trim().toLowerCase();
    if (!res.ok || !TYPES.has(type)) return NOT_FOUND();
    const declared = Number(res.headers.get('content-length') ?? '0');
    if (declared > MAX_BYTES) return NOT_FOUND();
    const buf = await readCapped(res, MAX_BYTES);
    if (!buf || buf.byteLength === 0) return NOT_FOUND();
    // Fail closed: the bytes must be exactly the photo the institution signed.
    if (!photoMatchesSignedHash(buf, d.holder?.photoSha256 ?? null)) return NOT_FOUND();
    return new Response(buf, {
      status: 200,
      headers: {
        'Content-Type': type,
        'Content-Length': String(buf.byteLength),
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': "default-src 'none'; sandbox",
        'Referrer-Policy': 'no-referrer',
      },
    });
  } catch {
    return NOT_FOUND();
  }
}
