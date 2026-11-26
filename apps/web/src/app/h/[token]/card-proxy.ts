import { isIP } from 'node:net';
import process from 'node:process';
import { CARD_MAX_BYTES, CARD_TYPES, cardMagicOk, parseSignedLocation, readCapped } from '../../../lib/holder';
import { isPlausibleToken, visitorIp } from '../../../lib/verify';

// Same-origin card proxy (ADR 0032). The API answers 302 to a 60 s signed storage URL, often on an internal or other
// origin the strict CSP and the browser cannot reach. This follows it server-side, checks the bytes and streams
// them as an attachment, so the holder token and the signed URL never reach browser history, a Referer or a log.

const fail = (status: number, extra: Record<string, string> = {}) =>
  new Response(null, { status, headers: { 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', ...extra } });

export async function cardProxy(req: Request, params: Promise<{ token: string }>, ext: 'png' | 'pdf'): Promise<Response> {
  const { token } = await params;
  if (!isPlausibleToken(token)) return fail(404);
  const base = (process.env.API_URL ?? 'http://localhost:4000').replace(/\/+$/, '');
  const clientIp = visitorIp(req.headers.get('x-forwarded-for'), process.env.WEB_TRUST_PROXY_HOPS);
  try {
    const api = await fetch(base + '/api/v1/holder/' + encodeURIComponent(token) + '/card.' + ext, {
      headers: { ...(clientIp && isIP(clientIp) !== 0 ? { 'X-Forwarded-For': clientIp } : {}) },
      cache: 'no-store',
      redirect: 'manual',
      referrerPolicy: 'no-referrer',
      signal: AbortSignal.timeout(8000),
    });
    if (api.status === 429) {
      const ra = api.headers.get('retry-after');
      return fail(429, { 'Retry-After': ra && /^\d{1,4}$/.test(ra) ? ra : '60' });
    }
    if (api.status === 404) {
      const ra = api.headers.get('retry-after');
      return fail(404, ra && /^\d{1,4}$/.test(ra) ? { 'Retry-After': ra } : {});
    }
    if (api.status !== 302 && api.status !== 303 && api.status !== 307) return fail(503);
    const url = parseSignedLocation(api.headers.get('location'), process.env.STORAGE_PUBLIC_ORIGIN);
    if (!url) return fail(503);

    const file = await fetch(url, { cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', signal: AbortSignal.timeout(15000) });
    if (!file.ok) return fail(503);
    const buf = await readCapped(file, CARD_MAX_BYTES);
    if (!buf || !cardMagicOk(buf, ext)) return fail(503);
    return new Response(buf, {
      status: 200,
      headers: {
        'Content-Type': CARD_TYPES[ext],
        'Content-Length': String(buf.byteLength),
        'Content-Disposition': `attachment; filename="credential-card.${ext}"`,
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': "default-src 'none'; sandbox",
        'Referrer-Policy': 'no-referrer',
      },
    });
  } catch {
    return fail(503);
  }
}
