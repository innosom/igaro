// Pure card HTML (T-039, ADR 0028). No I/O. Every dynamic value goes through esc() or a strict validator;
// images are data: URLs built from sniffed bytes; colours are re-emitted only if they are #rrggbb.
// The document carries a CSP that allows nothing but inline style and data: images, and the renderer also
// aborts every non-data request, so a template bug cannot reach the network.
import qrcode from 'qrcode-generator';

export type CardKind = 'ID_CARD' | 'CERTIFICATE';

export interface CardImage {
  mime: 'image/png' | 'image/jpeg' | 'image/webp';
  bytes: Buffer;
}

export interface CardModel {
  kind: CardKind;
  institutionName: string;
  cardTitle: string | null;
  primaryColor: string;
  secondaryColor: string;
  logo: CardImage | null;
  /** Only set after the SHA-256 of the stored bytes matched payload.holder.photoSha256. */
  photo: CardImage | null;
  holderName: string;
  idNumber: string | null;
  credentialTypeName: string;
  credentialNumber: string;
  issuedAt: string | null;
  expiresAt: string | null;
  attributes: Record<string, string>;
  /** Public verification URL: the ONLY content of the QR code. */
  verifyUrl: string;
}

export const CARD_CSP =
  "default-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'";

/** Page size in CSS px (96 dpi): CR80 card 85.6 x 54 mm and A4 landscape. */
export const CARD_SIZE: Record<CardKind, { width: number; height: number }> = {
  ID_CARD: { width: 856, height: 540 },
  CERTIFICATE: { width: 1123, height: 794 },
};

// Bidi controls, zero-width and other format characters can reorder or hide text on a card.
// Built from an escaped string so this source file holds no literal line-separator characters.
const UNSAFE_CHARS = new RegExp(
  // eslint-disable-next-line no-control-regex
  '[\\u0000-\\u0008\\u000b-\\u001f\\u007f-\\u009f\\u00ad\\u061c\\u180e\\u200b-\\u200f\\u2028-\\u202e\\u2060-\\u206f\\ufeff\\ufff9-\\ufffb]',
  'g',
);

export function esc(value: string): string {
  return value
    .replace(UNSAFE_CHARS, '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/`/g, '&#96;');
}

export function safeColor(value: string | null | undefined, fallback: string): string {
  if (typeof value === 'string') {
    const m = /^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/.exec(value.trim());
    if (m) {
      const h = m[1]!;
      return `#${(h.length === 3 ? [...h].map((c) => c + c).join('') : h).toLowerCase()}`;
    }
  }
  return fallback;
}

/** Black or white text for a background, by WCAG relative luminance. */
export function contrastText(hex: string): '#000000' | '#ffffff' {
  const lin = (v: number): number => {
    const c = v / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  const l = 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
  return l > 0.179 ? '#000000' : '#ffffff';
}

/** Identify an image by magic bytes (never by a stored name or type). */
export function sniffImage(bytes: Buffer): CardImage['mime'] | null {
  if (bytes.length >= 8 && bytes.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'image/png';
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return 'image/jpeg';
  if (bytes.length >= 12 && bytes.toString('latin1', 0, 4) === 'RIFF' && bytes.toString('latin1', 8, 12) === 'WEBP') return 'image/webp';
  return null;
}

function dataUrl(img: CardImage): string {
  return `data:${img.mime};base64,${img.bytes.toString('base64')}`;
}

const TOKEN_PATH = /^\/v\/[A-Za-z0-9_-]{16,128}$/;

/** The QR payload must be exactly an https (or http, dev) /v/<token> URL: no query, no fragment, no credentials. */
export function assertVerifyUrl(url: string): void {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new Error('invalid verify URL');
  }
  if ((u.protocol !== 'https:' && u.protocol !== 'http:') || u.username || u.password || u.search || u.hash || !TOKEN_PATH.test(u.pathname)) {
    throw new Error('invalid verify URL');
  }
}

/** QR as inline SVG (black modules on white, 4-module quiet zone). The only input is the verify URL. */
export function qrSvg(verifyUrl: string): string {
  assertVerifyUrl(verifyUrl);
  const qr = qrcode(0, 'M');
  qr.addData(verifyUrl, 'Byte');
  qr.make();
  const n = qr.getModuleCount();
  const q = 4;
  let d = '';
  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n; c++) {
      if (qr.isDark(r, c)) d += `M${c + q} ${r + q}h1v1h-1z`;
    }
  }
  const size = n + q * 2;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges" role="img" aria-label="QR code"><rect width="${size}" height="${size}" fill="#fff"/><path d="${d}" fill="#000"/></svg>`;
}

/** The module matrix, for tests that need to decode what the QR holds. */
export function qrMatrix(verifyUrl: string): boolean[][] {
  assertVerifyUrl(verifyUrl);
  const qr = qrcode(0, 'M');
  qr.addData(verifyUrl, 'Byte');
  qr.make();
  const n = qr.getModuleCount();
  return Array.from({ length: n }, (_, r) => Array.from({ length: n }, (_, c) => qr.isDark(r, c)));
}

function isoDate(v: string | null): string | null {
  return v && /^\d{4}-\d{2}-\d{2}/.test(v) ? v.slice(0, 10) : null;
}

export function renderCardHtml(m: CardModel): string {
  assertVerifyUrl(m.verifyUrl);
  const primary = safeColor(m.primaryColor, '#1d4ed8');
  const secondary = safeColor(m.secondaryColor, '#0f172a');
  const onPrimary = contrastText(primary);
  const { width, height } = CARD_SIZE[m.kind];
  const host = esc(new URL(m.verifyUrl).host);
  const title = esc(m.cardTitle?.trim() || m.credentialTypeName);
  const logo = m.logo ? `<img class="logo" alt="" src="${dataUrl(m.logo)}">` : '';
  const photo = m.photo
    ? `<img class="photo" alt="" src="${dataUrl(m.photo)}">`
    : `<div class="photo ph" aria-hidden="true"></div>`;
  const issued = isoDate(m.issuedAt);
  const expires = isoDate(m.expiresAt);
  const attrs = Object.entries(m.attributes)
    .slice(0, 8)
    .map(([k, v]) => `<div class="kv"><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></div>`)
    .join('');
  const common = `
<div class="kv"><span class="k">Credential no.</span><span class="v mono">${esc(m.credentialNumber)}</span></div>
${issued ? `<div class="kv"><span class="k">Issued</span><span class="v">${esc(issued)}</span></div>` : ''}
${expires ? `<div class="kv"><span class="k">Expires</span><span class="v">${esc(expires)}</span></div>` : ''}`;

  const body =
    m.kind === 'ID_CARD'
      ? `<div class="main">
  ${photo}
  <div class="info">
    <div class="name">${esc(m.holderName)}</div>
    ${m.idNumber ? `<div class="kv"><span class="k">ID</span><span class="v mono">${esc(m.idNumber)}</span></div>` : ''}
    ${common}
    ${attrs}
  </div>
  <div class="qr">${qrSvg(m.verifyUrl)}</div>
</div>`
      : `<div class="main cert">
  <div class="presented">This certifies that</div>
  <div class="name big">${esc(m.holderName)}</div>
  <div class="presented">${esc(m.credentialTypeName)}</div>
  <div class="row">
    ${photo}
    <div class="info">${m.idNumber ? `<div class="kv"><span class="k">ID</span><span class="v mono">${esc(m.idNumber)}</span></div>` : ''}${common}${attrs}</div>
    <div class="qr">${qrSvg(m.verifyUrl)}</div>
  </div>
</div>`;

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${CARD_CSP}">
<meta name="referrer" content="no-referrer">
<title>${esc(m.institutionName)}</title>
<style>
@page { size: ${width}px ${height}px; margin: 0; }
:root { --primary: ${primary}; --secondary: ${secondary}; --on-primary: ${onPrimary}; }
* { box-sizing: border-box; margin: 0; padding: 0; }
html, body { width: ${width}px; height: ${height}px; background: #fff; font-family: "DejaVu Sans", Arial, Helvetica, sans-serif; color: var(--secondary); }
.card { width: ${width}px; height: ${height}px; display: flex; flex-direction: column; border: 6px solid var(--primary); overflow: hidden; }
.head { background: var(--primary); color: var(--on-primary); display: flex; align-items: center; gap: 18px; padding: 16px 26px; }
.logo { max-height: 64px; max-width: 160px; object-fit: contain; background: #fff; border-radius: 6px; padding: 4px; }
.inst { font-size: 17px; opacity: .92; }
.title { font-size: 28px; font-weight: 700; }
.main { flex: 1; display: flex; align-items: center; gap: 28px; padding: 22px 26px; min-height: 0; }
.main.cert { flex-direction: column; justify-content: center; text-align: center; gap: 14px; }
.row { display: flex; align-items: center; gap: 28px; text-align: left; }
.photo { width: 170px; height: 215px; object-fit: cover; border: 3px solid var(--secondary); border-radius: 6px; flex: none; background: #e5e7eb; }
.info { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 6px; }
.name { font-size: 30px; font-weight: 700; overflow-wrap: anywhere; }
.name.big { font-size: 46px; }
.presented { font-size: 20px; color: #475569; }
.kv { display: flex; gap: 10px; font-size: 18px; }
.k { color: #475569; min-width: 130px; }
.v { font-weight: 600; overflow-wrap: anywhere; }
.mono { font-family: "DejaVu Sans Mono", monospace; }
.qr { width: 190px; height: 190px; flex: none; }
.qr svg { width: 100%; height: 100%; display: block; }
.foot { background: var(--secondary); color: ${contrastText(secondary)}; font-size: 16px; text-align: center; padding: 9px 16px; }
</style></head>
<body><div class="card">
<div class="head">${logo}<div><div class="inst">${esc(m.institutionName)}</div><div class="title">${title}</div></div></div>
${body}
<div class="foot">Verify only at ${host}</div>
</div></body></html>`;
}
