// Upload sniffing and metadata stripping for logos (and later photos). The client's mime type and file
// name are never trusted: the type comes from magic bytes, the bytes are re-walked structurally, and
// metadata segments (EXIF, XMP, text, comments, timestamps) are dropped. Pixel data is copied untouched.
// Malformed structure is rejected rather than passed through.

export type ImageType = 'image/png' | 'image/jpeg';

const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

export const sniffImage = (b: Buffer): ImageType | null => {
  if (b.length >= 8 && b.subarray(0, 8).equals(PNG_SIG)) return 'image/png';
  if (b.length >= 4 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg';
  return null;
};

export const extensionOf = (t: ImageType): string => (t === 'image/png' ? 'png' : 'jpg');

const PNG_DROP = new Set(['eXIf', 'tEXt', 'zTXt', 'iTXt', 'tIME']);

function stripPng(b: Buffer): Buffer | null {
  const out: Buffer[] = [PNG_SIG];
  let off = 8;
  let first = true;
  let sawIdat = false;
  while (off < b.length) {
    if (off + 12 > b.length) return null;
    const len = b.readUInt32BE(off);
    const type = b.toString('latin1', off + 4, off + 8);
    const end = off + 12 + len;
    if (end > b.length) return null;
    if (first && type !== 'IHDR') return null;
    first = false;
    if (type === 'IDAT') sawIdat = true;
    if (!PNG_DROP.has(type)) out.push(b.subarray(off, end));
    off = end;
    if (type === 'IEND') {
      return sawIdat && off === b.length ? Buffer.concat(out) : null;
    }
  }
  return null;
}

function stripJpeg(b: Buffer): Buffer | null {
  const out: Buffer[] = [b.subarray(0, 2)];
  let off = 2;
  while (off < b.length) {
    if (b[off] !== 0xff) return null;
    const marker = b[off + 1];
    if (marker === undefined) return null;
    if (marker === 0xff) {
      off += 1; // fill byte
      continue;
    }
    if (marker === 0xd9) return null; // EOI before any scan
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd8)) return null; // standalone: not valid pre-scan
    if (off + 4 > b.length) return null;
    const len = b.readUInt16BE(off + 2);
    if (len < 2 || off + 2 + len > b.length) return null;
    const seg = b.subarray(off, off + 2 + len);
    if (marker === 0xda) {
      // Start of scan: entropy-coded data follows to the end of the file, copied verbatim.
      out.push(b.subarray(off));
      return Buffer.concat(out);
    }
    const isApp = marker >= 0xe0 && marker <= 0xef;
    const keep =
      marker === 0xe0 || // JFIF
      (marker === 0xe2 && seg.toString('latin1', 4, 16) === 'ICC_PROFILE') || // colour profile
      (marker === 0xee && seg.toString('latin1', 4, 9) === 'Adobe') || // colour transform flag
      (!isApp && marker !== 0xfe); // frame, tables; comments dropped
    if (keep) out.push(seg);
    off += 2 + len;
  }
  return null;
}

/** Returns the sanitised bytes, or null if the structure is not a well-formed PNG/JPEG. */
export function stripMetadata(b: Buffer, type: ImageType): Buffer | null {
  return type === 'image/png' ? stripPng(b) : stripJpeg(b);
}
