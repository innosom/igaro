// Upload sniffing and metadata stripping for logos and holder photos. The client's mime type and file name
// are never trusted: the type comes from magic bytes, the bytes are re-walked structurally, and everything
// outside a small allow-list is dropped (EXIF, XMP, text, comments, timestamps, thumbnails, trailing data).
// Pixel data is copied untouched. Malformed structure, bad PNG CRCs and oversized dimensions are rejected
// rather than passed through.
import { crc32 } from 'node:zlib';

export type ImageType = 'image/png' | 'image/jpeg';

const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

export const sniffImage = (b: Buffer): ImageType | null => {
  if (b.length >= 8 && b.subarray(0, 8).equals(PNG_SIG)) return 'image/png';
  if (b.length >= 4 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg';
  return null;
};

export const extensionOf = (t: ImageType): string => (t === 'image/png' ? 'png' : 'jpg');

/** Per-side and total pixel caps, read from the header before anything is stored (decompression bombs). */
export const MAX_IMAGE_SIDE = 10_000;
export const MAX_IMAGE_PIXELS = 40_000_000;

const dimsOk = (w: number, h: number): boolean =>
  w > 0 && h > 0 && w <= MAX_IMAGE_SIDE && h <= MAX_IMAGE_SIDE && w * h <= MAX_IMAGE_PIXELS;

// PNG allow-list: critical chunks plus two tiny colour-rendering chunks. Everything else is dropped
// (text, EXIF, time, iCCP, pHYs, private chunks). An unknown CRITICAL chunk cannot be dropped safely: reject.
const PNG_KEEP = new Set(['PLTE', 'tRNS', 'gAMA', 'sRGB']);

function stripPng(b: Buffer): Buffer | null {
  const out: Buffer[] = [PNG_SIG];
  let off = 8;
  let first = true;
  let sawIdat = false;
  let idatDone = false;
  while (off < b.length) {
    if (off + 12 > b.length) return null;
    const len = b.readUInt32BE(off);
    if (len > 0x7fffffff) return null;
    const type = b.toString('latin1', off + 4, off + 8);
    const end = off + 12 + len;
    if (end > b.length) return null;
    if (b.readUInt32BE(end - 4) !== crc32(b.subarray(off + 4, end - 4))) return null;
    if (first && type !== 'IHDR') return null;
    if (type === 'IHDR') {
      if (!first || len !== 13) return null;
      if (!dimsOk(b.readUInt32BE(off + 8), b.readUInt32BE(off + 12))) return null;
    }
    first = false;
    if (type === 'IDAT') {
      if (idatDone) return null; // IDAT chunks must be contiguous
      sawIdat = true;
      out.push(b.subarray(off, end));
    } else {
      if (sawIdat) idatDone = true;
      if (type === 'IEND') {
        if (len !== 0 || !sawIdat) return null;
        out.push(b.subarray(off, end));
        return Buffer.concat(out); // anything after IEND is cut
      }
      if (type === 'IHDR') out.push(b.subarray(off, end));
      else if (PNG_KEEP.has(type)) {
        // Colour chunks after the image data are invalid and are dropped rather than carried over.
        if (!sawIdat) out.push(b.subarray(off, end));
      } else if (!(type.charCodeAt(0) & 0x20)) {
        return null; // unknown critical chunk
      }
    }
    off = end;
  }
  return null; // no IEND
}

const isSof = (m: number): boolean => m >= 0xc0 && m <= 0xcf && m !== 0xc4 && m !== 0xc8 && m !== 0xcc;

function stripJpeg(b: Buffer): Buffer | null {
  const out: Buffer[] = [b.subarray(0, 2)];
  let off = 2;
  let sawSof = false;
  let scans = 0;
  while (off < b.length) {
    if (b[off] !== 0xff) return null;
    const marker = b[off + 1];
    if (marker === undefined) return null;
    if (marker === 0xff) {
      off += 1; // fill byte
      continue;
    }
    if (marker === 0xd9) {
      // EOI: finish here. Whatever follows (trailers, appended archives, a second image) is cut.
      if (!sawSof || scans === 0) return null;
      out.push(Buffer.from([0xff, 0xd9]));
      return Buffer.concat(out);
    }
    if (marker === 0x00 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd8)) return null;
    if (off + 4 > b.length) return null;
    const len = b.readUInt16BE(off + 2);
    if (len < 2 || off + 2 + len > b.length) return null;
    const seg = b.subarray(off, off + 2 + len);
    const next = off + 2 + len;
    if (isSof(marker)) {
      if (sawSof || len < 8) return null;
      if (!dimsOk(seg.readUInt16BE(7), seg.readUInt16BE(5))) return null;
      sawSof = true;
      out.push(seg);
      off = next;
      continue;
    }
    if (marker === 0xda) {
      if (!sawSof) return null;
      scans += 1;
      out.push(seg);
      // Entropy-coded data runs until the next real marker: FF00 is a stuffed byte, FFD0-FFD7 are restarts.
      let p = next;
      for (;;) {
        if (p >= b.length) return null;
        if (b[p] !== 0xff) {
          p += 1;
          continue;
        }
        const m = b[p + 1];
        if (m === undefined) return null;
        if (m === 0x00 || (m >= 0xd0 && m <= 0xd7)) {
          p += 2;
          continue;
        }
        if (m === 0xff) {
          p += 1;
          continue;
        }
        break;
      }
      out.push(b.subarray(next, p));
      off = p;
      continue;
    }
    // Headers between (and before) scans pass through the same filter, so metadata cannot hide after a scan.
    const isApp = marker >= 0xe0 && marker <= 0xef;
    if (marker === 0xe0 && len >= 16 && seg.toString('latin1', 4, 9) === 'JFIF\0') {
      // Keep the 16-byte JFIF header only, with the embedded thumbnail dropped.
      const jfif = Buffer.from(seg.subarray(0, 18));
      jfif.writeUInt16BE(16, 2);
      jfif[16] = 0;
      jfif[17] = 0;
      out.push(jfif);
    } else if (marker === 0xe2 && seg.toString('latin1', 4, 15) === 'ICC_PROFILE') {
      out.push(seg); // colour profile
    } else if (marker === 0xee && seg.toString('latin1', 4, 9) === 'Adobe') {
      out.push(seg); // colour transform flag
    } else if (!isApp && marker !== 0xfe) {
      out.push(seg); // tables (DQT, DHT, DRI, DNL, ...); comments and other APPn are dropped
    }
    off = next;
  }
  return null; // no EOI
}

/** Returns the sanitised bytes, or null if the structure is not a well-formed PNG/JPEG. */
export function stripMetadata(b: Buffer, type: ImageType): Buffer | null {
  return type === 'image/png' ? stripPng(b) : stripJpeg(b);
}
