// JPEG sniffing and metadata stripping for imported photos (T-044, ADR 0034). Copy of the JPEG half of
// apps/api/src/image.ts (the worker may not import the API). The API re-walks the bytes it receives and refuses any
// photo for which stripping is not a no-op, so a divergence between the copies fails closed.
//
// Everything outside a small allow-list is dropped (EXIF, XMP, comments, timestamps, thumbnails, trailing data after EOI).
// Pixel data is copied untouched. Malformed structure and oversized dimensions are rejected.

export const MAX_IMAGE_SIDE = 10_000;
export const MAX_IMAGE_PIXELS = 40_000_000;

const dimsOk = (w: number, h: number): boolean =>
  w > 0 && h > 0 && w <= MAX_IMAGE_SIDE && h <= MAX_IMAGE_SIDE && w * h <= MAX_IMAGE_PIXELS;

export const isJpeg = (b: Buffer): boolean => b.length >= 4 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff;

const isSof = (m: number): boolean => m >= 0xc0 && m <= 0xcf && m !== 0xc4 && m !== 0xc8 && m !== 0xcc;

/** Returns the sanitised bytes, or null if the structure is not a well-formed JPEG. */
export function stripJpeg(b: Buffer): Buffer | null {
  if (!isJpeg(b)) return null;
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
