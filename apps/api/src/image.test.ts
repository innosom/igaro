import { crc32 } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { MAX_IMAGE_SIDE, sniffImage, stripMetadata } from './image.js';

const SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const chunk = (type: string, data: Buffer, badCrc = false) => {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'latin1'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE((crc32(body) ^ (badCrc ? 1 : 0)) >>> 0);
  return Buffer.concat([len, body, crc]);
};
const ihdr = (w = 4, h = 4) => {
  const d = Buffer.alloc(13);
  d.writeUInt32BE(w, 0);
  d.writeUInt32BE(h, 4);
  d[8] = 8;
  d[9] = 2;
  return chunk('IHDR', d);
};
const idat = chunk('IDAT', Buffer.from('pixels'));
const iend = chunk('IEND', Buffer.alloc(0));
const png = (...parts: Buffer[]) => Buffer.concat([SIG, ...parts]);
const strip = (b: Buffer) => stripMetadata(b, sniffImage(b)!);

describe('PNG cleaner (allow-list)', () => {
  it('keeps only allow-listed chunks and drops every other ancillary chunk', () => {
    const input = png(
      ihdr(),
      chunk('tEXt', Buffer.from('Author\0someone')),
      chunk('eXIf', Buffer.from('GPS')),
      chunk('tIME', Buffer.alloc(7)),
      chunk('iCCP', Buffer.from('x')),
      chunk('pHYs', Buffer.alloc(9)),
      chunk('prVt', Buffer.from('private')), // unknown ancillary
      chunk('gAMA', Buffer.alloc(4)),
      chunk('sRGB', Buffer.alloc(1)),
      idat,
      iend,
    );
    const out = strip(input)!;
    expect(out.equals(png(ihdr(), chunk('gAMA', Buffer.alloc(4)), chunk('sRGB', Buffer.alloc(1)), idat, iend))).toBe(true);
    expect(out.includes(Buffer.from('someone'))).toBe(false);
  });

  it('cuts anything after IEND', () => {
    const out = strip(png(ihdr(), idat, iend, Buffer.from('TRAILING-SECRET')))!;
    expect(out.equals(png(ihdr(), idat, iend))).toBe(true);
  });

  it('rejects a bad CRC, even on a chunk that would be dropped', () => {
    expect(strip(png(ihdr(), idat, iend.subarray(0, 8), Buffer.alloc(4)))).toBeNull();
    expect(strip(png(ihdr(), chunk('tEXt', Buffer.from('a'), true), idat, iend))).toBeNull();
    expect(strip(png(ihdr(), chunk('IDAT', Buffer.from('p'), true), iend))).toBeNull();
  });

  it('rejects oversized and zero dimensions', () => {
    expect(strip(png(ihdr(MAX_IMAGE_SIDE + 1, 1), idat, iend))).toBeNull();
    expect(strip(png(ihdr(1, MAX_IMAGE_SIDE + 1), idat, iend))).toBeNull();
    expect(strip(png(ihdr(9000, 9000), idat, iend))).toBeNull(); // 81M pixels
    expect(strip(png(ihdr(0, 5), idat, iend))).toBeNull();
    expect(strip(png(ihdr(MAX_IMAGE_SIDE, 100), idat, iend))).not.toBeNull();
  });

  it('rejects structural problems', () => {
    expect(strip(png(idat, iend))).toBeNull(); // no IHDR first
    expect(strip(png(ihdr(), iend))).toBeNull(); // no IDAT
    expect(strip(png(ihdr(), idat))).toBeNull(); // no IEND
    expect(strip(png(ihdr(), idat, chunk('tEXt', Buffer.from('a')), idat, iend))).toBeNull(); // split IDAT
    expect(strip(png(ihdr(), chunk('ZZZZ', Buffer.alloc(1)), idat, iend))).toBeNull(); // unknown critical
    expect(strip(png(ihdr(), ihdr(), idat, iend))).toBeNull();
    expect(strip(png(ihdr(), idat, chunk('IEND', Buffer.from('x'))))).toBeNull();
  });
});

const seg = (marker: number, data: Buffer) => {
  const len = Buffer.alloc(2);
  len.writeUInt16BE(data.length + 2);
  return Buffer.concat([Buffer.from([0xff, marker]), len, data]);
};
const SOI = Buffer.from([0xff, 0xd8]);
const EOI = Buffer.from([0xff, 0xd9]);
const sof = (w = 8, h = 8) => {
  const d = Buffer.alloc(6);
  d[0] = 8;
  d.writeUInt16BE(h, 1);
  d.writeUInt16BE(w, 3);
  d[5] = 0;
  return seg(0xc0, d);
};
const sos = seg(0xda, Buffer.from([0x00]));
const exif = seg(0xe1, Buffer.from('Exif\0\0GPS-LOCATION'));
const jpeg = (...parts: Buffer[]) => Buffer.concat([SOI, ...parts]);

describe('JPEG cleaner', () => {
  it('drops EXIF/XMP/comments before the scan and keeps tables and frame header', () => {
    const dqt = seg(0xdb, Buffer.alloc(65));
    const input = jpeg(exif, seg(0xe1, Buffer.from('http://ns.adobe.com/xap/1.0/\0xmp')), seg(0xfe, Buffer.from('hi')), dqt, sof(), sos, Buffer.from('scandata'), EOI);
    const out = strip(input)!;
    expect(out.equals(jpeg(dqt, sof(), sos, Buffer.from('scandata'), EOI))).toBe(true);
  });

  it('strips metadata that appears between scans (progressive JPEG)', () => {
    const dht = seg(0xc4, Buffer.alloc(17));
    const input = jpeg(sof(), sos, Buffer.from('scan1'), exif, seg(0xfe, Buffer.from('c')), dht, sos, Buffer.from('scan2'), EOI);
    const out = strip(input)!;
    expect(out.equals(jpeg(sof(), sos, Buffer.from('scan1'), dht, sos, Buffer.from('scan2'), EOI))).toBe(true);
    expect(out.includes(Buffer.from('GPS-LOCATION'))).toBe(false);
  });

  it('cuts everything after EOI', () => {
    const out = strip(jpeg(sof(), sos, Buffer.from('s'), EOI, exif, Buffer.from('PK\x03\x04hidden')))!;
    expect(out.equals(jpeg(sof(), sos, Buffer.from('s'), EOI))).toBe(true);
  });

  it('keeps stuffed bytes and restart markers inside scan data', () => {
    const data = Buffer.from([0x01, 0xff, 0x00, 0x02, 0xff, 0xd0, 0x03]);
    const out = strip(jpeg(sof(), sos, data, EOI))!;
    expect(out.equals(jpeg(sof(), sos, data, EOI))).toBe(true);
  });

  it('keeps ICC and Adobe, drops the JFIF thumbnail and non-JFIF APP0', () => {
    const icc = seg(0xe2, Buffer.concat([Buffer.from('ICC_PROFILE\0'), Buffer.alloc(8)]));
    const adobe = seg(0xee, Buffer.from('Adobe\0\0\0\0\0\0\0'));
    const jfif = seg(0xe0, Buffer.concat([Buffer.from('JFIF\0'), Buffer.from([1, 1, 0, 0, 1, 0, 1, 2, 2]), Buffer.alloc(12, 9)]));
    const jfxx = seg(0xe0, Buffer.from('JFXX\0thumb'));
    const out = strip(jpeg(jfif, jfxx, icc, adobe, sof(), sos, Buffer.from('s'), EOI))!;
    const cleanJfif = seg(0xe0, Buffer.concat([Buffer.from('JFIF\0'), Buffer.from([1, 1, 0, 0, 1, 0, 1, 0, 0])]));
    expect(out.equals(jpeg(cleanJfif, icc, adobe, sof(), sos, Buffer.from('s'), EOI))).toBe(true);
  });

  it('rejects missing EOI, missing frame header, oversized dimensions and truncation', () => {
    expect(strip(jpeg(sof(), sos, Buffer.from('s')))).toBeNull(); // no EOI
    expect(strip(jpeg(sos, Buffer.from('s'), EOI))).toBeNull(); // scan before SOF
    expect(strip(jpeg(sof(), EOI))).toBeNull(); // no scan
    expect(strip(jpeg(sof(MAX_IMAGE_SIDE + 1, 10), sos, Buffer.from('s'), EOI))).toBeNull();
    expect(strip(jpeg(sof(9000, 9000), sos, Buffer.from('s'), EOI))).toBeNull();
    expect(strip(jpeg(sof(0, 10), sos, Buffer.from('s'), EOI))).toBeNull();
    expect(strip(jpeg(sof(), sof(), sos, Buffer.from('s'), EOI))).toBeNull();
    expect(strip(Buffer.concat([jpeg(sof()), Buffer.from([0xff, 0xda, 0x00])]))).toBeNull();
  });
});
