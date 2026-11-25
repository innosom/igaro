// Well-formed tiny PNG/JPEG fixtures (real CRCs, frame headers, EOI) for upload tests. Test use only.
import { crc32 } from 'node:zlib';

export const pngChunk = (type: string, data: Buffer): Buffer => {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'latin1'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
};

const IHDR = (() => {
  const d = Buffer.alloc(13);
  d.writeUInt32BE(4, 0);
  d.writeUInt32BE(4, 4);
  d[8] = 8;
  d[9] = 2;
  return pngChunk('IHDR', d);
})();

export const PNG = (extraIdat = 0, ...meta: [string, string][]): Buffer =>
  Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    IHDR,
    ...meta.map(([t, d]) => pngChunk(t, Buffer.from(d))),
    pngChunk('IDAT', Buffer.alloc(6 + extraIdat, 7)),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);

export const JPEG = (extra: Buffer = Buffer.alloc(0)): Buffer =>
  Buffer.concat([
    Buffer.from([0xff, 0xd8]),
    Buffer.from([0xff, 0xe0, 0x00, 0x07, 0x4a, 0x46, 0x49, 0x46, 0x00]), // junk APP0, not JFIF: dropped
    extra,
    Buffer.from([0xff, 0xc0, 0x00, 0x08, 0x08, 0x00, 0x08, 0x00, 0x08, 0x00]), // SOF0 8x8
    Buffer.from([0xff, 0xda, 0x00, 0x03, 0x00]),
    Buffer.from('scan'),
    Buffer.from([0xff, 0xd9]),
  ]);
