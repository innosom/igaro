// Well-formed tiny PNG/JPEG fixtures (real CRCs, frame headers, EOI) for import tests. Test use only.
import { crc32 } from 'node:zlib';

const pngChunk = (type: string, data: Buffer): Buffer => {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'latin1'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
};

export const PNG = (): Buffer => {
  const d = Buffer.alloc(13);
  d.writeUInt32BE(4, 0);
  d.writeUInt32BE(4, 4);
  d[8] = 8;
  d[9] = 2;
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk('IHDR', d),
    pngChunk('IDAT', Buffer.alloc(6, 7)),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
};

/** A JPEG whose APP1 segment holds `exif` (metadata that must be stripped) and trailing bytes after EOI. */
export const JPEG = (exif = '', trailer = ''): Buffer => {
  const app1 = exif
    ? Buffer.concat([Buffer.from([0xff, 0xe1]), Buffer.from([0x00, 2 + exif.length]), Buffer.from(exif, 'latin1')])
    : Buffer.alloc(0);
  return Buffer.concat([
    Buffer.from([0xff, 0xd8]),
    app1,
    Buffer.from([0xff, 0xc0, 0x00, 0x08, 0x08, 0x00, 0x08, 0x00, 0x08, 0x00]), // SOF0 8x8
    Buffer.from([0xff, 0xda, 0x00, 0x03, 0x00]),
    Buffer.from('scan'),
    Buffer.from([0xff, 0xd9]),
    Buffer.from(trailer, 'latin1'),
  ]);
};
