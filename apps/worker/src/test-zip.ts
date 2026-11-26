// Minimal ZIP writer for tests only (stored/deflate, optional lies about sizes to build hostile archives).
import { crc32, deflateRawSync } from 'node:zlib';

export interface TestZipEntry {
  name: string;
  data: Buffer;
  method?: 0 | 8;
  /** Declare a different uncompressed size in the headers (zip bomb simulation). */
  declaredSize?: number;
  flags?: number;
}

export function makeZip(entries: TestZipEntry[]): Buffer {
  const locals: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const e of entries) {
    const name = Buffer.from(e.name, 'utf8');
    const method = e.method ?? 8;
    const body = method === 8 ? deflateRawSync(e.data) : e.data;
    const size = e.declaredSize ?? e.data.length;
    const flags = (e.flags ?? 0) | 0x800;
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(flags, 6);
    lh.writeUInt16LE(method, 8);
    lh.writeUInt32LE(crc32(e.data), 14);
    lh.writeUInt32LE(body.length, 18);
    lh.writeUInt32LE(size, 22);
    lh.writeUInt16LE(name.length, 26);
    const local = Buffer.concat([lh, name, body]);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(flags, 8);
    ch.writeUInt16LE(method, 10);
    ch.writeUInt32LE(crc32(e.data), 16);
    ch.writeUInt32LE(body.length, 20);
    ch.writeUInt32LE(size, 24);
    ch.writeUInt16LE(name.length, 28);
    ch.writeUInt32LE(offset, 42);
    central.push(Buffer.concat([ch, name]));
    locals.push(local);
    offset += local.length;
  }
  const cd = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, eocd]);
}
