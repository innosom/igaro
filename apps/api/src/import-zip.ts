// Defensive ZIP reader for the photo archive of a credential import (T-043, ADR 0033). Nothing is ever written to disk,
// so path traversal cannot escape; names are still validated strictly (flat names only) so a later consumer cannot be
// tricked either. Zip bombs are bounded three ways: entry count, per-entry and total DECLARED uncompressed size are capped
// before any inflation, and every inflation is capped at the declared size (the real size must equal it).
// Supported: stored and deflate, no encryption, no ZIP64, single disk. Everything else is refused.
import { crc32, inflateRawSync } from 'node:zlib';

export type ZipErrorCode =
  | 'ZIP_INVALID'
  | 'ZIP_UNSUPPORTED'
  | 'ZIP_TOO_MANY_ENTRIES'
  | 'ZIP_TOO_LARGE'
  | 'ZIP_ENTRY_TOO_LARGE'
  | 'ZIP_BAD_ENTRY_NAME'
  | 'ZIP_DUPLICATE_ENTRY';

export class ZipError extends Error {
  constructor(
    readonly code: ZipErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'ZipError';
  }
}

export interface ZipLimits {
  maxEntries: number;
  maxEntryBytes: number;
  maxTotalBytes: number;
}

export interface ZipEntry {
  /** Validated flat file name. Client-controlled: never log or echo it. */
  name: string;
  size: number;
  /** Inflate and CRC-check this entry. Throws ZipError ZIP_INVALID on any mismatch. */
  read(): Buffer;
}

const EOCD_SIG = 0x06054b50;
const CD_SIG = 0x02014b50;
const LOCAL_SIG = 0x04034b50;
const invalid = () => new ZipError('ZIP_INVALID', 'The photo archive is not a valid ZIP file');

// eslint-disable-next-line no-control-regex
const BAD_NAME = /[\u0000-\u001f\u007f-\u009f/\\]|\p{Cf}/u;

function decodeName(raw: Buffer, utf8: boolean): string {
  let s: string;
  try {
    s = utf8 ? new TextDecoder('utf-8', { fatal: true }).decode(raw) : raw.toString('latin1');
  } catch {
    throw new ZipError('ZIP_BAD_ENTRY_NAME', 'The photo archive has an invalid entry name');
  }
  // Flat names only: no directories, separators, traversal, hidden files, control characters.
  if (s.length < 1 || raw.length > 255 || BAD_NAME.test(s) || s.startsWith('.') || s.endsWith('.')) {
    throw new ZipError('ZIP_BAD_ENTRY_NAME', 'The photo archive has an invalid entry name');
  }
  return s.normalize('NFC');
}

export function readZip(buf: Buffer, limits: ZipLimits): ZipEntry[] {
  if (buf.length < 22) throw invalid();
  // End of central directory: scan backwards (a comment of up to 64 KiB may follow it).
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 0xffff); i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw invalid();
  const disk = buf.readUInt16LE(eocd + 4);
  const cdDisk = buf.readUInt16LE(eocd + 6);
  const entriesOnDisk = buf.readUInt16LE(eocd + 8);
  const total = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  const cdOffset = buf.readUInt32LE(eocd + 16);
  if (disk !== 0 || cdDisk !== 0 || entriesOnDisk !== total) throw new ZipError('ZIP_UNSUPPORTED', 'Multi-part ZIP files are not supported');
  if (total === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    throw new ZipError('ZIP_UNSUPPORTED', 'ZIP64 archives are not supported');
  }
  if (total > limits.maxEntries) throw new ZipError('ZIP_TOO_MANY_ENTRIES', 'The photo archive has too many files');
  if (cdOffset + cdSize > eocd) throw invalid();

  const entries: ZipEntry[] = [];
  const seen = new Set<string>();
  let totalBytes = 0;
  let p = cdOffset;
  for (let n = 0; n < total; n++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== CD_SIG) throw invalid();
    const flags = buf.readUInt16LE(p + 8);
    const method = buf.readUInt16LE(p + 10);
    const crc = buf.readUInt32LE(p + 16);
    const compSize = buf.readUInt32LE(p + 20);
    const size = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOffset = buf.readUInt32LE(p + 42);
    const next = p + 46 + nameLen + extraLen + commentLen;
    if (next > cdOffset + cdSize || next > buf.length) throw invalid();
    if (flags & 0x1 || flags & 0x40) throw new ZipError('ZIP_UNSUPPORTED', 'Encrypted ZIP files are not supported');
    if (method !== 0 && method !== 8) throw new ZipError('ZIP_UNSUPPORTED', 'Unsupported ZIP compression method');
    if (compSize === 0xffffffff || size === 0xffffffff || localOffset === 0xffffffff) {
      throw new ZipError('ZIP_UNSUPPORTED', 'ZIP64 archives are not supported');
    }
    const rawName = buf.subarray(p + 46, p + 46 + nameLen);
    const name = decodeName(rawName, (flags & 0x800) !== 0);
    const key = name.toLowerCase();
    if (seen.has(key)) throw new ZipError('ZIP_DUPLICATE_ENTRY', 'The photo archive has duplicate file names');
    seen.add(key);
    if (size > limits.maxEntryBytes) throw new ZipError('ZIP_ENTRY_TOO_LARGE', 'A file in the photo archive is too large');
    totalBytes += size;
    if (totalBytes > limits.maxTotalBytes) throw new ZipError('ZIP_TOO_LARGE', 'The photo archive is too large when unpacked');
    if (method === 0 && compSize !== size) throw invalid();

    // Local header: must agree with the central directory (a mismatch is a classic confusion trick).
    if (localOffset + 30 > buf.length || buf.readUInt32LE(localOffset) !== LOCAL_SIG) throw invalid();
    const lNameLen = buf.readUInt16LE(localOffset + 26);
    const lExtraLen = buf.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + lNameLen + lExtraLen;
    if (lNameLen !== nameLen || !buf.subarray(localOffset + 30, localOffset + 30 + lNameLen).equals(rawName)) throw invalid();
    if (dataStart + compSize > cdOffset) throw invalid();

    const compressed = buf.subarray(dataStart, dataStart + compSize);
    entries.push({
      name,
      size,
      read: () => {
        let out: Buffer;
        try {
          out = method === 0 ? Buffer.from(compressed) : inflateRawSync(compressed, { maxOutputLength: Math.max(size, 1) });
        } catch {
          throw invalid();
        }
        if (out.length !== size || crc32(out) !== crc) throw invalid();
        return out;
      },
    });
    p = next;
  }
  return entries;
}
