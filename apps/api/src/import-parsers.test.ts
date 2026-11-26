// T-043 (ADR 0033): CSV parser and ZIP reader unit tests (no database).
import { describe, expect, it } from 'vitest';
import { CsvError, decodeCsv, parseCsv } from './import-csv.js';
import { readZip, ZipError } from './import-zip.js';
import { makeZip } from './test-zip.js';

const L = { maxRecords: 5, maxColumns: 4, maxCellChars: 20 };
const ZL = { maxEntries: 3, maxEntryBytes: 1000, maxTotalBytes: 2000 };
const codeOf = (fn: () => unknown): string | undefined => {
  try {
    fn();
  } catch (e) {
    return (e as { code?: string }).code;
  }
  return undefined;
};

describe('parseCsv', () => {
  it('parses quotes, escaped quotes, embedded commas/newlines, CRLF and skips blank lines', () => {
    const t = 'a,b,c\r\n"x,1","he said ""hi""","l1\nl2"\r\n\r\n,,\r\nlast,,';
    expect(parseCsv(t, { ...L, maxRecords: 10 })).toEqual([
      ['a', 'b', 'c'],
      ['x,1', 'he said "hi"', 'l1\nl2'],
      ['', '', ''],
      ['last', '', ''],
    ]);
  });
  it('does not interpret formulas: cells come back verbatim', () => {
    expect(parseCsv('=1+1,@x,-5', L)).toEqual([['=1+1', '@x', '-5']]);
  });
  it('strips a UTF-8 BOM and refuses invalid UTF-8 and NUL', () => {
    expect(decodeCsv(Buffer.from('﻿a,b'))).toBe('a,b');
    expect(codeOf(() => decodeCsv(Buffer.from([0x61, 0xff, 0xfe])))).toBe('CSV_ENCODING');
    expect(codeOf(() => decodeCsv(Buffer.from('a\u0000b')))).toBe('CSV_ENCODING');
  });
  it('rejects malformed quoting', () => {
    expect(codeOf(() => parseCsv('a,"b', L))).toBe('CSV_MALFORMED');
    expect(codeOf(() => parseCsv('a,"b"c', L))).toBe('CSV_MALFORMED');
    expect(codeOf(() => parseCsv('a,b"c"', L))).toBe('CSV_MALFORMED');
  });
  it('enforces row, column and cell limits', () => {
    expect(codeOf(() => parseCsv('1\n2\n3\n4\n5\n6', L))).toBe('CSV_TOO_MANY_ROWS');
    expect(codeOf(() => parseCsv('a,b,c,d,e', L))).toBe('CSV_TOO_MANY_COLUMNS');
    expect(codeOf(() => parseCsv('x'.repeat(21), L))).toBe('CSV_CELL_TOO_LONG');
    expect(codeOf(() => parseCsv(`"${'x'.repeat(21)}"`, L))).toBe('CSV_CELL_TOO_LONG');
    expect(new CsvError('CSV_MALFORMED', 'm')).toBeInstanceOf(Error);
  });
});

describe('readZip', () => {
  const data = Buffer.from('hello photo');
  it('reads stored and deflated entries and checks CRC', () => {
    const z = makeZip([
      { name: 'a.jpg', data },
      { name: 'b.jpg', data, method: 0 },
    ]);
    const es = readZip(z, ZL);
    expect(es.map((e) => e.name)).toEqual(['a.jpg', 'b.jpg']);
    expect(es[0]!.read().equals(data)).toBe(true);
    expect(es[1]!.read().equals(data)).toBe(true);
  });
  it('rejects path traversal, nested, absolute, hidden and control-character names', () => {
    for (const name of ['../x.jpg', 'dir/x.jpg', '/etc/passwd', 'a\\b.jpg', '.hidden.jpg', 'dir/', 'a\u0001.jpg', '..']) {
      expect(codeOf(() => readZip(makeZip([{ name, data }]), ZL)), name).toBe('ZIP_BAD_ENTRY_NAME');
    }
  });
  it('rejects duplicate names (case-insensitive)', () => {
    expect(codeOf(() => readZip(makeZip([{ name: 'a.jpg', data }, { name: 'A.JPG', data }]), ZL))).toBe('ZIP_DUPLICATE_ENTRY');
  });
  it('caps entry count, per-entry and total declared sizes before inflating', () => {
    const many = ['1', '2', '3', '4'].map((n) => ({ name: `${n}.jpg`, data }));
    expect(codeOf(() => readZip(makeZip(many), ZL))).toBe('ZIP_TOO_MANY_ENTRIES');
    expect(codeOf(() => readZip(makeZip([{ name: 'a.jpg', data: Buffer.alloc(1001) }]), ZL))).toBe('ZIP_ENTRY_TOO_LARGE');
    const three = ['1', '2', '3'].map((n) => ({ name: `${n}.jpg`, data: Buffer.alloc(800) }));
    expect(codeOf(() => readZip(makeZip(three), ZL))).toBe('ZIP_TOO_LARGE');
  });
  it('a bomb that lies about its size is caught when inflating (output capped at the declared size)', () => {
    const bomb = Buffer.alloc(5_000_000, 0);
    const [e] = readZip(makeZip([{ name: 'a.jpg', data: bomb, declaredSize: 10 }]), ZL);
    expect(codeOf(() => e!.read())).toBe('ZIP_INVALID');
  });
  it('rejects encrypted entries, bad signatures and truncated files', () => {
    expect(codeOf(() => readZip(makeZip([{ name: 'a.jpg', data, flags: 1 }]), ZL))).toBe('ZIP_UNSUPPORTED');
    expect(codeOf(() => readZip(Buffer.from('not a zip at all, definitely not'), ZL))).toBe('ZIP_INVALID');
    const z = makeZip([{ name: 'a.jpg', data }]);
    expect(codeOf(() => readZip(z.subarray(0, z.length - 10), ZL))).toBe('ZIP_INVALID');
    expect(new ZipError('ZIP_INVALID', 'm')).toBeInstanceOf(Error);
  });
  it('detects corrupted data via CRC', () => {
    const z = makeZip([{ name: 'a.jpg', data, method: 0 }]);
    const i = 30 + 'a.jpg'.length; // first data byte
    z[i] = z[i]! ^ 0xff;
    const [e] = readZip(z, ZL);
    expect(codeOf(() => e!.read())).toBe('ZIP_INVALID');
  });
});
