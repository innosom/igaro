import { describe, expect, it } from 'vitest';
import {
  canStartImport,
  isTerminalStatus,
  previewErrorRows,
  previewFromErrorBody,
  validateCsvFile,
  validateZipFile,
  type ImportPreview,
} from './import';

const preview = (over: Partial<ImportPreview> = {}): ImportPreview => ({
  totalRows: 2,
  validRows: 2,
  errorRows: 0,
  photos: { provided: true, matched: 2, unmatched: 0 },
  rows: [],
  ...over,
});

describe('import file checks', () => {
  it('requires a csv', () => {
    expect(validateCsvFile(null)).toMatch(/Choose/);
    expect(validateCsvFile({ name: 'a.txt', size: 5 })).toMatch(/\.csv/);
    expect(validateCsvFile({ name: 'a.csv', size: 0 })).toMatch(/empty/);
    expect(validateCsvFile({ name: 'a.csv', size: 3 * 1024 * 1024 })).toMatch(/larger/);
    expect(validateCsvFile({ name: 'a.CSV', size: 10 })).toBeUndefined();
  });
  it('zip is optional', () => {
    expect(validateZipFile(null)).toBeUndefined();
    expect(validateZipFile({ name: 'p.rar', size: 5 })).toMatch(/\.zip/);
    expect(validateZipFile({ name: 'p.zip', size: 60 * 1024 * 1024 })).toMatch(/larger/);
    expect(validateZipFile({ name: 'p.zip', size: 5 })).toBeUndefined();
  });
});

describe('status and preview', () => {
  it('knows terminal states', () => {
    expect(isTerminalStatus('COMPLETED')).toBe(true);
    expect(isTerminalStatus('FAILED')).toBe(true);
    expect(isTerminalStatus('PENDING')).toBe(false);
    expect(isTerminalStatus('PROCESSING')).toBe(false);
  });
  it('enables start only for a clean non-empty preview', () => {
    expect(canStartImport(null, false)).toBe(false);
    expect(canStartImport(preview(), false)).toBe(true);
    expect(canStartImport(preview(), true)).toBe(false);
    expect(canStartImport(preview({ errorRows: 1 }), false)).toBe(false);
    expect(canStartImport(preview({ totalRows: 0 }), false)).toBe(false);
  });
  it('flattens errors with a cap', () => {
    const p = preview({
      errorRows: 1,
      rows: [
        { row: 1, ok: true, holderExists: false, errors: [] },
        {
          row: 2,
          ok: false,
          holderExists: false,
          errors: [{ column: 'email', code: 'BAD', message: 'm' }, { code: 'X', message: 'n' }],
        },
      ],
    });
    expect(previewErrorRows(p)).toEqual([
      { row: 2, column: 'email', code: 'BAD', message: 'm' },
      { row: 2, column: '', code: 'X', message: 'n' },
    ]);
    expect(previewErrorRows(p, 1)).toHaveLength(1);
  });
  it('reads a 422 preview defensively', () => {
    expect(previewFromErrorBody({ preview: preview() })?.totalRows).toBe(2);
    expect(previewFromErrorBody({ preview: { totalRows: 'x' } })).toBeUndefined();
    expect(previewFromErrorBody(undefined)).toBeUndefined();
  });
});
