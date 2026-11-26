// Pure helpers for the CSV + ZIP import screen (no React, no network). Limits mirror ADR 0033;
// the API stays authoritative.

export const MAX_CSV_BYTES = 2 * 1024 * 1024;
export const MAX_ZIP_BYTES = 50 * 1024 * 1024;
export const POLL_INTERVAL_MS = 3000;

export interface ImportRowError {
  column?: string;
  code: string;
  message: string;
}
export interface ImportPreview {
  dryRun?: boolean;
  totalRows: number;
  validRows: number;
  errorRows: number;
  photos: { provided: boolean; matched: number; unmatched: number };
  rows: { row: number; ok: boolean; holderExists: boolean; errors: ImportRowError[] }[];
}
export interface ImportBatch {
  id: string;
  filename: string;
  status: string;
  totalRows: number;
  importedRows: number;
  errorRows: number;
  pendingRows: number;
  createdAt: string;
  completedAt: string | null;
  errors: { row: number; error: string }[];
}

type FileLike = { name: string; size: number };

function checkFile(f: FileLike, ext: string, max: number, label: string): string | undefined {
  if (!f.name.toLowerCase().endsWith(ext)) return `${label} must be a ${ext} file.`;
  if (f.size <= 0) return `${label} is empty.`;
  if (f.size > max) return `${label} is larger than ${Math.round(max / (1024 * 1024))} MB.`;
  return undefined;
}

export function validateCsvFile(f: FileLike | null | undefined): string | undefined {
  if (!f) return 'Choose a CSV file.';
  return checkFile(f, '.csv', MAX_CSV_BYTES, 'The CSV file');
}

/** The photos ZIP is optional: no file is fine. */
export function validateZipFile(f: FileLike | null | undefined): string | undefined {
  return f ? checkFile(f, '.zip', MAX_ZIP_BYTES, 'The photos ZIP') : undefined;
}

export function isTerminalStatus(status: string): boolean {
  return status === 'COMPLETED' || status === 'FAILED';
}

/** The real run is allowed only after a clean preview. */
export function canStartImport(preview: ImportPreview | null, busy: boolean): boolean {
  return !!preview && preview.errorRows === 0 && preview.totalRows > 0 && !busy;
}

/** Flattens a preview into table rows (one per error), capped for rendering. */
export function previewErrorRows(
  preview: ImportPreview,
  cap = 200,
): { row: number; column: string; code: string; message: string }[] {
  const out: { row: number; column: string; code: string; message: string }[] = [];
  for (const r of preview.rows) {
    for (const e of r.errors) {
      if (out.length >= cap) return out;
      out.push({ row: r.row, column: e.column ?? '', code: e.code, message: e.message });
    }
  }
  return out;
}

/** Reads `preview` out of a 422 IMPORT_VALIDATION_FAILED body; undefined if absent or malformed. */
export function previewFromErrorBody(body: unknown): ImportPreview | undefined {
  const p = (body as { preview?: unknown } | undefined)?.preview as Partial<ImportPreview> | undefined;
  if (!p || typeof p.totalRows !== 'number' || typeof p.errorRows !== 'number' || !Array.isArray(p.rows)) {
    return undefined;
  }
  return p as ImportPreview;
}
