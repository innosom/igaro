// Credential import intake (T-043, ADR 0033): POST /credentials/import and GET /credentials/import/:id.
//
// This module only VALIDATES and RECORDS. It never signs and never creates holders or credentials: the batch worker
// (T-044) consumes the job and calls the single-issue code path. Flow: limits -> parse CSV (own RFC 4180 parser) and ZIP
// (own defensive reader) -> validate every row against the institution's types (buildAttributes, the same code as single
// issuance) -> dry run answers a preview and writes nothing; a real run stores the sources under the institution, writes
// import_batches + import_rows + audit in ONE tenant transaction and enqueues an ids-only job after commit.
//
// The institution comes from the session only. Cell contents, file names and ZIP entry names are client data: they are
// never echoed in errors or logs, and the audit entry carries counts and hashes only.
import { buildAttributes, isIsoSeconds } from './credentials.js';
import { isUuid } from './db.js';
import { AppError } from './errors.js';
import { parseHolderBody } from './holders.js';
import type { AttributeDef } from './credential-types.js';

export interface ImportLimits {
  maxCsvBytes: number;
  maxZipBytes: number;
  maxRows: number;
  maxZipEntries: number;
  maxPhotoBytes: number;
  maxZipUncompressedBytes: number;
  maxColumns: number;
  maxCellChars: number;
  /** Batches PENDING/PROCESSING (created in the last 24 h) allowed at once per institution. */
  maxActiveBatches: number;
}

export const DEFAULT_IMPORT_LIMITS: ImportLimits = {
  maxCsvBytes: 2 * 1024 * 1024,
  maxZipBytes: 50 * 1024 * 1024,
  maxRows: 1000,
  maxZipEntries: 1000,
  maxPhotoBytes: 2 * 1024 * 1024,
  maxZipUncompressedBytes: 200 * 1024 * 1024,
  maxColumns: 40,
  maxCellChars: 1000,
  maxActiveBatches: 3,
};

export interface ImportRateLimit {
  max: number;
  windowSeconds: number;
}
export const DEFAULT_IMPORT_RATE_LIMIT: ImportRateLimit = { max: 30, windowSeconds: 3600 };

const CORE_COLUMNS = ['fullName', 'externalId', 'email', 'credentialType', 'expiresAt'] as const;
const REQUIRED_COLUMNS = ['fullName', 'externalId', 'credentialType'] as const;
// A cell that starts like this is a spreadsheet formula when someone re-opens the data in Excel/Sheets.
const FORMULA_START = /^[=+\-@\t\r]/;

export interface RowError {
  column?: string;
  code: string;
  message: string;
}
export interface RowResult {
  row: number;
  ok: boolean;
  holderExists: boolean;
  errors: RowError[];
}
/** What import_rows.data holds for a valid row: normalised values the worker feeds to the issuance path. */
export interface ImportRowData {
  fullName: string;
  externalId: string;
  email: string | null;
  credentialType: string;
  attributes: Record<string, string>;
  expiresAt?: string;
  /** Where the photo comes from: the uploaded ZIP, or a photo the existing holder already has. */
  photo: 'zip' | 'holder';
}
export interface Preview {
  dryRun: boolean;
  totalRows: number;
  validRows: number;
  errorRows: number;
  photos: { provided: number; matched: number; unmatched: number };
  rows: RowResult[];
}

export interface TypeInfo {
  id: string;
  code: string;
  schema: unknown;
  defs: AttributeDef[];
}
export interface ExistingHolder {
  fullName: string;
  hasPhoto: boolean;
}

export const fileError =(code: string, message: string, status = 400) => new AppError(status, code, message);

const nfc = (s: string) => s.normalize('NFC');

/** Validate parsed CSV records. Pure apart from its inputs; unit-testable. Never throws for row problems. */
export function validateRows(
  records: string[][],
  types: TypeInfo[],
  holders: ReadonlyMap<string, ExistingHolder>,
  photoNames: ReadonlySet<string>,
  photoValid: ReadonlyMap<string, boolean>,
): { results: RowResult[]; data: (ImportRowData | null)[]; matched: Set<string> } {
  const header = records[0]!.map((h) => h.trim());
  const attrKeys = new Set<string>();
  for (const t of types) for (const d of t.defs) attrKeys.add(d.key);
  const seenCols = new Set<string>();
  for (const h of header) {
    if (seenCols.has(h)) throw fileError('DUPLICATE_COLUMN', 'The CSV header repeats a column');
    seenCols.add(h);
    const known = (CORE_COLUMNS as readonly string[]).includes(h) || attrKeys.has(h);
    if (!known) throw fileError('UNKNOWN_COLUMN', 'The CSV header has a column that is not a known field');
  }
  for (const r of REQUIRED_COLUMNS) {
    if (!seenCols.has(r)) throw fileError('MISSING_COLUMN', `The CSV header must contain ${r}`);
  }
  const col = (cells: string[], name: string): string | undefined => {
    const i = header.indexOf(name);
    return i < 0 ? undefined : cells[i];
  };

  const results: RowResult[] = [];
  const data: (ImportRowData | null)[] = [];
  const seenExternal = new Set<string>();
  const matched = new Set<string>();

  for (let n = 1; n < records.length; n++) {
    const cells = records[n]!;
    const errors: RowError[] = [];
    const fail = (code: string, message: string, column?: string) => errors.push({ ...(column ? { column } : {}), code, message });
    const safe = <T>(column: string, fn: () => T): T | undefined => {
      try {
        return fn();
      } catch (e) {
        if (e instanceof AppError) fail(e.code, e.message, column);
        else fail('INVALID_VALUE', 'Invalid value', column);
        return undefined;
      }
    };
    const noFormula = (column: string, v: string): boolean => {
      if (FORMULA_START.test(v) || FORMULA_START.test(v.trimStart())) {
        fail('FORMULA_PREFIX', 'Text must not start with = + - @ or a control character', column);
        return false;
      }
      return true;
    };

    if (cells.length !== header.length) {
      results.push({ row: n, ok: false, holderExists: false, errors: [{ code: 'COLUMN_COUNT', message: 'The row has the wrong number of columns' }] });
      data.push(null);
      continue;
    }

    const rawName = col(cells, 'fullName') ?? '';
    const rawExt = col(cells, 'externalId') ?? '';
    const rawEmail = (col(cells, 'email') ?? '').trim();
    const rawType = (col(cells, 'credentialType') ?? '').trim();
    const rawExpires = (col(cells, 'expiresAt') ?? '').trim();

    const fullName = noFormula('fullName', rawName)
      ? safe('fullName', () => parseHolderBody({ fullName: rawName }, 'patch').fullName!)
      : undefined;
    let externalId: string | undefined;
    if (rawExt.trim() === '') fail('INVALID_EXTERNAL_ID', 'External id is required', 'externalId');
    else if (noFormula('externalId', rawExt)) {
      externalId = safe('externalId', () => parseHolderBody({ externalId: rawExt }, 'patch').externalId ?? undefined);
    }
    const email = rawEmail === '' ? null : safe('email', () => parseHolderBody({ email: rawEmail }, 'patch').email ?? null);

    if (externalId !== undefined) {
      if (seenExternal.has(externalId)) fail('DUPLICATE_EXTERNAL_ID', 'This external id appears earlier in the file', 'externalId');
      seenExternal.add(externalId);
    }

    const type = rawType === '' ? undefined : types.find((t) => (isUuid(rawType) ? t.id === rawType.toLowerCase() : t.code === rawType));
    if (!type) fail('UNKNOWN_CREDENTIAL_TYPE', 'Unknown credential type', 'credentialType');

    let attributes: Record<string, string> | undefined;
    if (type) {
      const supplied: Record<string, unknown> = {};
      for (const [i, h] of header.entries()) {
        if ((CORE_COLUMNS as readonly string[]).includes(h)) continue;
        const v = cells[i] ?? '';
        if (v.trim() === '') continue;
        const def = type.defs.find((d) => d.key === h);
        if (!def) {
          fail('UNKNOWN_ATTRIBUTE', 'This column does not belong to the credential type', h);
          continue;
        }
        if (def.type === 'string' && !noFormula(h, v)) continue;
        supplied[h] = v;
      }
      if (errors.every((e) => e.code !== 'UNKNOWN_ATTRIBUTE' && e.code !== 'FORMULA_PREFIX')) {
        try {
          attributes = buildAttributes(type.schema, supplied);
        } catch (e) {
          if (e instanceof AppError) fail(e.code, e.message);
          else fail('INVALID_ATTRIBUTES', 'Invalid attributes');
        }
      }
    }

    let expiresAt: string | undefined;
    if (rawExpires !== '') {
      if (isIsoSeconds(rawExpires) && Date.parse(rawExpires) > Date.now()) expiresAt = rawExpires;
      else fail('INVALID_EXPIRES_AT', 'expiresAt must be a future UTC timestamp like 2027-01-31T00:00:00Z', 'expiresAt');
    }

    // Existing holder: reused by external id. A different name is refused rather than silently kept or overwritten.
    const existing = externalId === undefined ? undefined : holders.get(externalId);
    if (existing && fullName !== undefined && nfc(existing.fullName) !== nfc(fullName)) {
      fail('HOLDER_NAME_MISMATCH', 'A holder with this external id already exists under a different name', 'externalId');
    }
    let photo: 'zip' | 'holder' | undefined;
    if (externalId !== undefined) {
      const key = nfc(externalId);
      if (photoNames.has(key)) {
        matched.add(key);
        if (photoValid.get(key) === true) photo = 'zip';
        else fail('PHOTO_INVALID', 'The photo is not a valid JPEG image', 'externalId');
      } else if (existing?.hasPhoto) photo = 'holder';
      else fail('PHOTO_REQUIRED', 'No photo in the archive for this external id and the holder has none', 'externalId');
    }

    const ok = errors.length === 0;
    results.push({ row: n, ok, holderExists: existing !== undefined, errors });
    if (ok) {
      data.push({
        fullName: fullName!,
        externalId: externalId!,
        email: email ?? null,
        credentialType: type!.code,
        attributes: attributes!,
        ...(expiresAt ? { expiresAt } : {}),
        photo: photo!,
      });
    } else data.push(null);
  }
  return { results, data, matched };
}

