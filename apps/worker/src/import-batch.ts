// import.batch consumer (T-044, ADR 0034). Drives a batch created by POST /credentials/import (ADR 0033).
//
// The worker never signs, never holds key material and has no database grants on tenant import tables. It
//   1. asks the API to start the batch and list its rows (ids and flags only),
//   2. re-reads the stored photo ZIP, re-checks every photo (defensive ZIP reader, JPEG structure walk, EXIF and all
//      other metadata stripped, SHA-256 of the exact bytes to be stored, source hash compared with the intake audit),
//   3. calls the API once per row: the API creates or reuses the holder, stores the photo, issues through the one
//      issuance code path (signing, events, audit identical to single issuance) and queues the card render and the
//      holder email (ADR 0030) after commit,
//   4. asks the API to finish the batch, then deletes the stored sources (they hold personal data).
//
// Idempotent and safe to retry: rows already IMPORTED or ERROR are skipped here and refused a second time by the API.
// A row failure is recorded on that row and never stops the batch. Transient failures (API or storage unreachable)
// leave the row PENDING and make the job fail so pg-boss retries it; after the last retry the batch is marked FAILED.
// Never log names, addresses, tokens, file names or photo bytes: ids, row numbers, counts and codes only.
import { createHash } from 'node:crypto';
import type { Logger } from 'pino';
import { importStorageKeys, parseImportBatchJobData, type ImportBatchJob } from './import-batch-job.js';
import { isJpeg, stripJpeg } from './import-photo.js';
import { readZip, ZipError, type ZipEntry, type ZipLimits } from './import-zip.js';
import type { WorkerObjectStorage } from './card-storage.js';

export interface ImportStartResponse {
  status: string;
  rows: { row: number; status: string; externalId: string; photo: string }[];
  sources: { csvSha256?: string; photosSha256?: string };
}
export interface ImportRowResponse {
  outcome: 'IMPORTED' | 'ERROR';
  code?: string;
}
export interface ImportFinishResponse {
  status: string;
  imported: number;
  error: number;
  pending: number;
}

export interface ImportApi {
  start(job: ImportBatchJob): Promise<ImportStartResponse>;
  processRow(job: ImportBatchJob, row: number, body: { photo?: { sha256: string; data: string }; fail?: string }): Promise<ImportRowResponse>;
  finish(job: ImportBatchJob, outcome: 'complete' | 'failed'): Promise<ImportFinishResponse>;
}

/** Generic on purpose: response bodies and URLs are never part of the message. */
export class ImportApiError extends Error {
  constructor(readonly status: number) {
    super(`import api call failed (${status})`);
    this.name = 'ImportApiError';
  }
}

/** Calls the API's internal import endpoints (ADR 0034) with the shared secret. */
export class HttpImportApi implements ImportApi {
  constructor(
    private readonly opts: { baseUrl: string; token: string; timeoutMs?: number; fetchImpl?: typeof fetch },
  ) {}

  private async post<T>(path: string, body: object): Promise<T> {
    const f = this.opts.fetchImpl ?? fetch;
    let res: Response;
    try {
      res = await f(`${this.opts.baseUrl.replace(/\/+$/, '')}${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${this.opts.token}` },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(this.opts.timeoutMs ?? 60_000),
      });
    } catch {
      throw new ImportApiError(0); // network error or timeout; never echo the cause (it can embed the URL)
    }
    if (!res.ok) {
      await res.arrayBuffer().catch(() => undefined);
      throw new ImportApiError(res.status);
    }
    return (await res.json()) as T;
  }

  start(job: ImportBatchJob): Promise<ImportStartResponse> {
    return this.post(`/internal/import/batches/${job.batchId}/start`, { institutionId: job.institutionId });
  }
  processRow(job: ImportBatchJob, row: number, body: { photo?: { sha256: string; data: string }; fail?: string }): Promise<ImportRowResponse> {
    return this.post(`/internal/import/batches/${job.batchId}/rows/${row}`, { institutionId: job.institutionId, ...body });
  }
  finish(job: ImportBatchJob, outcome: 'complete' | 'failed'): Promise<ImportFinishResponse> {
    return this.post(`/internal/import/batches/${job.batchId}/finish`, { institutionId: job.institutionId, outcome });
  }
}

export interface ImportBatchLimits extends ZipLimits {
  /** Largest ZIP read from storage. */
  maxZipBytes: number;
}
export const DEFAULT_WORKER_IMPORT_LIMITS: ImportBatchLimits = {
  maxEntries: 1000,
  maxEntryBytes: 2 * 1024 * 1024,
  maxTotalBytes: 200 * 1024 * 1024,
  maxZipBytes: 50 * 1024 * 1024,
};

export interface ImportBatchDeps {
  api: ImportApi;
  storage: WorkerObjectStorage;
  logger: Logger;
  limits?: Partial<ImportBatchLimits>;
  /** Stop a run after this many transient failures in a row (the API is down; do not hammer it). Default 5. */
  maxConsecutiveTransient?: number;
}

export type ImportBatchOutcome = 'completed' | 'skipped_finished';

/** Thrown when some rows could not be processed for transient reasons; pg-boss retries the job. */
export class ImportBatchIncompleteError extends Error {
  constructor(readonly transientRows: number) {
    super('import batch has rows that must be retried');
    this.name = 'ImportBatchIncompleteError';
  }
}

const sha256 = (b: Buffer): string => createHash('sha256').update(b).digest('hex');
const nfc = (s: string) => s.normalize('NFC');
const JPEG_NAME = /^(.+)\.(?:jpe?g)$/i;

interface PhotoSource {
  /** Row-level problem with the whole archive, applied to every row that needs a zip photo. */
  failure?: string;
  entries?: Map<string, ZipEntry>;
}

async function loadPhotos(deps: ImportBatchDeps, job: ImportBatchJob, expectedSha: string | undefined): Promise<PhotoSource> {
  const limits = { ...DEFAULT_WORKER_IMPORT_LIMITS, ...deps.limits };
  const zip = await deps.storage.get(importStorageKeys(job.institutionId, job.batchId).photos, limits.maxZipBytes); // StorageError: transient
  if (!zip) return { failure: 'PHOTO_SOURCE_MISSING' };
  if (!expectedSha || sha256(zip) !== expectedSha) return { failure: 'PHOTO_SOURCE_MISMATCH' };
  try {
    const entries = new Map<string, ZipEntry>();
    for (const e of readZip(zip, limits)) {
      const m = JPEG_NAME.exec(e.name);
      if (!m) return { failure: 'PHOTO_ARCHIVE_INVALID' };
      const key = nfc(m[1]!);
      if (entries.has(key)) return { failure: 'PHOTO_ARCHIVE_INVALID' };
      entries.set(key, e);
    }
    return { entries };
  } catch (e) {
    if (e instanceof ZipError) return { failure: 'PHOTO_ARCHIVE_INVALID' };
    throw e;
  }
}

/** Sanitised photo for one row, or the failure code to record. Strips metadata; hashes the bytes that will be stored. */
function preparePhoto(src: PhotoSource, externalId: string): { photo: { sha256: string; data: string } } | { fail: string } {
  if (src.failure) return { fail: src.failure };
  const entry = src.entries?.get(nfc(externalId));
  if (!entry) return { fail: 'PHOTO_REQUIRED' };
  let bytes: Buffer;
  try {
    bytes = entry.read();
  } catch {
    return { fail: 'PHOTO_INVALID' };
  }
  if (!isJpeg(bytes)) return { fail: 'PHOTO_INVALID' };
  const clean = stripJpeg(bytes);
  if (!clean) return { fail: 'PHOTO_INVALID' };
  return { photo: { sha256: sha256(clean), data: clean.toString('base64') } };
}

async function deleteSources(deps: ImportBatchDeps, job: ImportBatchJob): Promise<void> {
  const keys = importStorageKeys(job.institutionId, job.batchId);
  for (const k of [keys.csv, keys.photos]) {
    await deps.storage.delete(k).catch(() => {
      deps.logger.warn({ institutionId: job.institutionId, batchId: job.batchId }, 'import source not deleted');
    });
  }
}

export async function runImportBatch(deps: ImportBatchDeps, data: unknown): Promise<ImportBatchOutcome> {
  const job = parseImportBatchJobData(data);
  const log = deps.logger;
  const started = await deps.api.start(job);
  if (started.status !== 'PROCESSING') {
    log.info({ institutionId: job.institutionId, batchId: job.batchId, status: started.status }, 'import batch already finished');
    return 'skipped_finished';
  }
  const pending = started.rows.filter((r) => r.status === 'PENDING');
  let photos: PhotoSource | undefined;
  if (pending.some((r) => r.photo === 'zip')) photos = await loadPhotos(deps, job, started.sources.photosSha256);

  let imported = 0;
  let errors = 0;
  let transient = 0;
  let consecutive = 0;
  const maxConsecutive = deps.maxConsecutiveTransient ?? 5;
  for (const r of pending) {
    const body: { photo?: { sha256: string; data: string }; fail?: string } = {};
    if (r.photo === 'zip') {
      const p = preparePhoto(photos ?? { failure: 'PHOTO_SOURCE_MISSING' }, r.externalId);
      if ('fail' in p) body.fail = p.fail;
      else body.photo = p.photo;
    }
    try {
      const res = await deps.api.processRow(job, r.row, body);
      consecutive = 0;
      if (res.outcome === 'IMPORTED') imported += 1;
      else errors += 1;
    } catch (err) {
      transient += 1;
      consecutive += 1;
      log.warn(
        { institutionId: job.institutionId, batchId: job.batchId, row: r.row, status: err instanceof ImportApiError ? err.status : undefined },
        'import row failed, will retry',
      );
      if (consecutive >= maxConsecutive) break;
    }
  }
  log.info({ institutionId: job.institutionId, batchId: job.batchId, imported, errors, transient, pending: pending.length }, 'import batch pass done');
  if (transient > 0) throw new ImportBatchIncompleteError(transient);

  await deps.api.finish(job, 'complete');
  await deleteSources(deps, job);
  return 'completed';
}

/** Last retry used up: mark the batch FAILED (rows not yet processed stay PENDING) and drop the stored sources. */
export async function failImportBatch(deps: ImportBatchDeps, data: unknown): Promise<void> {
  const job = parseImportBatchJobData(data);
  await deps.api.finish(job, 'failed');
  await deleteSources(deps, job);
  deps.logger.error({ institutionId: job.institutionId, batchId: job.batchId }, 'import batch failed after retries');
}
