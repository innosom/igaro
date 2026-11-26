// Contract for import.batch (T-043, ADR 0033). Shared by the producer (API) and the consumer (worker, T-044).
// Free of heavy imports on purpose. The job carries ids only: no CSV content, no holder data, no token.
// The worker loads the validated rows from import_rows and the sources from storage using these ids.

export const IMPORT_BATCH_QUEUE = 'import.batch';

export interface ImportBatchJob {
  institutionId: string;
  batchId: string;
}

/** A batch can run for minutes (up to 1000 issuances); retries are safe only if the consumer skips IMPORTED rows. */
export const IMPORT_BATCH_QUEUE_OPTIONS = {
  policy: 'short',
  retryLimit: 3,
  retryDelay: 60,
  retryBackoff: true,
  expireInSeconds: 3600,
  retentionSeconds: 7 * 24 * 3600,
  deleteAfterSeconds: 7 * 24 * 3600,
} as const;

/** One queued job per batch. */
export const importBatchSingletonKey = (batchId: string): string => `import.batch:${batchId}`;

export class InvalidImportBatchJobError extends Error {
  constructor() {
    super('invalid import batch job payload');
    this.name = 'InvalidImportBatchJobError';
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function parseImportBatchJobData(data: unknown): ImportBatchJob {
  if (typeof data !== 'object' || data === null) throw new InvalidImportBatchJobError();
  const d = data as Record<string, unknown>;
  if (typeof d.institutionId !== 'string' || !UUID.test(d.institutionId)) throw new InvalidImportBatchJobError();
  if (typeof d.batchId !== 'string' || !UUID.test(d.batchId)) throw new InvalidImportBatchJobError();
  return { institutionId: d.institutionId, batchId: d.batchId };
}

/** Storage keys of the uploaded sources. Institution-scoped; `photos` exists only when a ZIP was uploaded. */
export function importStorageKeys(institutionId: string, batchId: string): { csv: string; photos: string } {
  const base = `institutions/${institutionId}/imports/${batchId}`;
  return { csv: `${base}/source.csv`, photos: `${base}/photos.zip` };
}

export interface ImportBatchSender {
  send(name: string, data: object, options: Record<string, unknown>): Promise<string | null>;
}

/** Enqueue helper (API side). Returns false when a job for this batch is already queued. */
export async function enqueueImportBatch(boss: ImportBatchSender, job: ImportBatchJob): Promise<boolean> {
  const id = await boss.send(
    IMPORT_BATCH_QUEUE,
    { institutionId: job.institutionId, batchId: job.batchId },
    { singletonKey: importBatchSingletonKey(job.batchId) },
  );
  return id !== null;
}
