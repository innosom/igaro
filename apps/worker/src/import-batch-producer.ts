// Producer side of import.batch (T-043, ADR 0033): implements ImportBatchQueue on pg-boss. Used by the API.
import { enqueueImportBatch, type ImportBatchJob, type ImportBatchSender } from './import-batch-job.js';

export interface ImportBatchQueue {
  enqueue(job: ImportBatchJob): Promise<void>;
}

export class PgBossImportBatchQueue implements ImportBatchQueue {
  constructor(private readonly boss: ImportBatchSender) {}

  async enqueue(job: ImportBatchJob): Promise<void> {
    await enqueueImportBatch(this.boss, job);
  }
}
