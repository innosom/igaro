export const name = '@igaro/worker';

export * from './account-mail-job.js';
export {
  PgBossAccountMailQueue,
  connectAccountMailQueue,
  retentionFor,
  ACCOUNT_MAIL_QUEUE_OPTIONS,
} from './account-mail-producer.js';
export { setupPgbossSchema, grantSql, skeletonSql, PGBOSS_QUEUES, type PgbossSetupOptions } from './pgboss-setup.js';
export { parsePgbossSchemaMode, externalSchemaOptions, type PgbossSchemaMode } from './pgboss-mode.js';
export { createAccountMailHandler, renderAccountMail, buildLink } from './account-mail.js';
export { loadWorkerConfig, ConfigError, type WorkerConfig } from './config.js';
export { startWorker, startWorkerFromConfig } from './worker.js';
export {
  runAuditDailyHead,
  headSignerFromEnvelope,
  AUDIT_DAILY_HEAD_QUEUE,
  AUDIT_DAILY_HEAD_CRON,
  type AuditHeadDeps,
  type AuditHeadSummary,
  type HeadSigner,
} from './audit-head.js';
export {
  CalendarTimestamper,
  NoopTimestamper,
  parseCalendarUrls,
  parseProof,
  isCompleteProof,
  OtsError,
  type Timestamper,
} from './ots.js';

export * from './card-render-job.js';
export * from './holder-delivery-job.js';
export { PgBossHolderDeliveryQueue } from './holder-delivery-producer.js';
export { runHolderDelivery, renderHolderMail, holderLink, type HolderDeliveryDeps } from './holder-delivery.js';
export { runCardRender, ChromeCardRenderer, type CardRenderer, type CardRenderDeps } from './card-render.js';
export { renderCardHtml, qrSvg, type CardModel } from './card-template.js';
export { S3WorkerStorage, MemoryWorkerStorage, type WorkerObjectStorage } from './card-storage.js';

export * from './import-batch-job.js';
export {
  runImportBatch,
  failImportBatch,
  HttpImportApi,
  ImportApiError,
  ImportBatchIncompleteError,
  DEFAULT_WORKER_IMPORT_LIMITS,
  type ImportApi,
  type ImportBatchDeps,
} from './import-batch.js';

// --- Slots for later tasks (not implemented here) ---
// (import.batch: import-batch.ts, T-044.) (email.deliver: holder-delivery.ts, T-041.) (audit.dailyHead: audit-head.ts, T-028; card.render: card-render.ts, T-039.)
// anchor.credential: Phase 1 only. It will read credential_events (the outbox); do NOT implement in the MVP.
