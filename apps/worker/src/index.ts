export const name = '@igaro/worker';

export * from './account-mail-job.js';
export {
  PgBossAccountMailQueue,
  connectAccountMailQueue,
  retentionFor,
  ACCOUNT_MAIL_QUEUE_OPTIONS,
} from './account-mail-producer.js';
export { createAccountMailHandler, renderAccountMail, buildLink } from './account-mail.js';
export { loadWorkerConfig, ConfigError, type WorkerConfig } from './config.js';
export { startWorker, startWorkerFromConfig } from './worker.js';

// --- Slots for later tasks (not implemented here) ---
// card.render, email.deliver (holder card mail), import.csv, audit.dailyHead: later tasks.
// anchor.credential: Phase 1 only. It will read credential_events (the outbox); do NOT implement in the MVP.
