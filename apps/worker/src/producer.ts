// Producer-only entry for the API (`@igaro/worker/producer`): no nodemailer, no handlers.
export * from './account-mail-job.js';
export {
  PgBossAccountMailQueue,
  connectAccountMailQueue,
  retentionFor,
  ACCOUNT_MAIL_QUEUE_OPTIONS,
  type ConnectedAccountMailQueue,
} from './account-mail-producer.js';
