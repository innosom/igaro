// Producer-only entry for the API (`@igaro/worker/producer`): no nodemailer, no handlers.
export * from './account-mail-job.js';
export * from './card-render-job.js';
export {
  PgBossCardRenderQueue,
  connectProducerQueues,
  type CardRenderQueue,
  type ConnectedProducerQueues,
} from './card-render-producer.js';
export {
  PgBossAccountMailQueue,
  connectAccountMailQueue,
  retentionFor,
  ACCOUNT_MAIL_QUEUE_OPTIONS,
  type ConnectedAccountMailQueue,
} from './account-mail-producer.js';
