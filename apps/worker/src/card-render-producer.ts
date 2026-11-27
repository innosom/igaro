// Producer side of card.render (T-040, ADR 0029): implements CardRenderQueue on pg-boss. Used by the API.
// The job carries ids only. One pg-boss connection serves both producers (account mail and card render).
import { PgBoss } from 'pg-boss';
import { ACCOUNT_MAIL_QUEUE } from './account-mail-job.js';
import { ACCOUNT_MAIL_QUEUE_OPTIONS, PgBossAccountMailQueue } from './account-mail-producer.js';
import { externalSchemaOptions, type PgbossSchemaMode } from './pgboss-mode.js';
import { HOLDER_DELIVERY_QUEUE, HOLDER_DELIVERY_QUEUE_OPTIONS } from './holder-delivery-job.js';
import { PgBossHolderDeliveryQueue } from './holder-delivery-producer.js';
import { IMPORT_BATCH_QUEUE, IMPORT_BATCH_QUEUE_OPTIONS } from './import-batch-job.js';
import { PgBossImportBatchQueue } from './import-batch-producer.js';
import {
  CARD_RENDER_QUEUE,
  CARD_RENDER_QUEUE_OPTIONS,
  enqueueCardRender,
  type CardRenderJob,
  type CardRenderSender,
} from './card-render-job.js';

/** What the API calls after a credential commits. A queued duplicate is a no-op, not an error. */
export interface CardRenderQueue {
  enqueue(job: CardRenderJob): Promise<void>;
}

export class PgBossCardRenderQueue implements CardRenderQueue {
  constructor(private readonly boss: CardRenderSender) {}

  async enqueue(job: CardRenderJob): Promise<void> {
    await enqueueCardRender(this.boss, job);
  }
}

export interface ConnectedProducerQueues {
  /** Present only when a delivery payload key was given: invite and reset mail are sealed with it (ADR 0038). */
  accountMail: PgBossAccountMailQueue | undefined;
  cardRender: PgBossCardRenderQueue;
  importBatch: PgBossImportBatchQueue;
  /** Present only when a delivery payload key was given (ADR 0030). */
  holderDelivery: PgBossHolderDeliveryQueue | undefined;
  stop(): Promise<void>;
}

/** One producer-only pg-boss connection (no maintenance, no scheduling) that creates both queues. */
export async function connectProducerQueues(opts: {
  connectionString: string;
  schema?: string;
  /** DELIVERY_PAYLOAD_KEY (32 bytes). Without it the email.deliver queue is not created and no delivery is queued. */
  deliveryKey?: Buffer | undefined;
  /** `external` (ADR 0038): the schema and queues were provisioned by the owner; this connection creates nothing. */
  schemaMode?: PgbossSchemaMode;
}): Promise<ConnectedProducerQueues> {
  const mode = opts.schemaMode ?? 'auto';
  const boss = new PgBoss({
    connectionString: opts.connectionString,
    ...(opts.schema ? { schema: opts.schema } : {}),
    ...externalSchemaOptions(mode),
    ...(mode === 'external' ? { registerInstance: false } : {}),
    supervise: false,
    schedule: false,
    max: 2,
  });
  boss.on('error', (err: Error & { code?: string }) => {
    console.error(JSON.stringify({ msg: 'queue producer error', code: err.code }));
  });
  await boss.start();
  if (mode === 'auto') {
    await boss.createQueue(ACCOUNT_MAIL_QUEUE, ACCOUNT_MAIL_QUEUE_OPTIONS);
    await boss.createQueue(CARD_RENDER_QUEUE, CARD_RENDER_QUEUE_OPTIONS);
    await boss.createQueue(IMPORT_BATCH_QUEUE, IMPORT_BATCH_QUEUE_OPTIONS);
    if (opts.deliveryKey) await boss.createQueue(HOLDER_DELIVERY_QUEUE, HOLDER_DELIVERY_QUEUE_OPTIONS);
  }
  return {
    accountMail: opts.deliveryKey ? new PgBossAccountMailQueue(boss, opts.deliveryKey) : undefined,
    cardRender: new PgBossCardRenderQueue(boss),
    importBatch: new PgBossImportBatchQueue(boss),
    holderDelivery: opts.deliveryKey ? new PgBossHolderDeliveryQueue(boss, opts.deliveryKey) : undefined,
    stop: () => boss.stop({ graceful: true, timeout: 5000 }),
  };
}
