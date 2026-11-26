// Producer side of card.render (T-040, ADR 0029): implements CardRenderQueue on pg-boss. Used by the API.
// The job carries ids only. One pg-boss connection serves both producers (account mail and card render).
import { PgBoss } from 'pg-boss';
import { ACCOUNT_MAIL_QUEUE } from './account-mail-job.js';
import { ACCOUNT_MAIL_QUEUE_OPTIONS, PgBossAccountMailQueue } from './account-mail-producer.js';
import { HOLDER_DELIVERY_QUEUE, HOLDER_DELIVERY_QUEUE_OPTIONS } from './holder-delivery-job.js';
import { PgBossHolderDeliveryQueue } from './holder-delivery-producer.js';
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
  accountMail: PgBossAccountMailQueue;
  cardRender: PgBossCardRenderQueue;
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
}): Promise<ConnectedProducerQueues> {
  const boss = new PgBoss({
    connectionString: opts.connectionString,
    ...(opts.schema ? { schema: opts.schema } : {}),
    supervise: false,
    schedule: false,
    max: 2,
  });
  boss.on('error', (err: Error & { code?: string }) => {
    console.error(JSON.stringify({ msg: 'queue producer error', code: err.code }));
  });
  await boss.start();
  await boss.createQueue(ACCOUNT_MAIL_QUEUE, ACCOUNT_MAIL_QUEUE_OPTIONS);
  await boss.createQueue(CARD_RENDER_QUEUE, CARD_RENDER_QUEUE_OPTIONS);
  if (opts.deliveryKey) await boss.createQueue(HOLDER_DELIVERY_QUEUE, HOLDER_DELIVERY_QUEUE_OPTIONS);
  return {
    accountMail: new PgBossAccountMailQueue(boss),
    cardRender: new PgBossCardRenderQueue(boss),
    holderDelivery: opts.deliveryKey ? new PgBossHolderDeliveryQueue(boss, opts.deliveryKey) : undefined,
    stop: () => boss.stop({ graceful: true, timeout: 5000 }),
  };
}
