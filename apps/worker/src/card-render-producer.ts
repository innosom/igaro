// Producer side of card.render (T-040, ADR 0029): implements CardRenderQueue on pg-boss. Used by the API.
// The job carries ids only. One pg-boss connection serves both producers (account mail and card render).
import { PgBoss } from 'pg-boss';
import { ACCOUNT_MAIL_QUEUE } from './account-mail-job.js';
import { ACCOUNT_MAIL_QUEUE_OPTIONS, PgBossAccountMailQueue } from './account-mail-producer.js';
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
  stop(): Promise<void>;
}

/** One producer-only pg-boss connection (no maintenance, no scheduling) that creates both queues. */
export async function connectProducerQueues(opts: {
  connectionString: string;
  schema?: string;
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
  return {
    accountMail: new PgBossAccountMailQueue(boss),
    cardRender: new PgBossCardRenderQueue(boss),
    stop: () => boss.stop({ graceful: true, timeout: 5000 }),
  };
}
