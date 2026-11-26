// Producer side of email.deliver (T-041, ADR 0030). Used by the API. Seals {to, holderToken} before it reaches pg-boss.
// Never logs: the job carries a (sealed) raw holder token and the recipient address.
import {
  enqueueHolderDelivery,
  type HolderDeliveryJob,
  type HolderDeliveryQueue,
  type HolderDeliverySender,
} from './holder-delivery-job.js';

export class PgBossHolderDeliveryQueue implements HolderDeliveryQueue {
  constructor(
    private readonly boss: HolderDeliverySender,
    private readonly key: Buffer,
  ) {}

  /** A declined duplicate (same credential already queued) is a no-op, not an error. */
  async enqueue(job: HolderDeliveryJob): Promise<void> {
    await enqueueHolderDelivery(this.boss, job, this.key);
  }
}
