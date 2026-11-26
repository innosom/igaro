// Outbound account mail (invites, password resets). Sending is the worker's job (T-011); the API only
// enqueues through this interface. The job carries the RAW one-time token because the email must
// contain it: implementations must treat it as a secret (never log it; see ADR 0005 and ADR 0006).
//
// The contract lives in @igaro/worker (producer and consumer share it; the worker never imports the API,
// so there is no cycle). It is re-exported here so API code keeps importing from './notifications.js'.
import type { AccountMailJob, AccountMailQueue } from '@igaro/worker/producer';

// Type-only on purpose: the runtime producer is loaded lazily by server.ts (only when the pg-boss
// driver is configured), so tests and the default no-op path never load pg-boss.
export type { AccountMailJob, AccountMailQueue };

/** Drops every job. The default when the pg-boss queue is not configured (ACCOUNT_MAIL_QUEUE unset). */
export class NoopAccountMailQueue implements AccountMailQueue {
  async enqueue(): Promise<void> {
    // intentionally empty
  }
}

/** Card render jobs (T-040, ADR 0029). Ids only. Enqueued after the issuing transaction commits. */
export interface CardRenderQueue {
  enqueue(job: { institutionId: string; credentialId: string }): Promise<void>;
}

/** Drops every job (pg-boss not configured). Cards then simply do not exist and the endpoints answer CARD_NOT_READY. */
export class NoopCardRenderQueue implements CardRenderQueue {
  async enqueue(): Promise<void> {
    // intentionally empty
  }
}

/** Records jobs in memory for tests; `fail` makes enqueue reject. */
export class MemoryCardRenderQueue implements CardRenderQueue {
  readonly jobs: { institutionId: string; credentialId: string }[] = [];
  fail = false;
  async enqueue(job: { institutionId: string; credentialId: string }): Promise<void> {
    if (this.fail) throw new Error('queue unavailable');
    this.jobs.push({ institutionId: job.institutionId, credentialId: job.credentialId });
  }
}

/**
 * Holder delivery email jobs (T-041, ADR 0030). The job carries the RAW holder token and the recipient: the pg-boss
 * implementation seals them (AES-256-GCM) before they reach the queue. Implementations must never log them.
 */
export interface HolderDeliveryQueue {
  enqueue(job: { institutionId: string; credentialId: string; to: string; holderToken: string }): Promise<void>;
}

/** Drops every job (pg-boss or DELIVERY_PAYLOAD_KEY not configured): the holder simply gets no email. */
export class NoopHolderDeliveryQueue implements HolderDeliveryQueue {
  async enqueue(): Promise<void> {
    // intentionally empty
  }
}

/** Records jobs in memory for tests; `fail` makes enqueue reject. */
export class MemoryHolderDeliveryQueue implements HolderDeliveryQueue {
  readonly jobs: { institutionId: string; credentialId: string; to: string; holderToken: string }[] = [];
  fail = false;
  async enqueue(job: { institutionId: string; credentialId: string; to: string; holderToken: string }): Promise<void> {
    if (this.fail) throw new Error('queue unavailable');
    this.jobs.push({ ...job });
  }
}

/** Records jobs in memory for tests. */
export class MemoryAccountMailQueue implements AccountMailQueue {
  readonly jobs: AccountMailJob[] = [];
  async enqueue(job: AccountMailJob): Promise<void> {
    this.jobs.push(job);
  }
}
