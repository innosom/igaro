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

/** Records jobs in memory for tests. */
export class MemoryAccountMailQueue implements AccountMailQueue {
  readonly jobs: AccountMailJob[] = [];
  async enqueue(job: AccountMailJob): Promise<void> {
    this.jobs.push(job);
  }
}
