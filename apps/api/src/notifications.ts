// Outbound account mail (invites, password resets). Sending is the worker's job (T-011); the API only
// enqueues through this interface. The job carries the RAW one-time token because the email must
// contain it: implementations must treat it as a secret (never log it; T-011 must keep it out of
// long-lived job tables, see ADR 0005).

export type AccountMailJob =
  | { kind: 'INVITE'; to: string; token: string; expiresAt: Date; institutionId: string }
  | { kind: 'PASSWORD_RESET'; to: string; token: string; expiresAt: Date };

export interface AccountMailQueue {
  enqueue(job: AccountMailJob): Promise<void>;
}

/** Drops every job. The default until the worker's pg-boss implementation is wired (T-011). */
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
