// Producer side of account mail: implements AccountMailQueue on pg-boss. Used by the API.
// Never logs: the payload carries a raw one-time token and the recipient address.
import { PgBoss } from 'pg-boss';
import {
  ACCOUNT_MAIL_QUEUE,
  toJobData,
  type AccountMailJob,
  type AccountMailQueue,
} from './account-mail-job.js';

/** Queue options shared by producer and worker (ADR 0006): short life, nothing lingers after completion. */
export const ACCOUNT_MAIL_QUEUE_OPTIONS = {
  expireInSeconds: 120,
  retryLimit: 5,
  retryDelay: 30,
  retryBackoff: true,
  // Completed AND failed jobs (and their raw token) are deleted after 60 s. 0 would mean "keep forever".
  deleteAfterSeconds: 60,
  // Upper bound for a job that never starts; the producer lowers it per job to the token expiry.
  retentionSeconds: 24 * 3600,
} as const;

/** The subset of PgBoss the producer uses (lets tests pass a fake). */
export interface BossSender {
  send(name: string, data: object, options: Record<string, unknown>): Promise<string | null>;
}

/** A job is useless once its token expires, so it must not outlive it (plus a minute of slack). */
export function retentionFor(expiresAt: Date, now: Date = new Date()): number {
  const seconds = Math.ceil((expiresAt.getTime() - now.getTime()) / 1000) + 60;
  return Math.min(Math.max(seconds, 60), ACCOUNT_MAIL_QUEUE_OPTIONS.retentionSeconds * 7);
}

export class PgBossAccountMailQueue implements AccountMailQueue {
  constructor(
    private readonly boss: BossSender,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async enqueue(job: AccountMailJob): Promise<void> {
    const id = await this.boss.send(ACCOUNT_MAIL_QUEUE, toJobData(job), {
      retentionSeconds: retentionFor(job.expiresAt, this.now()),
    });
    // pg-boss returns null when it declined to create the job (e.g. singleton clash). We set no
    // singleton key, so null means something is wrong; fail loudly rather than lose an invite.
    if (id === null) throw new Error('account mail job was not created');
  }
}

export interface ConnectedAccountMailQueue {
  queue: PgBossAccountMailQueue;
  stop(): Promise<void>;
}

/**
 * Open a producer-only pg-boss connection (no maintenance, no scheduling: the worker owns those).
 * `schema` defaults to pg-boss's own default ("pgboss"); it is separate from tenant tables.
 */
export async function connectAccountMailQueue(opts: {
  connectionString: string;
  schema?: string;
}): Promise<ConnectedAccountMailQueue> {
  const boss = new PgBoss({
    connectionString: opts.connectionString,
    ...(opts.schema ? { schema: opts.schema } : {}),
    supervise: false,
    schedule: false,
    max: 2,
  });
  // 'error' with no listener would crash the process; log only the error class.
  boss.on('error', (err: Error & { code?: string }) => {
    console.error(JSON.stringify({ msg: 'account mail producer error', code: err.code }));
  });
  await boss.start();
  await boss.createQueue(ACCOUNT_MAIL_QUEUE, ACCOUNT_MAIL_QUEUE_OPTIONS);
  return {
    queue: new PgBossAccountMailQueue(boss),
    stop: () => boss.stop({ graceful: true, timeout: 5000 }),
  };
}
