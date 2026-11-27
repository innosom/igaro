// Producer side of account mail: implements AccountMailQueue on pg-boss. Used by the API.
// The job holds the recipient and raw one-time token only SEALED (ADR 0038). Never logs the job.
import { PgBoss } from 'pg-boss';
import {
  ACCOUNT_MAIL_QUEUE,
  sealAccountMail,
  type AccountMailJob,
  type AccountMailQueue,
} from './account-mail-job.js';
import { externalSchemaOptions, type PgbossSchemaMode } from './pgboss-mode.js';

/** Queue options shared by producer and worker (ADR 0006): short life, nothing lingers after completion. */
export const ACCOUNT_MAIL_QUEUE_OPTIONS = {
  expireInSeconds: 120,
  retryLimit: 5,
  retryDelay: 30,
  retryBackoff: true,
  // Completed AND failed jobs are deleted after 60 s. 0 would mean "keep forever".
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
    /** DELIVERY_PAYLOAD_KEY (32 bytes): seals {to, token} before the job reaches the table. */
    private readonly key: Buffer,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async enqueue(job: AccountMailJob): Promise<void> {
    const id = await this.boss.send(ACCOUNT_MAIL_QUEUE, sealAccountMail(job, this.key), {
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
 * `schemaMode: 'external'` (ADR 0038): the schema and queue were provisioned by the owner; this connection creates
 * nothing and needs only enqueue grants.
 */
export async function connectAccountMailQueue(opts: {
  connectionString: string;
  schema?: string;
  key: Buffer;
  schemaMode?: PgbossSchemaMode;
}): Promise<ConnectedAccountMailQueue> {
  const mode = opts.schemaMode ?? 'auto';
  const boss = new PgBoss({
    connectionString: opts.connectionString,
    ...(opts.schema ? { schema: opts.schema } : {}),
    ...externalSchemaOptions(mode),
    supervise: false,
    schedule: false,
    ...(mode === 'external' ? { registerInstance: false } : {}),
    max: 2,
  });
  // 'error' with no listener would crash the process; log only the error class.
  boss.on('error', (err: Error & { code?: string }) => {
    console.error(JSON.stringify({ msg: 'account mail producer error', code: err.code }));
  });
  await boss.start();
  if (mode === 'auto') await boss.createQueue(ACCOUNT_MAIL_QUEUE, ACCOUNT_MAIL_QUEUE_OPTIONS);
  return {
    queue: new PgBossAccountMailQueue(boss, opts.key),
    stop: () => boss.stop({ graceful: true, timeout: 5000 }),
  };
}
