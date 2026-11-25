// pg-boss lifecycle for the worker: start, register handlers, stop.
import { PgBoss } from 'pg-boss';
import type { Logger } from 'pino';
import { createTransport } from 'nodemailer';
import {
  createAccountMailHandler,
  type AccountMailHandlerDeps,
} from './account-mail.js';
import { ACCOUNT_MAIL_QUEUE, InvalidAccountMailJobError } from './account-mail-job.js';
import { ACCOUNT_MAIL_QUEUE_OPTIONS } from './account-mail-producer.js';
import type { WorkerConfig } from './config.js';

export interface WorkerHandle {
  boss: PgBoss;
  stop(): Promise<void>;
}

export interface StartWorkerOptions {
  databaseUrl: string;
  schema?: string;
  logger: Logger;
  mail: AccountMailHandlerDeps;
  /** Seconds between polls for new jobs (default 2). Tests lower it. */
  pollingIntervalSeconds?: number;
}

export async function startWorker(opts: StartWorkerOptions): Promise<WorkerHandle> {
  const { logger } = opts;
  const boss = new PgBoss({
    connectionString: opts.databaseUrl,
    ...(opts.schema ? { schema: opts.schema } : {}),
    max: 4,
  });
  boss.on('error', (err: Error & { code?: string }) => logger.error({ err }, 'pg-boss error'));
  await boss.start();
  await boss.createQueue(ACCOUNT_MAIL_QUEUE, ACCOUNT_MAIL_QUEUE_OPTIONS);

  const handle = createAccountMailHandler(opts.mail);
  await boss.work<unknown>(
    ACCOUNT_MAIL_QUEUE,
    { batchSize: 1, pollingIntervalSeconds: opts.pollingIntervalSeconds ?? 2 },
    async (jobs) => {
      for (const job of jobs) {
        try {
          // Only the job id and outcome are logged: never job.data (raw token, recipient).
          const outcome = await handle(job.data);
          logger.info({ jobId: job.id, queue: ACCOUNT_MAIL_QUEUE, outcome }, 'account mail job done');
        } catch (err) {
          if (err instanceof InvalidAccountMailJobError) {
            // Retrying cannot fix a malformed payload: drop it (completes, then is deleted).
            logger.error({ jobId: job.id, queue: ACCOUNT_MAIL_QUEUE }, 'invalid job dropped');
            continue;
          }
          logger.warn(
            { jobId: job.id, queue: ACCOUNT_MAIL_QUEUE, retryCount: job.retryCount, err },
            'account mail job failed, will retry',
          );
          throw err;
        }
      }
    },
  );
  logger.info({ queue: ACCOUNT_MAIL_QUEUE }, 'worker started');

  return {
    boss,
    stop: async () => {
      await boss.stop({ graceful: true, timeout: 10000 });
      logger.info('worker stopped');
    },
  };
}

export function startWorkerFromConfig(config: WorkerConfig, logger: Logger): Promise<WorkerHandle> {
  const transport = createTransport({
    host: config.smtp.host,
    port: config.smtp.port,
    secure: config.smtp.secure,
    ...(config.smtp.user ? { auth: { user: config.smtp.user, pass: config.smtp.pass ?? '' } } : {}),
    // Mailpit speaks plain SMTP; real providers are reached with SMTP_SECURE/STARTTLS.
    connectionTimeout: 10000,
    socketTimeout: 20000,
  });
  return startWorker({
    databaseUrl: config.databaseUrl,
    schema: config.pgbossSchema,
    logger,
    mail: { transport, from: config.smtp.from, webBaseUrl: config.webBaseUrl },
  });
}
