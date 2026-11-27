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
import { externalSchemaOptions, type PgbossSchemaMode } from './pgboss-mode.js';
import pg from 'pg';
import {
  AUDIT_DAILY_HEAD_CRON,
  AUDIT_DAILY_HEAD_QUEUE,
  AUDIT_DAILY_HEAD_QUEUE_OPTIONS,
  assertHeadInsertPrivilege,
  headSignerFromEnvelope,
  runAuditDailyHead,
  type AuditHeadDeps,
} from './audit-head.js';
import { CalendarTimestamper, NoopTimestamper } from './ots.js';
import { CARD_RENDER_QUEUE, CARD_RENDER_QUEUE_OPTIONS, InvalidCardRenderJobError } from './card-render-job.js';
import { ChromeCardRenderer, runCardRender, type CardRenderDeps } from './card-render.js';
import { S3WorkerStorage } from './card-storage.js';
import {
  HOLDER_DELIVERY_QUEUE,
  HOLDER_DELIVERY_QUEUE_OPTIONS,
  InvalidHolderDeliveryJobError,
} from './holder-delivery-job.js';
import { runHolderDelivery, type HolderDeliveryDeps } from './holder-delivery.js';
import {
  IMPORT_BATCH_QUEUE,
  IMPORT_BATCH_QUEUE_OPTIONS,
  InvalidImportBatchJobError,
} from './import-batch-job.js';
import { failImportBatch, HttpImportApi, runImportBatch, type ImportBatchDeps } from './import-batch.js';

export interface WorkerHandle {
  boss: PgBoss;
  stop(): Promise<void>;
}

export interface StartWorkerOptions {
  databaseUrl: string;
  schema?: string;
  logger: Logger;
  /**
   * Mail transport and links. `key` (DELIVERY_PAYLOAD_KEY) opens the sealed invite/reset jobs (ADR 0038); without it
   * the account.mail handler is not registered (jobs wait; the API without the key queues none).
   */
  mail: Omit<AccountMailHandlerDeps, 'key'> & { key?: Buffer };
  /** `external` (ADR 0038): the schema was provisioned by `setupPgbossSchema`; never create or migrate it here. */
  schemaMode?: PgbossSchemaMode;
  /** Seconds between polls for new jobs (default 2). Tests lower it. */
  pollingIntervalSeconds?: number;
  /** audit.dailyHead (T-028). Omitted = the job is not registered. */
  auditHead?: Omit<AuditHeadDeps, 'logger'> & { cron?: string };
  /** card.render (T-039). Omitted = the job is not registered. */
  cardRender?: Omit<CardRenderDeps, 'logger'>;
  /** email.deliver (T-041, ADR 0030). Uses `mail` for transport, sender and web URL. Omitted = the job is not registered. */
  holderDelivery?: Pick<HolderDeliveryDeps, 'pool' | 'key' | 'assumeRole'>;
  /** import.batch (T-044, ADR 0034). Omitted = the job is not registered. */
  importBatch?: Omit<ImportBatchDeps, 'logger'>;
}

export async function startWorker(opts: StartWorkerOptions): Promise<WorkerHandle> {
  const { logger } = opts;
  const boss = new PgBoss({
    connectionString: opts.databaseUrl,
    ...(opts.schema ? { schema: opts.schema } : {}),
    ...externalSchemaOptions(opts.schemaMode ?? 'auto'),
    max: 4,
  });
  boss.on('error', (err: Error & { code?: string }) => logger.error({ err }, 'pg-boss error'));
  await boss.start();
  await boss.createQueue(ACCOUNT_MAIL_QUEUE, ACCOUNT_MAIL_QUEUE_OPTIONS);

  const accountMailKey = opts.mail.key;
  if (!accountMailKey) logger.warn('DELIVERY_PAYLOAD_KEY not set: account.mail is not registered');
  const handle = accountMailKey ? createAccountMailHandler({ ...opts.mail, key: accountMailKey }) : undefined;
  if (handle) await boss.work<unknown>(
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
  if (handle) logger.info({ queue: ACCOUNT_MAIL_QUEUE }, 'worker started');

  if (opts.auditHead) {
    const { cron, ...deps } = opts.auditHead;
    // M2: fail loudly at startup if this login cannot write heads (e.g. APP_DATABASE_URL by mistake).
    await assertHeadInsertPrivilege(deps.pool, deps.assumeRole);
    await boss.createQueue(AUDIT_DAILY_HEAD_QUEUE, AUDIT_DAILY_HEAD_QUEUE_OPTIONS);
    // pg-boss schedules are keyed per queue (one schedule, one tick per cron slot). A duplicate or manual
    // run for the same UTC day is harmless: the job is idempotent per chain and day (unique constraint).
    await boss.schedule(AUDIT_DAILY_HEAD_QUEUE, cron ?? AUDIT_DAILY_HEAD_CRON, {}, { tz: 'UTC' });
    await boss.work(AUDIT_DAILY_HEAD_QUEUE, { batchSize: 1, pollingIntervalSeconds: opts.pollingIntervalSeconds ?? 2 }, async (jobs) => {
      for (const job of jobs) {
        const summary = await runAuditDailyHead({ ...deps, logger });
        logger.info({ jobId: job.id, queue: AUDIT_DAILY_HEAD_QUEUE }, 'audit head job done');
        // Fail (and retry with backoff) when any chain failed; completed chains are skipped next time.
        if (summary.failures > 0) throw new Error(`audit head run had ${summary.failures} failure(s)`);
      }
    });
    logger.info({ queue: AUDIT_DAILY_HEAD_QUEUE }, 'audit head job registered');
  }

  if (opts.cardRender) {
    const deps: CardRenderDeps = { ...opts.cardRender, logger };
    await boss.createQueue(CARD_RENDER_QUEUE, CARD_RENDER_QUEUE_OPTIONS);
    // One render at a time: each job starts a browser, and 500-card imports must not exhaust memory.
    await boss.work<unknown>(CARD_RENDER_QUEUE, { batchSize: 1, pollingIntervalSeconds: opts.pollingIntervalSeconds ?? 2 }, async (jobs) => {
      for (const job of jobs) {
        try {
          const outcome = await runCardRender(deps, job.data);
          logger.info({ jobId: job.id, queue: CARD_RENDER_QUEUE, outcome }, 'card render job done');
        } catch (err) {
          if (err instanceof InvalidCardRenderJobError) {
            logger.error({ jobId: job.id, queue: CARD_RENDER_QUEUE }, 'invalid job dropped');
            continue;
          }
          logger.warn({ jobId: job.id, queue: CARD_RENDER_QUEUE, retryCount: job.retryCount, err }, 'card render job failed, will retry');
          throw err;
        }
      }
    });
    logger.info({ queue: CARD_RENDER_QUEUE }, 'card render job registered');
  }

  if (opts.holderDelivery) {
    const deps: HolderDeliveryDeps = {
      ...opts.holderDelivery,
      transport: opts.mail.transport,
      from: opts.mail.from,
      webBaseUrl: opts.mail.webBaseUrl,
      logger,
    };
    await boss.createQueue(HOLDER_DELIVERY_QUEUE, HOLDER_DELIVERY_QUEUE_OPTIONS);
    await boss.work<unknown>(HOLDER_DELIVERY_QUEUE, { batchSize: 1, pollingIntervalSeconds: opts.pollingIntervalSeconds ?? 2 }, async (jobs) => {
      for (const job of jobs) {
        try {
          // Only ids and outcome are logged: never job.data (sealed token and recipient).
          const outcome = await runHolderDelivery(deps, job.data);
          logger.info({ jobId: job.id, queue: HOLDER_DELIVERY_QUEUE, outcome }, 'holder delivery job done');
          // The sealed token must not linger: remove the finished job now (deleteAfterSeconds is the backstop).
          await boss.deleteJob(HOLDER_DELIVERY_QUEUE, job.id).catch(() => undefined);
        } catch (err) {
          if (err instanceof InvalidHolderDeliveryJobError) {
            // A retry cannot fix a malformed, tampered or wrongly keyed payload: drop it.
            logger.error({ jobId: job.id, queue: HOLDER_DELIVERY_QUEUE }, 'invalid job dropped');
            continue;
          }
          logger.warn({ jobId: job.id, queue: HOLDER_DELIVERY_QUEUE, retryCount: job.retryCount, err }, 'holder delivery job failed, will retry');
          throw err;
        }
      }
    });
    logger.info({ queue: HOLDER_DELIVERY_QUEUE }, 'holder delivery job registered');
  }

  if (opts.importBatch) {
    const deps: ImportBatchDeps = { ...opts.importBatch, logger };
    await boss.createQueue(IMPORT_BATCH_QUEUE, IMPORT_BATCH_QUEUE_OPTIONS);
    // One batch at a time: each issuance is signed by the API and every row is serial by design (ADR 0034).
    await boss.work(IMPORT_BATCH_QUEUE, { batchSize: 1, includeMetadata: true, pollingIntervalSeconds: opts.pollingIntervalSeconds ?? 2 }, async (jobs) => {
      for (const job of jobs) {
        try {
          const outcome = await runImportBatch(deps, job.data);
          logger.info({ jobId: job.id, queue: IMPORT_BATCH_QUEUE, outcome }, 'import batch job done');
        } catch (err) {
          if (err instanceof InvalidImportBatchJobError) {
            logger.error({ jobId: job.id, queue: IMPORT_BATCH_QUEUE }, 'invalid job dropped');
            continue;
          }
          if (job.retryCount >= job.retryLimit) {
            // Last attempt: record the batch as FAILED so the admin sees it, then let pg-boss mark the job failed.
            await failImportBatch(deps, job.data).catch(() => logger.error({ jobId: job.id, queue: IMPORT_BATCH_QUEUE }, 'could not mark import batch failed'));
          }
          logger.warn({ jobId: job.id, queue: IMPORT_BATCH_QUEUE, retryCount: job.retryCount, err }, 'import batch job failed');
          throw err;
        }
      }
    });
    logger.info({ queue: IMPORT_BATCH_QUEUE }, 'import batch job registered');
  }

  return {
    boss,
    stop: async () => {
      await boss.stop({ graceful: true, timeout: 10000 });
      await opts.auditHead?.pool.end();
      await opts.cardRender?.pool.end();
      await opts.holderDelivery?.pool.end();
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
  const ah = config.auditHead;
  if (!ah) logger.warn('AUDIT_HEAD_SIGNING_KEY not set: audit.dailyHead is not registered');
  const cr = config.cardRender;
  if (!cr) logger.warn('S3_* or CHROME_PATH not set: card.render is not registered');
  const hd = config.holderDelivery;
  if (!hd) logger.warn('DELIVERY_PAYLOAD_KEY not set: email.deliver is not registered');
  const ib = config.importBatch;
  if (!ib) logger.warn('INTERNAL_API_URL/INTERNAL_API_TOKEN or S3_* not set: import.batch is not registered');
  return startWorker({
    databaseUrl: config.databaseUrl,
    schema: config.pgbossSchema,
    logger,
    schemaMode: config.pgbossSchemaMode,
    mail: { transport, from: config.smtp.from, webBaseUrl: config.webBaseUrl, ...(hd ? { key: hd.key } : {}) },
    ...(hd ? { holderDelivery: { pool: new pg.Pool({ connectionString: config.databaseUrl, max: 2 }), key: hd.key } } : {}),
    ...(ib
      ? { importBatch: { api: new HttpImportApi({ baseUrl: ib.apiUrl, token: ib.token }), storage: new S3WorkerStorage(ib.s3) } }
      : {}),
    ...(cr
      ? {
          cardRender: {
            pool: new pg.Pool({ connectionString: config.databaseUrl, max: 2 }),
            storage: new S3WorkerStorage(cr.s3),
            renderer: new ChromeCardRenderer({ executablePath: cr.chromePath, noSandbox: cr.chromeNoSandbox }),
            verifyBaseUrl: cr.verifyBaseUrl,
          },
        }
      : {}),
    ...(ah
      ? {
          auditHead: {
            pool: new pg.Pool({ connectionString: config.databaseUrl, max: 2 }),
            signer: headSignerFromEnvelope(ah.keyEnvelope, ah.wrapKey, ah.kid),
            timestamper:
              config.otsCalendars.length > 0
                ? new CalendarTimestamper({ calendars: config.otsCalendars })
                : new NoopTimestamper(),
            cron: ah.cron,
          },
        }
      : {}),
  });
}
