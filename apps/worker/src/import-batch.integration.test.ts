// Integration for import.batch (T-044, ADR 0034): real pg-boss on Postgres ($DATABASE_URL, scratch pg-boss schema), the
// producer used by the API, and a fake internal API. The API side (holders, issuance, rows) is covered end to end in
// apps/api/src/import-internal.test.ts. Skipped without DATABASE_URL. Test values only.
import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import { createTransport } from 'nodemailer';
import { connectProducerQueues, type ConnectedProducerQueues } from './card-render-producer.js';
import { MemoryWorkerStorage } from './card-storage.js';
import { IMPORT_BATCH_QUEUE, importBatchSingletonKey } from './import-batch-job.js';
import { ImportApiError, type ImportApi } from './import-batch.js';
import { createLogger } from './logger.js';
import { JPEG } from './test-images.js';
import { makeZip } from './test-zip.js';
import { startWorker, type WorkerHandle } from './worker.js';

const url = process.env.DATABASE_URL;
const INST = '11111111-1111-4111-8111-111111111111';
const B_OK = '22222222-2222-4222-8222-222222222222';
const B_FAIL = '33333333-3333-4333-8333-333333333333';
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function waitFor(cond: () => boolean | Promise<boolean>, ms = 20000): Promise<void> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await cond()) return;
    await sleep(100);
  }
  throw new Error('timed out waiting for condition');
}

describe.skipIf(!url)('import.batch via pg-boss (needs Postgres at DATABASE_URL)', () => {
  const schema = `pgboss_t044_${randomBytes(4).toString('hex')}`;
  const idleSchema = `pgboss_t044i_${randomBytes(4).toString('hex')}`;
  const logLines: string[] = [];
  const finished: Record<string, string[]> = {};
  const rowCalls: string[] = [];
  const storage = new MemoryWorkerStorage();
  let admin: pg.Client;
  let worker: WorkerHandle;
  let producer: ConnectedProducerQueues;
  let idleProducer: ConnectedProducerQueues;

  const api: ImportApi = {
    async start(job) {
      if (job.batchId === B_FAIL) throw new ImportApiError(503); // the API is down for this batch
      return { status: 'PROCESSING', rows: [{ row: 1, status: 'PENDING', externalId: 'e-1', photo: 'holder' }], sources: {} };
    },
    async processRow(job, row) {
      rowCalls.push(`${job.batchId}:${row}`);
      return { outcome: 'IMPORTED' };
    },
    async finish(job, outcome) {
      (finished[job.batchId] ??= []).push(outcome);
      return { status: outcome === 'complete' ? 'COMPLETED' : 'FAILED', imported: 0, error: 0, pending: 0 };
    },
  };
  const jobRows = async (sch: string, batchId: string) =>
    (await admin.query(`SELECT state, retry_count FROM "${sch}".job WHERE name = $1 AND singleton_key = $2`, [IMPORT_BATCH_QUEUE, importBatchSingletonKey(batchId)])).rows as {
      state: string;
      retry_count: number;
    }[];

  beforeAll(async () => {
    admin = new pg.Client({ connectionString: url });
    await admin.connect();
    const logger = createLogger('debug', { write: (s: string) => void logLines.push(s) });
    // Sources the job would delete when it finishes.
    await storage.put(`institutions/${INST}/imports/${B_OK}/source.csv`, Buffer.from('fullName\nSecret Person\n'), 'text/csv');
    await storage.put(`institutions/${INST}/imports/${B_OK}/photos.zip`, makeZip([{ name: 'e-1.jpg', data: JPEG() }]), 'application/zip');
    worker = await startWorker({
      databaseUrl: url as string,
      schema,
      logger,
      pollingIntervalSeconds: 0.5,
      mail: { transport: createTransport({ jsonTransport: true }), from: 'iGARO <no-reply@igaro.test>', webBaseUrl: 'https://app.igaro.test' },
      importBatch: { api, storage },
    });
    producer = await connectProducerQueues({ connectionString: url as string, schema });
    idleProducer = await connectProducerQueues({ connectionString: url as string, schema: idleSchema });
  }, 90000);

  afterAll(async () => {
    await producer?.stop();
    await idleProducer?.stop();
    await worker?.stop();
    await admin?.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    await admin?.query(`DROP SCHEMA IF EXISTS "${idleSchema}" CASCADE`);
    await admin?.end();
  }, 60000);

  it('runs a queued batch: rows processed, batch finished, sources deleted, job completed, nothing sensitive logged', async () => {
    await producer.importBatch.enqueue({ institutionId: INST, batchId: B_OK });
    await waitFor(() => (finished[B_OK] ?? []).length > 0);
    expect(finished[B_OK]).toEqual(['complete']);
    expect(rowCalls).toContain(`${B_OK}:1`);
    expect(storage.objects.size).toBe(0);
    await waitFor(async () => (await jobRows(schema, B_OK)).some((r) => r.state === 'completed'));
    const out = logLines.join('');
    expect(out).not.toContain('Secret Person');
    expect(out).not.toContain('e-1');
  }, 40000);

  it('marks the batch FAILED when the last attempt fails', async () => {
    // retryLimit 0 on this job: the first attempt is the last one.
    await sendWithoutRetries(B_FAIL);
    await waitFor(() => (finished[B_FAIL] ?? []).length > 0);
    expect(finished[B_FAIL]).toEqual(['failed']);
    await waitFor(async () => (await jobRows(schema, B_FAIL)).some((r) => r.state === 'failed'));
  }, 40000);

  it('a second enqueue for the same batch is a declined no-op (singleton key)', async () => {
    await idleProducer.importBatch.enqueue({ institutionId: INST, batchId: B_OK });
    await idleProducer.importBatch.enqueue({ institutionId: INST, batchId: B_OK });
    expect(await jobRows(idleSchema, B_OK)).toHaveLength(1);
  });

  it('drops a malformed payload instead of retrying it', async () => {
    const before = finished[B_OK]?.length ?? 0;
    await rawSend({ institutionId: 'nope', batchId: B_OK });
    await sleep(2500);
    expect(finished[B_OK]?.length ?? 0).toBe(before);
    expect(logLines.join('')).toContain('invalid job dropped');
  }, 20000);

  async function rawSend(data: object, options: Record<string, unknown> = {}): Promise<void> {
    const { PgBoss } = await import('pg-boss');
    const boss = new PgBoss({ connectionString: url as string, schema, supervise: false, schedule: false, max: 1 });
    boss.on('error', () => undefined);
    await boss.start();
    try {
      await boss.send(IMPORT_BATCH_QUEUE, data, options);
    } finally {
      await boss.stop({ graceful: true, timeout: 3000 });
    }
  }
  const sendWithoutRetries = (batchId: string) => rawSend({ institutionId: INST, batchId }, { retryLimit: 0, singletonKey: importBatchSingletonKey(batchId) });
});
