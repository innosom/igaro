// Integration: real pg-boss on Postgres ($DATABASE_URL) + an in-process fake SMTP server (Mailpit is not
// needed). Uses a unique pg-boss schema per run and drops it afterwards. Skipped without DATABASE_URL.
import { randomBytes, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import { SMTPServer } from 'smtp-server';
import { createTransport } from 'nodemailer';
import { ACCOUNT_MAIL_QUEUE, type AccountMailJob } from './account-mail-job.js';
import { connectAccountMailQueue } from './account-mail-producer.js';
import { createLogger } from './logger.js';
import { startWorker, type WorkerHandle } from './worker.js';

const url = process.env.DATABASE_URL;

/** Decode quoted-printable (soft breaks and =XX) so link assertions work on the raw SMTP data. */
const decodeQp = (s: string): string =>
  s
    .replace(/=\r?\n/g, '')
    .replace(/=([0-9A-F]{2})/g, (_m, h: string) => String.fromCharCode(parseInt(h, 16)));

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function waitFor(cond: () => boolean | Promise<boolean>, ms = 20000): Promise<void> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await cond()) return;
    await sleep(100);
  }
  throw new Error('timed out waiting for condition');
}

describe.skipIf(!url)('account mail via pg-boss (needs Postgres at DATABASE_URL)', () => {
  const schema = `pgboss_t011_${randomBytes(4).toString('hex')}`;
  // A schema with no worker: jobs stay queued, so the stored row can be inspected (T-051).
  const idleSchema = `pgboss_t011i_${randomBytes(4).toString('hex')}`;
  const key = randomBytes(32);
  let idleProducer: Awaited<ReturnType<typeof connectAccountMailQueue>>;
  const messages: string[] = [];
  const logLines: string[] = [];
  let smtp: SMTPServer;
  let smtpPort = 0;
  let worker: WorkerHandle;
  let producer: Awaited<ReturnType<typeof connectAccountMailQueue>>;
  let admin: pg.Client;
  const token = () => randomBytes(32).toString('base64url');

  beforeAll(async () => {
    smtp = new SMTPServer({
      authOptional: true,
      disabledCommands: ['STARTTLS'],
      onData(stream, _session, cb) {
        const chunks: Buffer[] = [];
        stream.on('data', (c: Buffer) => chunks.push(c));
        stream.on('end', () => {
          messages.push(Buffer.concat(chunks).toString('utf8'));
          cb();
        });
      },
    });
    await new Promise<void>((r) => smtp.listen(0, '127.0.0.1', r));
    smtpPort = (smtp.server.address() as { port: number }).port;

    admin = new pg.Client({ connectionString: url });
    await admin.connect();

    const logger = createLogger('debug', { write: (s: string) => void logLines.push(s) });
    worker = await startWorker({
      databaseUrl: url as string,
      schema,
      logger,
      pollingIntervalSeconds: 0.5,
      mail: {
        transport: createTransport({ host: '127.0.0.1', port: smtpPort, secure: false, tls: { rejectUnauthorized: false }, ignoreTLS: true }),
        from: 'iGARO <no-reply@igaro.test>',
        webBaseUrl: 'https://app.igaro.test',
        key,
      },
    });
    producer = await connectAccountMailQueue({ connectionString: url as string, schema, key });
    idleProducer = await connectAccountMailQueue({ connectionString: url as string, schema: idleSchema, key });
  }, 60000);

  afterAll(async () => {
    await producer?.stop();
    await idleProducer?.stop();
    await worker?.stop();
    await admin?.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    await admin?.query(`DROP SCHEMA IF EXISTS "${idleSchema}" CASCADE`);
    await admin?.end();
    await new Promise<void>((r) => smtp?.close(() => r()));
  }, 60000);

  it('delivers invite and reset mail with the link and leaves no pending job', async () => {
    const t1 = token();
    const t2 = token();
    const exp = new Date(Date.now() + 3600_000);
    const jobs: AccountMailJob[] = [
      { kind: 'INVITE', to: 'new-admin@school.test', token: t1, expiresAt: exp, institutionId: randomUUID() },
      { kind: 'PASSWORD_RESET', to: 'user@school.test', token: t2, expiresAt: exp },
    ];
    for (const j of jobs) await producer.queue.enqueue(j);

    await waitFor(() => messages.length >= 2);
    const all = messages.map(decodeQp).join('\n----\n');
    expect(all).toContain(`https://app.igaro.test/invite/accept#token=${t1}`);
    expect(all).toContain(`https://app.igaro.test/password-reset#token=${t2}`);
    expect(all).toContain('To: new-admin@school.test');
    expect(all).toContain('Content-Type: text/plain');
    expect(all).toContain('Content-Type: text/html');

    // Completed jobs (and so the raw tokens) leave the table shortly after completion (deleteAfterSeconds 60).
    // Until the maintenance sweep runs they are in state "completed"; assert that none is still waiting.
    // The SMTP message arrives while the handler is still running, so the job can briefly still be
    // "active": poll until none is waiting or active (a job stuck pending still fails the test).
    const countPending = async (): Promise<number> => {
      const pending = await admin.query(
        `SELECT count(*)::int AS n FROM "${schema}".job WHERE name = $1 AND state < 'completed'`,
        [ACCOUNT_MAIL_QUEUE],
      );
      return (pending.rows[0] as { n: number }).n;
    };
    await waitFor(async () => (await countPending()) === 0, 10000).catch(() => undefined);
    expect(await countPending()).toBe(0);
  }, 40000);

  it('a queued job row holds no token and no address, in any column (T-051)', async () => {
    const t1 = token();
    const t2 = token();
    const exp = new Date(Date.now() + 3600_000);
    await idleProducer.queue.enqueue({ kind: 'INVITE', to: 'row-check@school.test', token: t1, expiresAt: exp, institutionId: '33333333-3333-4333-8333-333333333333' });
    await idleProducer.queue.enqueue({ kind: 'PASSWORD_RESET', to: 'row-check2@school.test', token: t2, expiresAt: exp });
    // Whole rows as text: data, output, every column.
    const rows = await admin.query(`SELECT j::text AS row, data FROM "${idleSchema}".job j WHERE name = $1`, [ACCOUNT_MAIL_QUEUE]);
    expect(rows.rows).toHaveLength(2);
    for (const r of rows.rows as { row: string; data: Record<string, unknown> }[]) {
      expect(r.row).not.toContain(t1);
      expect(r.row).not.toContain(t2);
      expect(r.row).not.toContain('school.test');
      expect(Object.keys(r.data).sort()).toEqual(
        r.data.kind === 'INVITE' ? ['expiresAt', 'institutionId', 'kind', 'ref', 'sealed'] : ['expiresAt', 'kind', 'ref', 'sealed'],
      );
    }
  }, 40000);

  it('a job from an old clear-text producer is dropped, not mailed', async () => {
    const before = messages.length;
    const t = token();
    const boss = (worker as WorkerHandle).boss;
    await boss.send(ACCOUNT_MAIL_QUEUE, { kind: 'PASSWORD_RESET', to: 'legacy@school.test', token: t, expiresAt: new Date(Date.now() + 3600_000).toISOString() });
    await waitFor(() => logLines.some((l) => l.includes('invalid job dropped')));
    expect(messages.slice(before).map(decodeQp).join('\n')).not.toContain(t);
  }, 40000);

  it('stores a short retention and deleteAfter on the job rows', async () => {
    const exp = new Date(Date.now() + 120_000);
    await producer.queue.enqueue({ kind: 'PASSWORD_RESET', to: 'r@school.test', token: token(), expiresAt: exp });
    const r = await admin.query(
      `SELECT deletion_seconds AS d, EXTRACT(EPOCH FROM (keep_until - start_after))::int AS r FROM "${schema}".job WHERE name = $1 ORDER BY created_on DESC LIMIT 1`,
      [ACCOUNT_MAIL_QUEUE],
    );
    // The worker may already have taken the job, but the row exists until the 60 s deletion window passes.
    const row = r.rows[0] as { d: number; r: number };
    expect(row.d).toBe(60);
    expect(row.r).toBeLessThanOrEqual(120 + 60 + 1);
    await waitFor(() => messages.length >= 3);
  }, 40000);

  it('does not send a job whose expiresAt has passed, and still completes it', async () => {
    const before = messages.length;
    const t = token();
    await producer.queue.enqueue({
      kind: 'PASSWORD_RESET',
      to: 'late@school.test',
      token: t,
      expiresAt: new Date(Date.now() - 5000),
    });
    // A later valid job proves the queue kept flowing past the expired one.
    const t3 = token();
    await producer.queue.enqueue({
      kind: 'PASSWORD_RESET',
      to: 'ontime@school.test',
      token: t3,
      expiresAt: new Date(Date.now() + 3600_000),
    });
    await waitFor(() => messages.slice(before).some((m) => decodeQp(m).includes(t3)));
    await waitFor(() => logLines.some((l) => l.includes('skipped_expired')));
    const sent = messages.slice(before).map(decodeQp).join('\n');
    expect(sent).toContain(t3);
    expect(sent).not.toContain(t);
    expect(sent).not.toContain('late@school.test');
  }, 40000);

  it('never logs tokens, recipients or links', async () => {
    const out = logLines.join('');
    expect(out).toContain('account mail job done');
    expect(out).not.toMatch(/school\.test/);
    expect(out).not.toContain('#token=');
    // Every token ever seen in a delivered mail must be absent from the logs.
    for (const m of messages) {
      for (const t of decodeQp(m).match(/#token=([A-Za-z0-9_-]{43})/g) ?? []) {
        expect(out).not.toContain(t.slice('#token='.length));
      }
    }
  });
});
