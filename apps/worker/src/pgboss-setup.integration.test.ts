// Integration for the pre-created pg-boss schema with enqueue-only grants (T-051, ADR 0038). Real Postgres
// ($DATABASE_URL, scratch schema), real pg-boss, an in-process SMTP server. The API and the worker connect as login roles
// that are members of igaro_app and igaro_worker, so they carry exactly the privileges of those roles.
// Skipped without DATABASE_URL. Test values only.
import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import { SMTPServer } from 'smtp-server';
import { createTransport } from 'nodemailer';
import { createHarness, hasDatabase, type Harness } from '@igaro/db/testing';
import { ACCOUNT_MAIL_QUEUE } from './account-mail-job.js';
import { connectProducerQueues, type ConnectedProducerQueues } from './card-render-producer.js';
import { createLogger } from './logger.js';
import { setupPgbossSchema } from './pgboss-setup.js';
import { startWorker, type WorkerHandle } from './worker.js';

const url = process.env.DATABASE_URL as string;

const decodeQp = (s: string): string =>
  s.replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/g, (_m, h: string) => String.fromCharCode(parseInt(h, 16)));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function waitFor(cond: () => boolean | Promise<boolean>, ms = 20000): Promise<void> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await cond()) return;
    await sleep(100);
  }
  throw new Error('timed out waiting for condition');
}
const urlFor = (user: string, password: string): string => {
  const u = new URL(url);
  u.username = user;
  u.password = password;
  return u.toString();
};
const sqlState = async (p: Promise<unknown>): Promise<string | undefined> => {
  try {
    await p;
    return undefined;
  } catch (e) {
    return (e as { code?: string }).code;
  }
};

describe.skipIf(!hasDatabase)('pre-created pg-boss schema, enqueue-only API role (needs Postgres at DATABASE_URL)', () => {
  const tag = randomBytes(4).toString('hex');
  const schema = `pgboss_t051_${tag}`;
  const wLogin = `t051_w_${tag}`;
  const aLogin = `t051_a_${tag}`;
  const pw = randomBytes(12).toString('hex');
  const key = randomBytes(32);
  const messages: string[] = [];
  const logLines: string[] = [];
  let h: Harness;
  let admin: pg.Client;
  let apiClient: pg.Client;
  let smtp: SMTPServer;
  let smtpPort = 0;
  let producer: ConnectedProducerQueues;
  let worker: WorkerHandle | undefined;
  let sent = { t1: '', t2: '' };
  const token = () => randomBytes(32).toString('base64url');

  beforeAll(async () => {
    // Applies every migration, which creates the global igaro_app and igaro_worker roles.
    h = await createHarness('t051');
    admin = new pg.Client({ connectionString: url });
    await admin.connect();
    await admin.query(`CREATE ROLE "${wLogin}" LOGIN PASSWORD '${pw}' IN ROLE igaro_worker`);
    await admin.query(`CREATE ROLE "${aLogin}" LOGIN PASSWORD '${pw}' IN ROLE igaro_app`);
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

    await setupPgbossSchema({ ownerUrl: url, schema });
    producer = await connectProducerQueues({
      connectionString: urlFor(aLogin, pw),
      schema,
      deliveryKey: key,
      schemaMode: 'external',
    });
    apiClient = new pg.Client({ connectionString: urlFor(aLogin, pw) });
    await apiClient.connect();
  }, 90000);

  afterAll(async () => {
    await producer?.stop();
    await worker?.stop();
    await apiClient?.end();
    await admin?.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    await admin?.query(`DROP ROLE IF EXISTS "${wLogin}"`);
    await admin?.query(`DROP ROLE IF EXISTS "${aLogin}"`);
    await admin?.end();
    await new Promise<void>((r) => smtp?.close(() => r()));
    await h?.close();
  }, 60000);

  it('setup is idempotent', async () => {
    await setupPgbossSchema({ ownerUrl: url, schema });
  }, 60000);

  it('T-053: setup refuses a schema pre-created by the API role, and one with an API-owned table', async () => {
    const evil = `pgboss_t053_${tag}`;
    await admin.query(`GRANT CREATE ON DATABASE "${new URL(url).pathname.slice(1)}" TO igaro_app`);
    try {
      await admin.query(`CREATE SCHEMA "${evil}" AUTHORIZATION igaro_app`);
      await expect(setupPgbossSchema({ ownerUrl: url, schema: evil })).rejects.toThrow(/not the migrator/);
      await admin.query(`ALTER SCHEMA "${evil}" OWNER TO CURRENT_USER`);
      await admin.query(`GRANT CREATE ON SCHEMA "${evil}" TO igaro_app`);
      await admin.query(`CREATE TABLE "${evil}".sneaky (id int)`);
      await admin.query(`ALTER TABLE "${evil}".sneaky OWNER TO igaro_app`);
      await expect(setupPgbossSchema({ ownerUrl: url, schema: evil })).rejects.toThrow(/not owned by the migrator/);
    } finally {
      await admin.query(`DROP SCHEMA IF EXISTS "${evil}" CASCADE`);
    }
  }, 60000);

  it('T-053: the API queue role passes the queue role check; the worker login does not', async () => {
    const { checkQueueRole } = await import('@igaro/db');
    expect(await checkQueueRole(apiClient, { schema })).toEqual([]);
    const w = new pg.Client({ connectionString: urlFor(wLogin, pw) });
    await w.connect();
    try {
      const problems = await checkQueueRole(w, { schema });
      expect(problems.join(';')).toContain('igaro_worker');
      expect(problems.join(';')).toContain('SELECT job data');
    } finally {
      await w.end();
    }
  }, 30000);

  it('an external-mode producer fails instead of creating a missing schema', async () => {
    const missing = `pgboss_t051_missing_${tag}`;
    await expect(
      connectProducerQueues({ connectionString: urlFor(aLogin, pw), schema: missing, deliveryKey: key, schemaMode: 'external' }),
    ).rejects.toBeDefined();
    const r = await admin.query(`SELECT 1 FROM pg_namespace WHERE nspname = $1`, [missing]);
    expect(r.rowCount).toBe(0);
  }, 30000);

  it('the API role can enqueue, and no job row holds a token or an address', async () => {
    const t1 = token();
    const t2 = token();
    const exp = new Date(Date.now() + 3600_000);
    await producer.accountMail!.enqueue({ kind: 'INVITE', to: 'e2e-invite@school.test', token: t1, expiresAt: exp, institutionId: '44444444-4444-4444-8444-444444444444' });
    await producer.accountMail!.enqueue({ kind: 'PASSWORD_RESET', to: 'e2e-reset@school.test', token: t2, expiresAt: exp });
    const rows = await admin.query(`SELECT j::text AS row FROM "${schema}".job j WHERE name = $1`, [ACCOUNT_MAIL_QUEUE]);
    expect(rows.rows).toHaveLength(2);
    for (const r of rows.rows as { row: string }[]) {
      expect(r.row).not.toContain(t1);
      expect(r.row).not.toContain(t2);
      expect(r.row).not.toContain('school.test');
      expect(r.row).toContain('sealed');
    }
    sent = { t1, t2 };
  }, 30000);

  it('the API role cannot read, change, delete or create anything else in the schema', async () => {
    const s = `"${schema}"`;
    for (const col of ['data', 'output', 'singleton_key', 'state', 'name', '*']) {
      expect(await sqlState(apiClient.query(`SELECT ${col} FROM ${s}.job`))).toBe('42501');
      expect(await sqlState(apiClient.query(`SELECT ${col} FROM ${s}.job_common`))).toBe('42501');
    }
    // Known and accepted: the id column is readable (random UUIDs), so count(*) works. No job content is.
    expect(await sqlState(apiClient.query(`SELECT id FROM ${s}.job LIMIT 1`))).toBeUndefined();
    expect(await sqlState(apiClient.query(`UPDATE ${s}.job SET data = '{}'`))).toBe('42501');
    expect(await sqlState(apiClient.query(`DELETE FROM ${s}.job`))).toBe('42501');
    expect(await sqlState(apiClient.query(`TRUNCATE ${s}.job`))).toBe('42501');
    expect(await sqlState(apiClient.query(`SELECT * FROM ${s}.job_common`))).toBe('42501');
    expect(await sqlState(apiClient.query(`UPDATE ${s}.queue SET policy = 'standard'`))).toBe('42501');
    expect(await sqlState(apiClient.query(`DELETE FROM ${s}.queue`))).toBe('42501');
    expect(await sqlState(apiClient.query(`SELECT * FROM ${s}.schedule`))).toBe('42501');
    expect(await sqlState(apiClient.query(`SELECT ${s}.create_queue('x', '{}'::jsonb)`))).toBe('42501');
    expect(await sqlState(apiClient.query(`SELECT ${s}.delete_queue('${ACCOUNT_MAIL_QUEUE}')`))).toBe('42501');
    expect(await sqlState(apiClient.query(`CREATE TABLE ${s}.evil (a int)`))).toBe('42501');
    // What it does need.
    expect(await sqlState(apiClient.query(`SELECT name FROM ${s}.queue`))).toBeUndefined();
  }, 30000);

  it('a worker in external mode (igaro_worker rights only) delivers the mail from the sealed job', async () => {
    const logger = createLogger('debug', { write: (s: string) => void logLines.push(s) });
    worker = await startWorker({
      databaseUrl: urlFor(wLogin, pw),
      schema,
      schemaMode: 'external',
      logger,
      pollingIntervalSeconds: 0.5,
      mail: {
        transport: createTransport({ host: '127.0.0.1', port: smtpPort, secure: false, ignoreTLS: true }),
        from: 'iGARO <no-reply@igaro.test>',
        webBaseUrl: 'https://app.igaro.test',
        key,
      },
    });
    await waitFor(() => messages.length >= 2);
    const { t1, t2 } = sent;
    const all = messages.map(decodeQp).join('\n----\n');
    expect(all).toContain(`https://app.igaro.test/invite/accept#token=${t1}`);
    expect(all).toContain(`https://app.igaro.test/password-reset#token=${t2}`);
    expect(all).toContain('To: e2e-invite@school.test');
    expect(all).toContain('To: e2e-reset@school.test');
    // Nothing the worker logged contains a token, an address or the sealed blob.
    const out = logLines.join('');
    expect(out).not.toContain(t1);
    expect(out).not.toContain(t2);
    expect(out).not.toContain('school.test');
    expect(out).not.toContain('sealed');
  }, 60000);

  it('the worker role still cannot touch tenant tables beyond its grants (unchanged)', async () => {
    const w = new pg.Client({ connectionString: urlFor(wLogin, pw) });
    await w.connect();
    try {
      expect(await sqlState(w.query(`DELETE FROM ${h.schema}.audit_logs`))).toBe('42501');
    } finally {
      await w.end();
    }
  }, 30000);
});
