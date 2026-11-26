// Integration for email.deliver (T-041, ADR 0030): real pg-boss and Postgres ($DATABASE_URL, scratch schema,
// igaro_worker role with RLS), an in-process fake SMTP server (Mailpit is not needed), the producer sealing the job.
// Skipped without DATABASE_URL. Test values only.
import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import { SMTPServer } from 'smtp-server';
import { createTransport } from 'nodemailer';
import { createHarness, hasDatabase, type Harness } from '@igaro/db/testing';
import { connectProducerQueues, type ConnectedProducerQueues } from './card-render-producer.js';
import { HOLDER_DELIVERY_QUEUE, sealHolderDelivery } from './holder-delivery-job.js';
import { createLogger } from './logger.js';
import { startWorker, type WorkerHandle } from './worker.js';

const url = process.env.DATABASE_URL;

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

describe.skipIf(!hasDatabase)('email.deliver via pg-boss (needs Postgres at DATABASE_URL)', () => {
  const schema = `pgboss_t041_${randomBytes(4).toString('hex')}`;
  const idleSchema = `pgboss_t041i_${randomBytes(4).toString('hex')}`;
  const key = randomBytes(32);
  const messages: string[] = [];
  const logLines: string[] = [];
  let failSmtp = false;
  let smtp: SMTPServer;
  let h: Harness;
  let pool: pg.Pool;
  let admin: pg.Client;
  let worker: WorkerHandle;
  let producer: ConnectedProducerQueues;
  let idleProducer: ConnectedProducerQueues;

  async function addCredential(status: 'ACTIVE' | 'DRAFT'): Promise<string> {
    const id = h.uid();
    const t = h.A;
    const payload = {
      schemaVersion: 'igaro.credential.v1',
      credentialId: id,
      credentialNumber: `IG-${id.slice(-6)}`,
      institutionId: t.institutionId,
      issuerKeyId: t.kid,
      credentialType: 'STUDENT_ID',
      holder: { fullName: 'Ada <b>Lovelace</b>', externalId: 'S-1001', photoSha256: 'a'.repeat(64) },
      attributes: {},
      issuedAt: '2026-11-26T10:00:00Z',
      expiresAt: null,
      salt: randomBytes(32).toString('base64url'),
    };
    await h.owner.query('BEGIN');
    try {
      await h.owner.query(
        `INSERT INTO credentials (id, institution_id, holder_id, type_id, credential_number, status, payload, data_hash,
           issuer_kid, signature, verification_token, holder_token_hash, issued_at, updated_at)
         VALUES ($1,$2,$3,$4,$9,$5,$6,'h',$7,'s',$8,$10,now(),now())`,
        [id, t.institutionId, t.holderId, t.typeId, status, JSON.stringify(payload), t.kid, randomBytes(16).toString('base64url'), `IG-${id.slice(-6)}`, `hh-${id}`],
      );
      if (status === 'ACTIVE') {
        await h.owner.query(`INSERT INTO credential_events (id, institution_id, credential_id, type) VALUES ($1,$2,$3,'ISSUED')`, [h.uid(), t.institutionId, id]);
      }
      await h.owner.query('COMMIT');
    } catch (e) {
      await h.owner.query('ROLLBACK');
      throw e;
    }
    return id;
  }
  const newToken = () => randomBytes(16).toString('base64url');
  const jobRows = async (sch: string, credentialId: string) =>
    (await admin.query(`SELECT state, retry_count, data FROM "${sch}".job WHERE name = $1 AND singleton_key = $2`, [HOLDER_DELIVERY_QUEUE, `email.deliver:${credentialId}`])).rows as {
      state: string;
      retry_count: number;
      data: unknown;
    }[];

  beforeAll(async () => {
    h = await createHarness('t041');
    pool = new pg.Pool({ connectionString: url, options: `-c search_path=${h.schema}`, max: 3 });
    admin = new pg.Client({ connectionString: url });
    await admin.connect();
    smtp = new SMTPServer({
      authOptional: true,
      disabledCommands: ['STARTTLS'],
      onData(stream, _session, cb) {
        const chunks: Buffer[] = [];
        stream.on('data', (c: Buffer) => chunks.push(c));
        stream.on('end', () => {
          if (failSmtp) return cb(new Error('451 try later'));
          messages.push(Buffer.concat(chunks).toString('utf8'));
          cb();
        });
      },
    });
    await new Promise<void>((r) => smtp.listen(0, '127.0.0.1', r));
    const smtpPort = (smtp.server.address() as { port: number }).port;
    const logger = createLogger('debug', { write: (s: string) => void logLines.push(s) });
    worker = await startWorker({
      databaseUrl: url as string,
      schema,
      logger,
      pollingIntervalSeconds: 0.5,
      mail: {
        transport: createTransport({ host: '127.0.0.1', port: smtpPort, secure: false, ignoreTLS: true }),
        from: 'iGARO <no-reply@igaro.test>',
        webBaseUrl: 'https://app.igaro.test',
      },
      holderDelivery: { pool, key, assumeRole: 'igaro_worker' },
    });
    producer = await connectProducerQueues({ connectionString: url as string, schema, deliveryKey: key });
    // A producer on a schema with no worker: jobs stay queued, so duplicates can be observed.
    idleProducer = await connectProducerQueues({ connectionString: url as string, schema: idleSchema, deliveryKey: key });
  }, 90000);

  afterAll(async () => {
    await producer?.stop();
    await idleProducer?.stop();
    await worker?.stop();
    await admin?.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    await admin?.query(`DROP SCHEMA IF EXISTS "${idleSchema}" CASCADE`);
    await admin?.end();
    await new Promise<void>((r) => smtp?.close(() => r()));
    // worker.stop() already ended `pool` (it owns the holder delivery pool).
    await h?.close();
  }, 60000);

  it('emails the private /h/<token> link, then removes the job (and its sealed token) from the queue', async () => {
    const credentialId = await addCredential('ACTIVE');
    const holderToken = newToken();
    await producer.holderDelivery!.enqueue({ institutionId: h.A.institutionId, credentialId, to: 'holder@school.test', holderToken });
    await waitFor(() => messages.some((m) => decodeQp(m).includes(holderToken)));
    const mail = decodeQp(messages.find((m) => decodeQp(m).includes(holderToken))!);
    expect(mail).toContain(`https://app.igaro.test/h/${holderToken}`);
    expect(mail).toContain('To: holder@school.test');
    expect(mail).toContain('Content-Type: text/plain');
    expect(mail).toContain('Content-Type: text/html');
    expect(mail).toContain('Ada &#60;b&#62;Lovelace&#60;/b&#62;');
    await waitFor(async () => (await jobRows(schema, credentialId)).length === 0);
  }, 40000);

  it('keeps no clear token or address in the job table while queued', async () => {
    const credentialId = await addCredential('ACTIVE');
    const holderToken = newToken();
    await idleProducer.holderDelivery!.enqueue({ institutionId: h.A.institutionId, credentialId, to: 'queued@school.test', holderToken });
    const rows = await jobRows(idleSchema, credentialId);
    expect(rows).toHaveLength(1);
    const raw = JSON.stringify(rows[0]!.data);
    expect(raw).not.toContain(holderToken);
    expect(raw).not.toContain('school.test');
  });

  it('is idempotent per credential: a second enqueue while one is queued creates no second job', async () => {
    const credentialId = await addCredential('ACTIVE');
    const job = { institutionId: h.A.institutionId, credentialId, to: 'dup@school.test', holderToken: newToken() };
    await idleProducer.holderDelivery!.enqueue(job);
    await idleProducer.holderDelivery!.enqueue({ ...job, holderToken: newToken() });
    expect(await jobRows(idleSchema, credentialId)).toHaveLength(1);
  });

  it('does not mail a credential that is not ACTIVE, and completes the job', async () => {
    const before = messages.length;
    const credentialId = await addCredential('DRAFT');
    const holderToken = newToken();
    await producer.holderDelivery!.enqueue({ institutionId: h.A.institutionId, credentialId, to: 'draft@school.test', holderToken });
    await waitFor(() => logLines.some((l) => l.includes('skipped_not_active')));
    await sleep(500);
    expect(messages.slice(before).map(decodeQp).join('')).not.toContain(holderToken);
  }, 40000);

  it('is tenant scoped: a job naming another institution finds no credential and sends nothing', async () => {
    const before = messages.length;
    const credentialId = await addCredential('ACTIVE');
    const holderToken = newToken();
    await producer.holderDelivery!.enqueue({ institutionId: h.B.institutionId, credentialId, to: 'cross@school.test', holderToken });
    await waitFor(async () => (await jobRows(schema, credentialId)).some((r) => r.retry_count >= 1 || r.state === 'retry'));
    expect(messages.length).toBe(before);
  }, 40000);

  it('retries with backoff when SMTP fails, without leaking the recipient or token', async () => {
    failSmtp = true;
    const credentialId = await addCredential('ACTIVE');
    const holderToken = newToken();
    await producer.holderDelivery!.enqueue({ institutionId: h.A.institutionId, credentialId, to: 'retry@school.test', holderToken });
    await waitFor(async () => (await jobRows(schema, credentialId)).some((r) => r.state === 'retry'));
    failSmtp = false;
    const out = await admin.query(`SELECT output FROM "${schema}".job WHERE name = $1 AND singleton_key = $2`, [HOLDER_DELIVERY_QUEUE, `email.deliver:${credentialId}`]);
    const stored = JSON.stringify(out.rows[0]);
    expect(stored).not.toContain('retry@school.test');
    expect(stored).not.toContain(holderToken);
  }, 40000);

  it('drops a payload sealed with another key instead of retrying it', async () => {
    const before = messages.length;
    const credentialId = await addCredential('ACTIVE');
    const data = sealHolderDelivery(
      { institutionId: h.A.institutionId, credentialId, to: 'wrongkey@school.test', holderToken: newToken() },
      randomBytes(32),
    );
    // The producer always uses the right key, so put the job on the queue with the worker's own pg-boss handle.
    await worker.boss.send(HOLDER_DELIVERY_QUEUE, data, { singletonKey: `email.deliver:${credentialId}` });
    await waitFor(() => logLines.some((l) => l.includes('invalid job dropped')));
    expect((await jobRows(schema, credentialId)).every((r) => r.retry_count === 0 && r.state !== 'retry')).toBe(true);
    expect(messages.length).toBe(before);
  }, 40000);

  it('never logs tokens, recipients, links or sealed payloads', () => {
    const out = logLines.join('');
    expect(out).toContain('holder delivery job done');
    expect(out).not.toMatch(/school\.test/);
    expect(out).not.toContain('/h/');
    for (const m of messages) {
      for (const t of decodeQp(m).match(/\/h\/([A-Za-z0-9_-]{22})/g) ?? []) {
        expect(out).not.toContain(t.slice('/h/'.length));
      }
    }
    expect(out).not.toContain('v1.');
  });
});
