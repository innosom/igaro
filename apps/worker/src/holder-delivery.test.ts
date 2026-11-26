// Unit tests for email.deliver (T-041, ADR 0030): sealed payload, producer, rendering, handler with fakes, config.
// Test values only.
import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import { generateSigningKey, parseMasterKey } from '@igaro/core';
import { createLogger } from './logger.js';
import { ConfigError, loadWorkerConfig } from './config.js';
import {
  HOLDER_DELIVERY_QUEUE,
  HOLDER_DELIVERY_QUEUE_OPTIONS,
  InvalidHolderDeliveryJobError,
  enqueueHolderDelivery,
  holderDeliverySingletonKey,
  openHolderDelivery,
  sealHolderDelivery,
  type HolderDeliveryJob,
} from './holder-delivery-job.js';
import { PgBossHolderDeliveryQueue } from './holder-delivery-producer.js';
import { holderLink, renderHolderMail, runHolderDelivery, HolderDeliveryNotFoundError } from './holder-delivery.js';
import { MailSendError } from './account-mail.js';

const key = randomBytes(32);
const job: HolderDeliveryJob = {
  institutionId: '11111111-1111-4111-8111-111111111111',
  credentialId: '22222222-2222-4222-8222-222222222222',
  to: 'holder@school.test',
  holderToken: randomBytes(16).toString('base64url'),
};

describe('sealed job payload', () => {
  it('round-trips and carries no clear token or address', () => {
    const data = sealHolderDelivery(job, key);
    const json = JSON.stringify(data);
    expect(json).not.toContain(job.holderToken);
    expect(json).not.toContain('school.test');
    expect(Object.keys(data).sort()).toEqual(['credentialId', 'institutionId', 'sealed']);
    expect(openHolderDelivery(data, key)).toEqual(job);
  });

  it('uses a fresh IV each time', () => {
    expect(sealHolderDelivery(job, key).sealed).not.toBe(sealHolderDelivery(job, key).sealed);
  });

  it('refuses the wrong key, tampering and a payload moved to another credential or tenant', () => {
    const data = sealHolderDelivery(job, key);
    expect(() => openHolderDelivery(data, randomBytes(32))).toThrow(InvalidHolderDeliveryJobError);
    const parts = data.sealed.split('.');
    parts[2] = Buffer.from('tampered-ciphertext-bytes').toString('base64url');
    expect(() => openHolderDelivery({ ...data, sealed: parts.join('.') }, key)).toThrow(InvalidHolderDeliveryJobError);
    expect(() => openHolderDelivery({ ...data, credentialId: '33333333-3333-4333-8333-333333333333' }, key)).toThrow(InvalidHolderDeliveryJobError);
    expect(() => openHolderDelivery({ ...data, institutionId: '33333333-3333-4333-8333-333333333333' }, key)).toThrow(InvalidHolderDeliveryJobError);
  });

  it('rejects malformed data with a generic error that carries no payload', () => {
    const data = sealHolderDelivery(job, key);
    for (const bad of [null, 'x', {}, { ...data, sealed: 'v2.a.b.c' }, { ...data, sealed: 42 }, { ...data, credentialId: 'nope' }, { ...data, sealed: 'a'.repeat(3000) }]) {
      try {
        openHolderDelivery(bad, key);
        throw new Error('should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(InvalidHolderDeliveryJobError);
        expect((e as Error).message).toBe('invalid holder delivery job payload');
      }
    }
  });

  it('refuses to seal bad input (CRLF recipient, second address, bad token, bad ids, short key)', () => {
    for (const bad of [
      { ...job, to: 'a@b.test\r\nBcc: x@y.test' },
      { ...job, to: 'a@b.test,c@d.test' },
      { ...job, holderToken: 'short' },
      { ...job, holderToken: `${job.holderToken.slice(0, 21)}/` },
      { ...job, credentialId: 'x' },
    ]) {
      expect(() => sealHolderDelivery(bad, key)).toThrow(InvalidHolderDeliveryJobError);
    }
    expect(() => sealHolderDelivery(job, randomBytes(16))).toThrow();
  });
});

describe('producer', () => {
  it('sends the sealed job with a per-credential singleton key', async () => {
    const calls: { name: string; data: Record<string, unknown>; opts: Record<string, unknown> }[] = [];
    const q = new PgBossHolderDeliveryQueue({ send: async (name, data, opts) => (calls.push({ name, data: data as Record<string, unknown>, opts }), 'id') }, key);
    await q.enqueue(job);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.name).toBe(HOLDER_DELIVERY_QUEUE);
    expect(calls[0]!.opts).toEqual({ singletonKey: holderDeliverySingletonKey(job.credentialId) });
    expect(JSON.stringify(calls[0]!.data)).not.toContain(job.holderToken);
    expect(openHolderDelivery(calls[0]!.data, key)).toEqual(job);
  });

  it('treats a declined duplicate (null id) as success and reports it', async () => {
    expect(await enqueueHolderDelivery({ send: async () => null }, job, key)).toBe(false);
    await expect(new PgBossHolderDeliveryQueue({ send: async () => null }, key).enqueue(job)).resolves.toBeUndefined();
  });

  it('propagates sender errors (the API logs and swallows them)', async () => {
    await expect(new PgBossHolderDeliveryQueue({ send: async () => Promise.reject(new Error('down')) }, key).enqueue(job)).rejects.toThrow('down');
  });

  it('queue options: short policy, backoff retries, completed and failed jobs deleted quickly', () => {
    expect(HOLDER_DELIVERY_QUEUE_OPTIONS).toMatchObject({ policy: 'short', retryBackoff: true, deleteAfterSeconds: 60 });
    expect(HOLDER_DELIVERY_QUEUE_OPTIONS.retryLimit).toBeGreaterThanOrEqual(3);
  });
});

describe('mail rendering', () => {
  it('links to /h/<token> and escapes names', () => {
    const link = holderLink('https://app.igaro.test/', job.holderToken);
    expect(link).toBe(`https://app.igaro.test/h/${job.holderToken}`);
    const m = renderHolderMail({ holderName: 'Ada <b>L</b>', typeName: 'ID "card"', institutionName: 'Uni\r\nBcc: x@y.test', link });
    expect(m.subject).not.toMatch(/[\r\n]/);
    expect(m.html).toContain('Ada &#60;b&#62;L&#60;/b&#62;');
    expect(m.html).not.toContain('<b>L</b>');
    expect(m.text).toContain(link);
    expect(m.html).toContain(`href="${link}"`);
  });
});

describe('handler', () => {
  const lines: string[] = [];
  const logger = createLogger('debug', { write: (s: string) => void lines.push(s) });
  const poolFor = (row: unknown): Pool => {
    const client = { query: async (sql: string) => (/FROM credentials/.test(sql) ? { rows: row ? [row] : [] } : { rows: [] }), release: () => undefined };
    return { connect: async () => client } as unknown as Pool;
  };
  const active = { status: 'ACTIVE', payload: { holder: { fullName: 'Ada Lovelace' } }, type_name: 'Student ID', inst_name: 'Test University' };
  const mk = (row: unknown, sent: unknown[], fail = false) => ({
    pool: poolFor(row),
    transport: { sendMail: async (m: unknown) => (fail ? Promise.reject(new Error(`550 ${job.to} rejected`)) : void sent.push(m)) },
    from: 'iGARO <no-reply@igaro.test>',
    webBaseUrl: 'https://app.igaro.test',
    key,
    logger,
  });

  it('sends the private link to the holder', async () => {
    const sent: { to: string; text: string }[] = [];
    const out = await runHolderDelivery(mk(active, sent) as never, sealHolderDelivery(job, key));
    expect(out).toBe('sent');
    expect(sent[0]!.to).toBe(job.to);
    expect(sent[0]!.text).toContain(`https://app.igaro.test/h/${job.holderToken}`);
    const log = lines.join('');
    expect(log).toContain('holder delivery sent');
    expect(log).not.toContain(job.holderToken);
    expect(log).not.toContain('school.test');
  });

  it('skips credentials that are no longer ACTIVE', async () => {
    const sent: unknown[] = [];
    for (const status of ['REVOKED', 'SUSPENDED', 'SUPERSEDED', 'DRAFT']) {
      expect(await runHolderDelivery(mk({ ...active, status }, sent) as never, sealHolderDelivery(job, key))).toBe('skipped_not_active');
    }
    expect(sent).toHaveLength(0);
  });

  it('retries (throws) when the credential is not visible yet', async () => {
    await expect(runHolderDelivery(mk(undefined, []) as never, sealHolderDelivery(job, key))).rejects.toBeInstanceOf(HolderDeliveryNotFoundError);
  });

  it('turns SMTP failures into a generic retryable error without the recipient', async () => {
    const err = await runHolderDelivery(mk(active, [], true) as never, sealHolderDelivery(job, key)).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(MailSendError);
    expect((err as Error).message).toBe('smtp send failed');
  });

  it('refuses a payload sealed with another key before touching the database', async () => {
    let touched = false;
    const deps = { ...mk(active, []), pool: { connect: async () => ((touched = true), undefined) } as unknown as Pool };
    await expect(runHolderDelivery(deps as never, sealHolderDelivery(job, randomBytes(32)))).rejects.toBeInstanceOf(InvalidHolderDeliveryJobError);
    expect(touched).toBe(false);
  });
});

describe('worker config', () => {
  const base = {
    APP_DATABASE_URL: 'postgresql://igaro_app:pw@127.0.0.1:5432/igaro',
    SMTP_HOST: '127.0.0.1',
    SMTP_FROM: 'no-reply@igaro.test',
    WEB_BASE_URL: 'http://127.0.0.1:3000',
  };
  it('is off without the key outside production and on with it', () => {
    expect(loadWorkerConfig(base).holderDelivery).toBeUndefined();
    const k = randomBytes(32);
    expect(loadWorkerConfig({ ...base, DELIVERY_PAYLOAD_KEY: k.toString('base64') }).holderDelivery?.key.equals(k)).toBe(true);
  });
  it('rejects a bad or placeholder key without echoing it', () => {
    for (const bad of ['short', 'replace-me', randomBytes(16).toString('base64')]) {
      try {
        loadWorkerConfig({ ...base, DELIVERY_PAYLOAD_KEY: bad });
        throw new Error('should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(ConfigError);
        expect((e as Error).message).not.toContain(bad);
      }
    }
  });
  it('production requires the key and the worker login', () => {
    const wrap = randomBytes(32).toString('base64');
    const head = generateSigningKey(parseMasterKey(wrap));
    const prod = {
      ...base,
      NODE_ENV: 'production',
      WEB_BASE_URL: 'https://app.igaro.test',
      WORKER_DATABASE_URL: 'postgresql://igaro_worker:pw@127.0.0.1:5432/igaro',
      AUDIT_HEAD_WRAP_KEY: wrap,
      AUDIT_HEAD_SIGNING_KEY: head.encryptedPrivateKey,
      AUDIT_HEAD_KEY_ID: head.kid,
    };
    expect(() => loadWorkerConfig(prod)).toThrow(/DELIVERY_PAYLOAD_KEY is required/);
    expect(loadWorkerConfig({ ...prod, DELIVERY_PAYLOAD_KEY: randomBytes(32).toString('base64') }).holderDelivery).toBeDefined();
    const { WORKER_DATABASE_URL: _w, ...noWorker } = prod;
    void _w;
    expect(() => loadWorkerConfig({ ...noWorker, DELIVERY_PAYLOAD_KEY: randomBytes(32).toString('base64') })).toThrow(/WORKER_DATABASE_URL/);
  });
});
