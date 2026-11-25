import { describe, expect, it, vi } from 'vitest';
import {
  buildLink,
  createAccountMailHandler,
  MailSendError,
  renderAccountMail,
} from './account-mail.js';
import {
  InvalidAccountMailJobError,
  parseAccountMailJobData,
  toJobData,
  type AccountMailJob,
} from './account-mail-job.js';
import { PgBossAccountMailQueue, retentionFor } from './account-mail-producer.js';
import { ConfigError, loadWorkerConfig } from './config.js';
import { createLogger } from './logger.js';

const TOKEN = 'Tok3n_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abc';
const NOW = new Date('2026-11-25T12:00:00Z');
const later = new Date(NOW.getTime() + 3600_000);
const BASE = 'https://app.igaro.test';

const invite: AccountMailJob = {
  kind: 'INVITE',
  to: 'admin@school.test',
  token: TOKEN,
  expiresAt: later,
  institutionId: '11111111-1111-1111-1111-111111111111',
};
const reset: AccountMailJob = {
  kind: 'PASSWORD_RESET',
  to: 'admin@school.test',
  token: TOKEN,
  expiresAt: later,
};

describe('job contract', () => {
  it('round-trips through JSON', () => {
    const json = JSON.parse(JSON.stringify(toJobData(invite)));
    expect(parseAccountMailJobData(json)).toEqual(invite);
    expect(parseAccountMailJobData(JSON.parse(JSON.stringify(toJobData(reset))))).toEqual(reset);
  });

  it.each([
    null,
    'x',
    {},
    { ...toJobData(invite), kind: 'OTHER' },
    { ...toJobData(invite), to: 'a@b.test\r\nBcc: evil@x.test' },
    { ...toJobData(invite), to: 'a@b.test, c@d.test' },
    { ...toJobData(invite), token: 'short' },
    { ...toJobData(invite), token: `${TOKEN}#x/../` },
    { ...toJobData(invite), expiresAt: 'not a date' },
    { ...toJobData(invite), institutionId: '' },
  ])('rejects malformed payload %#', (data) => {
    expect(() => parseAccountMailJobData(data)).toThrow(InvalidAccountMailJobError);
  });

  it('the validation error does not echo the payload', () => {
    try {
      parseAccountMailJobData({ ...toJobData(invite), token: 'bad token SECRET' });
    } catch (e) {
      expect(String(e)).not.toContain('SECRET');
      expect(String(e)).not.toContain('admin@school.test');
    }
  });
});

describe('rendering', () => {
  it('builds fragment links under a configurable base', () => {
    expect(buildLink(BASE, invite)).toBe(`${BASE}/invite/accept#token=${TOKEN}`);
    expect(buildLink(`${BASE}/`, reset)).toBe(`${BASE}/password-reset#token=${TOKEN}`);
    expect(buildLink(`${BASE}/sub/`, reset)).toBe(`${BASE}/sub/password-reset#token=${TOKEN}`);
  });

  it('renders text and html for both kinds with the link and expiry', () => {
    for (const job of [invite, reset]) {
      const m = renderAccountMail(job, BASE);
      const link = buildLink(BASE, job);
      expect(m.text).toContain(link);
      expect(m.html).toContain(`href="${link}"`);
      expect(m.text).toContain('2026-11-25 13:00:00 UTC');
      expect(m.subject.length).toBeGreaterThan(5);
    }
    expect(renderAccountMail(invite, BASE).subject).toMatch(/invited/);
    expect(renderAccountMail(reset, BASE).subject).toMatch(/Reset/);
  });

  it('escapes html in the link', () => {
    const m = renderAccountMail(reset, 'https://x.test/a"onmouseover="y');
    expect(m.html).not.toContain('"onmouseover=');
  });
});

describe('handler', () => {
  const mk = (sendMail = vi.fn(async (...args: [Record<string, string>]) => ({ args }))) => ({
    sendMail,
    handle: createAccountMailHandler({
      transport: { sendMail } as never,
      from: 'iGARO <no-reply@igaro.test>',
      webBaseUrl: BASE,
      now: () => NOW,
    }),
  });

  it('sends invite and reset mail', async () => {
    const { sendMail, handle } = mk();
    expect(await handle(toJobData(invite))).toBe('sent');
    expect(await handle(toJobData(reset))).toBe('sent');
    expect(sendMail).toHaveBeenCalledTimes(2);
    const arg = sendMail.mock.calls[0]?.[0] as Record<string, string>;
    expect(arg.to).toBe('admin@school.test');
    expect(arg.from).toBe('iGARO <no-reply@igaro.test>');
    expect(arg.text).toContain(`#token=${TOKEN}`);
    expect(arg.html).toContain(TOKEN);
  });

  it('skips and does not send an expired job', async () => {
    const { sendMail, handle } = mk();
    const expired = { ...toJobData(invite), expiresAt: new Date(NOW.getTime() - 1).toISOString() };
    expect(await handle(expired)).toBe('skipped_expired');
    const exactly = { ...toJobData(reset), expiresAt: NOW.toISOString() };
    expect(await handle(exactly)).toBe('skipped_expired');
    expect(sendMail).not.toHaveBeenCalled();
  });

  it('throws a generic error on SMTP failure (no recipient or token in it)', async () => {
    const { handle } = mk(
      vi.fn(async () => {
        throw new Error(`550 mailbox admin@school.test rejected, ${TOKEN}`);
      }),
    );
    const err = await handle(toJobData(invite)).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(MailSendError);
    expect(String(err)).not.toContain('school.test');
    expect(String(err)).not.toContain(TOKEN);
  });

  it('does not send a malformed job', async () => {
    const { sendMail, handle } = mk();
    await expect(handle({ kind: 'INVITE' })).rejects.toBeInstanceOf(InvalidAccountMailJobError);
    expect(sendMail).not.toHaveBeenCalled();
  });
});

describe('producer', () => {
  it('sends the JSON form with retention bounded by token expiry', async () => {
    const send = vi.fn(async () => 'job-1');
    const q = new PgBossAccountMailQueue({ send }, () => NOW);
    await q.enqueue(invite);
    const [name, data, opts] = send.mock.calls[0] as unknown as [string, unknown, { retentionSeconds: number }];
    expect(name).toBe('account.mail');
    expect(data).toEqual(toJobData(invite));
    expect(opts.retentionSeconds).toBe(3600 + 60);
  });

  it('fails loudly if pg-boss declines to create the job', async () => {
    const q = new PgBossAccountMailQueue({ send: async () => null });
    await expect(q.enqueue(reset)).rejects.toThrow('not created');
  });

  it('retentionFor has a floor for already-expired tokens', () => {
    expect(retentionFor(new Date(NOW.getTime() - 99999), NOW)).toBe(60);
  });
});

describe('config', () => {
  const base = {
    APP_DATABASE_URL: 'postgresql://igaro_app:pw@127.0.0.1:5432/igaro',
    SMTP_HOST: '127.0.0.1',
    SMTP_PORT: '1025',
    SMTP_FROM: 'no-reply@igaro.local',
    WEB_BASE_URL: 'http://127.0.0.1:3000/',
  };

  it('loads dev defaults and strips the trailing slash', () => {
    const c = loadWorkerConfig(base);
    expect(c.webBaseUrl).toBe('http://127.0.0.1:3000');
    expect(c.smtp).toMatchObject({ host: '127.0.0.1', port: 1025, secure: false });
    expect(c.pgbossSchema).toBe('pgboss');
    expect(c.databaseUrl).toBe(base.APP_DATABASE_URL);
  });

  it('prefers WORKER_DATABASE_URL and falls back to PUBLIC_WEB_URL', () => {
    const c = loadWorkerConfig({
      ...base,
      WEB_BASE_URL: undefined,
      PUBLIC_WEB_URL: 'http://web.test',
      WORKER_DATABASE_URL: 'postgresql://igaro_worker:pw@h:5432/igaro',
    });
    expect(c.databaseUrl).toContain('igaro_worker');
    expect(c.webBaseUrl).toBe('http://web.test');
  });

  it('rejects bad values without echoing them', () => {
    const bad: Array<Record<string, string | undefined>> = [
      { ...base, APP_DATABASE_URL: undefined },
      { ...base, APP_DATABASE_URL: 'mysql://u:SECRETPW@h/db' },
      { ...base, DATABASE_URL: base.APP_DATABASE_URL },
      { ...base, SMTP_HOST: undefined },
      { ...base, SMTP_PORT: '99999' },
      { ...base, SMTP_FROM: 'a@b.test\r\nBcc: x@y.test' },
      { ...base, WEB_BASE_URL: undefined },
      { ...base, WEB_BASE_URL: 'http://x.test', NODE_ENV: 'production' },
      { ...base, WEB_BASE_URL: 'https://u:SECRETPW@x.test' },
      { ...base, PGBOSS_SCHEMA: 'a;drop' },
      { ...base, NODE_ENV: 'staging' },
    ];
    for (const env of bad) {
      let msg = '';
      try {
        loadWorkerConfig(env);
      } catch (e) {
        expect(e).toBeInstanceOf(ConfigError);
        msg = (e as Error).message;
      }
      expect(msg).not.toBe('');
      expect(msg).not.toContain('SECRETPW');
    }
  });
});

describe('logger', () => {
  it('redacts sensitive keys and never prints error messages', () => {
    const lines: string[] = [];
    const log = createLogger('info', { write: (s: string) => void lines.push(s) });
    log.info({ token: TOKEN, to: 'a@b.test', data: { token: TOKEN }, job: { data: { to: 'x' } } }, 'm');
    log.error({ err: new Error(`boom ${TOKEN}`) }, 'failed');
    const out = lines.join('');
    expect(out).not.toContain(TOKEN);
    expect(out).not.toContain('a@b.test');
    expect(out).toContain('[REDACTED]');
  });
});
