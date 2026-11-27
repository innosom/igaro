import { describe, expect, it, vi } from 'vitest';
import {
  buildLink,
  createAccountMailHandler,
  MailSendError,
  renderAccountMail,
} from './account-mail.js';
import { randomBytes } from 'node:crypto';
import {
  InvalidAccountMailJobError,
  openAccountMailJobData,
  sealAccountMail,
  type AccountMailJob,
} from './account-mail-job.js';
import { PgBossAccountMailQueue, retentionFor } from './account-mail-producer.js';
import { ConfigError, loadWorkerConfig } from './config.js';
import { createLogger } from './logger.js';
import { parsePgbossSchemaMode } from './pgboss-mode.js';

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

const KEY = Buffer.alloc(32, 7);
const seal = (j: AccountMailJob, key = KEY) => sealAccountMail(j, key);

describe('job contract (sealed, ADR 0038)', () => {
  it('round-trips through JSON', () => {
    expect(openAccountMailJobData(JSON.parse(JSON.stringify(seal(invite))), KEY)).toEqual(invite);
    expect(openAccountMailJobData(JSON.parse(JSON.stringify(seal(reset))), KEY)).toEqual(reset);
  });

  it('the stored form holds neither the token nor the recipient', () => {
    for (const j of [invite, reset]) {
      const text = JSON.stringify(seal(j));
      expect(text).not.toContain(TOKEN);
      expect(text).not.toContain('admin@school.test');
      expect(text).not.toContain('school.test');
    }
    // Two seals of the same job differ (random IV and reference).
    expect(seal(invite)).not.toEqual(seal(invite));
  });

  it('rejects a wrong key', () => {
    expect(() => openAccountMailJobData(seal(invite), randomBytes(32))).toThrow(InvalidAccountMailJobError);
  });

  it('rejects any moved or edited routing field (AAD binding)', () => {
    const s = seal(invite) as Record<string, string>;
    const other = seal(invite) as Record<string, string>;
    const cases = [
      { ...s, kind: 'PASSWORD_RESET' },
      { ...s, institutionId: '22222222-2222-2222-2222-222222222222' },
      { ...s, expiresAt: new Date(NOW.getTime() + 999_000).toISOString() },
      { ...s, ref: other.ref },
      { ...s, sealed: other.sealed },
      { ...s, sealed: `${s.sealed}x` },
    ];
    for (const c of cases) expect(() => openAccountMailJobData(c, KEY)).toThrow(InvalidAccountMailJobError);
  });

  it('refuses the old clear-text job form', () => {
    const legacy = { kind: 'INVITE', to: 'admin@school.test', token: TOKEN, expiresAt: later.toISOString(), institutionId: invite.kind === 'INVITE' ? invite.institutionId : '' };
    expect(() => openAccountMailJobData(legacy, KEY)).toThrow(InvalidAccountMailJobError);
  });

  it.each([
    null,
    'x',
    {},
    { ...seal(invite), kind: 'OTHER' },
    { ...seal(invite), ref: 'nope' },
    { ...seal(invite), expiresAt: 'not a date' },
    { ...seal(invite), institutionId: '' },
    { ...seal(invite), sealed: 'v2.a.b.c' },
    { ...seal(invite), sealed: 'v1.a.b' },
  ])('rejects malformed payload %#', (data) => {
    expect(() => openAccountMailJobData(data, KEY)).toThrow(InvalidAccountMailJobError);
  });

  it('refuses to seal a bad recipient, token, institution or key', () => {
    for (const bad of [
      { ...invite, to: 'a@b.test\r\nBcc: evil@x.test' },
      { ...invite, to: 'a@b.test, c@d.test' },
      { ...invite, token: 'short' },
      { ...invite, token: `${TOKEN}#x/../` },
      { ...invite, institutionId: 'x' },
      { ...invite, expiresAt: new Date('nope') },
    ] as AccountMailJob[]) {
      expect(() => seal(bad)).toThrow(InvalidAccountMailJobError);
    }
    expect(() => seal(invite, Buffer.alloc(16))).toThrow();
  });

  it('the validation error does not echo the payload', () => {
    try {
      openAccountMailJobData({ ...seal(invite), sealed: 'bad token SECRET' }, KEY);
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
      key: KEY,
      now: () => NOW,
    }),
  });

  it('sends invite and reset mail', async () => {
    const { sendMail, handle } = mk();
    expect(await handle(seal(invite))).toBe('sent');
    expect(await handle(seal(reset))).toBe('sent');
    expect(sendMail).toHaveBeenCalledTimes(2);
    const arg = sendMail.mock.calls[0]?.[0] as Record<string, string>;
    expect(arg.to).toBe('admin@school.test');
    expect(arg.from).toBe('iGARO <no-reply@igaro.test>');
    expect(arg.text).toContain(`#token=${TOKEN}`);
    expect(arg.html).toContain(TOKEN);
  });

  it('skips and does not send an expired job', async () => {
    const { sendMail, handle } = mk();
    const expired = seal({ ...invite, expiresAt: new Date(NOW.getTime() - 1) });
    expect(await handle(expired)).toBe('skipped_expired');
    const exactly = seal({ ...reset, expiresAt: NOW });
    expect(await handle(exactly)).toBe('skipped_expired');
    expect(sendMail).not.toHaveBeenCalled();
  });

  it('throws a generic error on SMTP failure (no recipient or token in it)', async () => {
    const { handle } = mk(
      vi.fn(async () => {
        throw new Error(`550 mailbox admin@school.test rejected, ${TOKEN}`);
      }),
    );
    const err = await handle(seal(invite)).catch((e: unknown) => e);
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
  it('sends the sealed form with retention bounded by token expiry', async () => {
    const send = vi.fn(async () => 'job-1');
    const q = new PgBossAccountMailQueue({ send }, KEY, () => NOW);
    await q.enqueue(invite);
    const [name, data, opts] = send.mock.calls[0] as unknown as [string, object, { retentionSeconds: number }];
    expect(name).toBe('account.mail');
    expect(JSON.stringify(data)).not.toContain(TOKEN);
    expect(JSON.stringify(data)).not.toContain('school.test');
    expect(openAccountMailJobData(data, KEY)).toEqual(invite);
    expect(opts.retentionSeconds).toBe(3600 + 60);
  });

  it('fails loudly if pg-boss declines to create the job', async () => {
    const q = new PgBossAccountMailQueue({ send: async () => null }, KEY);
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
    expect(c.pgbossSchemaMode).toBe('auto');
    expect(c.databaseUrl).toBe(base.APP_DATABASE_URL);
  });

  it('schema mode: external by default in production, explicit value wins', () => {
    expect(parsePgbossSchemaMode(undefined, 'production')).toBe('external');
    expect(parsePgbossSchemaMode('', 'development')).toBe('auto');
    expect(parsePgbossSchemaMode('auto', 'production')).toBe('auto');
    expect(loadWorkerConfig({ ...base, PGBOSS_SCHEMA_MODE: 'external' }).pgbossSchemaMode).toBe('external');
    expect(() => loadWorkerConfig({ ...base, PGBOSS_SCHEMA_MODE: 'yes' })).toThrow(ConfigError);
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
