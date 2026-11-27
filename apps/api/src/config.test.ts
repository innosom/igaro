import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig } from './config.js';

const good = {
  APP_DATABASE_URL: 'postgresql://igaro_app:s3cret-pw@127.0.0.1:5432/igaro',
  NODE_ENV: 'test',
};
const key = Buffer.alloc(32, 7).toString('base64');

describe('loadConfig', () => {
  it('parses a valid environment with defaults', () => {
    const c = loadConfig(good);
    expect(c.port).toBe(4000);
    expect(c.masterKey).toBeUndefined();
    expect(c.cookie).toMatchObject({ secure: false, sameSite: 'lax' });
  });

  it('accepts INTERNAL_API_TOKEN (T-044, ADR 0034) and refuses short, spaced, placeholder and master-key values', () => {
    expect(loadConfig(good).internalApiToken).toBeUndefined();
    const t = 'x7Kq'.repeat(10);
    expect(loadConfig({ ...good, INTERNAL_API_TOKEN: t }).internalApiToken).toBe(t);
    for (const bad of ['short', `${t} ${t}`, 'replace-me-'.padEnd(40, 'x'), 'a'.repeat(513)]) {
      expect(() => loadConfig({ ...good, INTERNAL_API_TOKEN: bad })).toThrow(/INTERNAL_API_TOKEN/);
    }
    const mk = Buffer.alloc(32, 9).toString('base64');
    expect(() => loadConfig({ ...good, MASTER_KEY: mk, INTERNAL_API_TOKEN: mk })).toThrow(/differ from MASTER_KEY/);
    try {
      loadConfig({ ...good, INTERNAL_API_TOKEN: 'short' });
    } catch (e) {
      expect(String((e as Error).message)).not.toContain('short-secret');
    }
  });

  it('defaults account mail to the no-op and selects pg-boss on request (ADR 0006)', () => {
    expect(loadConfig(good).accountMail).toEqual({ driver: 'noop' });
    expect(loadConfig({ ...good, ACCOUNT_MAIL_QUEUE: 'pgboss' }).accountMail).toEqual({
      driver: 'pgboss',
      databaseUrl: good.APP_DATABASE_URL,
      schema: undefined,
      schemaMode: 'auto',
    });
    const w = 'postgresql://igaro_worker:pw@127.0.0.1:5432/igaro';
    expect(
      loadConfig({ ...good, ACCOUNT_MAIL_QUEUE: 'pgboss', WORKER_DATABASE_URL: w, PGBOSS_SCHEMA: 'q' })
        .accountMail,
    ).toEqual({ driver: 'pgboss', databaseUrl: w, schema: 'q', schemaMode: 'auto' });
    // ADR 0038: an explicit mode wins.
    expect(
      loadConfig({ ...good, ACCOUNT_MAIL_QUEUE: 'pgboss', PGBOSS_SCHEMA_MODE: 'external' }).accountMail,
    ).toMatchObject({ schemaMode: 'external' });
    for (const bad of [
      { ACCOUNT_MAIL_QUEUE: 'pgboss', PGBOSS_SCHEMA_MODE: 'yes' },
      { ACCOUNT_MAIL_QUEUE: 'redis' },
      { ACCOUNT_MAIL_QUEUE: 'pgboss', PGBOSS_SCHEMA: 'x;drop' },
      { ACCOUNT_MAIL_QUEUE: 'pgboss', WORKER_DATABASE_URL: 'not a url' },
      { ACCOUNT_MAIL_QUEUE: 'pgboss', WORKER_DATABASE_URL: w, DATABASE_URL: w },
    ]) {
      expect(() => loadConfig({ ...good, ...bad })).toThrow(ConfigError);
    }
  });

  it('reads rate limits and token lifetimes from the environment, with safe defaults', () => {
    const d = loadConfig(good);
    expect(d.rateLimit.login).toEqual({ ipMax: 30, accountMax: 5, windowSeconds: 900 });
    expect(d.tokenTtl).toEqual({ inviteSeconds: 72 * 3600, resetSeconds: 3600 });
    const c = loadConfig({
      ...good,
      RATE_LIMIT_LOGIN_IP_MAX: '7',
      RATE_LIMIT_LOGIN_ACCOUNT_MAX: '2',
      RATE_LIMIT_RESET_ACCOUNT_MAX: '9',
      RATE_LIMIT_TOKEN_WINDOW_SECONDS: '60',
      INVITE_TTL_HOURS: '24',
      RESET_TTL_MINUTES: '30',
    });
    expect(c.rateLimit.login).toMatchObject({ ipMax: 7, accountMax: 2 });
    expect(c.rateLimit.reset.accountMax).toBe(9);
    expect(c.rateLimit.token.windowSeconds).toBe(60);
    expect(c.tokenTtl).toEqual({ inviteSeconds: 24 * 3600, resetSeconds: 1800 });
    for (const bad of ['0', '-1', 'abc', '1.5']) {
      expect(() => loadConfig({ ...good, RATE_LIMIT_LOGIN_IP_MAX: bad })).toThrow(ConfigError);
    }
    expect(() => loadConfig({ ...good, RESET_TTL_MINUTES: '1' })).toThrow(ConfigError);
  });

  it('requires APP_DATABASE_URL and never echoes its value', () => {
    expect(() => loadConfig({ NODE_ENV: 'test' })).toThrow(ConfigError);
    try {
      loadConfig({ ...good, APP_DATABASE_URL: 'mysql://u:topsecret@h/db' });
    } catch (e) {
      expect(String(e)).not.toContain('topsecret');
    }
  });

  it.each(['postgres', 'igaro', 'root'])('refuses superuser/owner-style user %s', (u) => {
    expect(() =>
      loadConfig({ ...good, APP_DATABASE_URL: `postgresql://${u}:pw@127.0.0.1/igaro` }),
    ).toThrow(/restricted igaro_app/);
  });

  it('refuses placeholders and the owner URL', () => {
    expect(() =>
      loadConfig({ ...good, APP_DATABASE_URL: 'postgresql://igaro_app:REPLACE_ME@h/db' }),
    ).toThrow(/placeholder/);
    expect(() => loadConfig({ ...good, DATABASE_URL: good.APP_DATABASE_URL })).toThrow(/differ/);
  });

  it('validates MASTER_KEY as 32 bytes', () => {
    expect(loadConfig({ ...good, MASTER_KEY: key }).masterKey?.length).toBe(32);
    expect(() => loadConfig({ ...good, MASTER_KEY: 'c2hvcnQ=' })).toThrow(/32 bytes/);
    expect(() => loadConfig({ ...good, MASTER_KEY: 'REPLACE_ME_generate_with_openssl' })).toThrow(
      /placeholder/,
    );
  });

  it('validates PORT and NODE_ENV', () => {
    expect(() => loadConfig({ ...good, PORT: '99999' })).toThrow(/PORT/);
    expect(() => loadConfig({ ...good, PORT: 'abc' })).toThrow(/PORT/);
    expect(() => loadConfig({ ...good, NODE_ENV: 'staging' })).toThrow(/NODE_ENV/);
  });

  it('is strict in production', () => {
    const prod = { ...good, NODE_ENV: 'production' };
    expect(() => loadConfig(prod)).toThrow(/MASTER_KEY is required/);
    expect(() => loadConfig({ ...prod, MASTER_KEY: key, COOKIE_SECURE: 'false' })).toThrow(
      /COOKIE_SECURE/,
    );
    const pub = 'A'.repeat(43);
    expect(() => loadConfig({ ...prod, MASTER_KEY: key, IP_HASH_KEY: key })).toThrow(/AUDIT_HEAD_PUBLIC_KEYS is required/);
    expect(
      loadConfig({ ...prod, MASTER_KEY: key, IP_HASH_KEY: key, AUDIT_HEAD_PUBLIC_KEYS: `k1:${pub}`, TRUST_PROXY: '1' }).cookie.secure,
    ).toBe(true);
  });

  it('hashes IPs with IP_HASH_KEY (ADR 0003), required in production', () => {
    expect(loadConfig(good).ipHashKey).toHaveLength(32);
    const k = Buffer.alloc(32, 9).toString('base64');
    expect(loadConfig({ ...good, IP_HASH_KEY: k }).ipHashKey.equals(Buffer.alloc(32, 9))).toBe(
      true,
    );
    expect(() => loadConfig({ ...good, IP_HASH_KEY: 'short' })).toThrow(/IP_HASH_KEY/);
    expect(() => loadConfig({ ...good, IP_HASH_KEY: 'REPLACE_ME_x' })).toThrow(/placeholder/);
    expect(() =>
      loadConfig({ ...good, NODE_ENV: 'production', MASTER_KEY: key, COOKIE_SECURE: 'true' }),
    ).toThrow(/IP_HASH_KEY is required/);
    // Not configured outside production: still allowed.
    expect(loadConfig(good).auditHeadPublicKeys).toEqual({});
  });

  it('parses session lifetimes (ADR 0004) and validates them', () => {
    expect(loadConfig(good).session).toEqual({ idleSeconds: 3600, maxSeconds: 43200 });
    expect(
      loadConfig({ ...good, SESSION_IDLE_MINUTES: '15', SESSION_MAX_HOURS: '2' }).session,
    ).toEqual({ idleSeconds: 900, maxSeconds: 7200 });
    expect(() => loadConfig({ ...good, SESSION_IDLE_MINUTES: 'abc' })).toThrow(/SESSION_IDLE/);
    expect(() => loadConfig({ ...good, SESSION_MAX_HOURS: '0' })).toThrow(/SESSION_MAX_HOURS/);
    expect(() =>
      loadConfig({ ...good, SESSION_IDLE_MINUTES: '600', SESSION_MAX_HOURS: '1' }),
    ).toThrow(/must not exceed/);
  });

  it('requires an explicit non-false TRUST_PROXY in production', () => {
    const prod = {
      ...good,
      NODE_ENV: 'production',
      MASTER_KEY: key,
      IP_HASH_KEY: key,
      AUDIT_HEAD_PUBLIC_KEYS: `k1:${'A'.repeat(43)}`,
    };
    expect(() => loadConfig(prod)).toThrow(/TRUST_PROXY/);
    expect(() => loadConfig({ ...prod, TRUST_PROXY: 'false' })).toThrow(/TRUST_PROXY/);
    expect(loadConfig({ ...prod, TRUST_PROXY: '1' }).trustProxy).toBe(1);
  });

  it('parses TRUST_PROXY (ADR 0003) and refuses "true"', () => {
    expect(loadConfig(good).trustProxy).toBe(false);
    expect(loadConfig({ ...good, TRUST_PROXY: 'false' }).trustProxy).toBe(false);
    expect(loadConfig({ ...good, TRUST_PROXY: '1' }).trustProxy).toBe(1);
    expect(loadConfig({ ...good, TRUST_PROXY: '10.0.0.0/8, 192.168.1.1' }).trustProxy).toBe(
      '10.0.0.0/8,192.168.1.1',
    );
    expect(() => loadConfig({ ...good, TRUST_PROXY: 'true' })).toThrow(/trusts any client/);
    expect(() => loadConfig({ ...good, TRUST_PROXY: '0' })).toThrow(/hop count/);
    expect(() => loadConfig({ ...good, TRUST_PROXY: 'evil.example' })).toThrow(/TRUST_PROXY/);
  });

  it('parses object storage and the logo cap (ADR 0008)', () => {
    const c = loadConfig(good);
    expect(c.s3).toBeUndefined();
    expect(c.logoMaxBytes).toBe(1024 * 1024);
    expect(c.photoMaxBytes).toBe(2 * 1024 * 1024);
    expect(loadConfig({ ...good, PHOTO_MAX_BYTES: '4096' }).photoMaxBytes).toBe(4096);
    expect(() => loadConfig({ ...good, PHOTO_MAX_BYTES: 'big' })).toThrow(/PHOTO_MAX_BYTES/);
    const s3 = {
      S3_ENDPOINT: 'http://127.0.0.1:9000',
      S3_BUCKET: 'igaro',
      S3_ACCESS_KEY: 'ak',
      S3_SECRET_KEY: 'sk-value',
    };
    expect(loadConfig({ ...good, ...s3, LOGO_MAX_BYTES: '2048' })).toMatchObject({
      s3: { bucket: 'igaro', region: 'us-east-1', forcePathStyle: true },
      logoMaxBytes: 2048,
    });
    expect(() => loadConfig({ ...good, S3_BUCKET: 'igaro' })).toThrow(/set together/);
    expect(() => loadConfig({ ...good, ...s3, LOGO_MAX_BYTES: 'big' })).toThrow(/LOGO_MAX_BYTES/);
    expect(() => loadConfig({ ...good, ...s3, S3_ENDPOINT: 'ftp://x' })).toThrow(/http/);
    expect(() => loadConfig({ ...good, ...s3, S3_SECRET_KEY: 'change-me' })).toThrow(/placeholder/);
    try {
      loadConfig({ ...good, ...s3, S3_SECRET_KEY: 'change-me' });
    } catch (e) {
      expect(String((e as Error).message)).not.toContain('change-me');
    }
  });
});
