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
    expect(loadConfig({ ...prod, MASTER_KEY: key, IP_HASH_KEY: key }).cookie.secure).toBe(true);
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
});
