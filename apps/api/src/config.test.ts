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
    expect(loadConfig({ ...prod, MASTER_KEY: key }).cookie.secure).toBe(true);
  });
});
