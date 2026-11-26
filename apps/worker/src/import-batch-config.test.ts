import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { ConfigError, loadWorkerConfig } from './config.js';

const base = {
  APP_DATABASE_URL: 'postgresql://igaro_app:pw@127.0.0.1:5432/igaro',
  SMTP_HOST: '127.0.0.1',
  SMTP_FROM: 'no-reply@igaro.test',
  WEB_BASE_URL: 'http://127.0.0.1:3000',
  DELIVERY_PAYLOAD_KEY: randomBytes(32).toString('base64'),
};
const s3 = { S3_BUCKET: 'igaro-private', S3_ACCESS_KEY: 'access-test', S3_SECRET_KEY: 'secret-test-value', S3_ENDPOINT: 'http://127.0.0.1:9000' };
const token = randomBytes(32).toString('base64url');

describe('import.batch config (T-044)', () => {
  it('is off by default', () => {
    expect(loadWorkerConfig(base).importBatch).toBeUndefined();
  });

  it('is enabled by the internal API url, the shared token and storage', () => {
    const c = loadWorkerConfig({ ...base, ...s3, INTERNAL_API_URL: 'http://127.0.0.1:4000/api/v1/', INTERNAL_API_TOKEN: token });
    expect(c.importBatch).toMatchObject({ apiUrl: 'http://127.0.0.1:4000/api/v1', token });
    expect(c.importBatch?.s3.bucket).toBe('igaro-private');
  });

  it('stays off without storage (warned at startup)', () => {
    expect(loadWorkerConfig({ ...base, INTERNAL_API_URL: 'http://127.0.0.1:4000/api/v1', INTERNAL_API_TOKEN: token }).importBatch).toBeUndefined();
  });

  it('refuses half-set, short, placeholder and malformed values without echoing them', () => {
    const cases: Record<string, string>[] = [
      { INTERNAL_API_URL: 'http://127.0.0.1:4000/api/v1' },
      { INTERNAL_API_TOKEN: token },
      { INTERNAL_API_URL: 'http://127.0.0.1:4000/api/v1', INTERNAL_API_TOKEN: 'short' },
      { INTERNAL_API_URL: 'http://127.0.0.1:4000/api/v1', INTERNAL_API_TOKEN: 'replace-me-'.padEnd(40, 'x') },
      { INTERNAL_API_URL: 'not a url', INTERNAL_API_TOKEN: token },
      { INTERNAL_API_URL: 'ftp://127.0.0.1/api', INTERNAL_API_TOKEN: token },
      { INTERNAL_API_URL: 'http://user:pw@127.0.0.1/api', INTERNAL_API_TOKEN: token },
    ];
    for (const c of cases) {
      let err: unknown;
      try {
        loadWorkerConfig({ ...base, ...s3, ...c });
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(ConfigError);
      expect((err as Error).message).not.toContain(token);
      expect((err as Error).message).not.toContain('user:pw');
    }
  });
});
