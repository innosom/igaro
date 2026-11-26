// T-047 (ADR 0035): INTERNAL_ALLOWED_CIDRS parsing and the production requirement. Test values only.
import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig, parseInternalAllowlist } from './config.js';

const key = Buffer.alloc(32, 7).toString('base64');
const token = 'a-test-only-internal-token-0123456789abcdef';
const prod = {
  APP_DATABASE_URL: 'postgresql://igaro_app:s3cret-pw@127.0.0.1:5432/igaro',
  NODE_ENV: 'production',
  MASTER_KEY: key,
  IP_HASH_KEY: Buffer.alloc(32, 9).toString('base64'),
  AUDIT_HEAD_PUBLIC_KEYS: 'k1:' + 'A'.repeat(43),
  TRUST_PROXY: '1',
};

describe('INTERNAL_ALLOWED_CIDRS', () => {
  it('parses addresses and CIDRs, unset is undefined', () => {
    expect(parseInternalAllowlist(undefined)).toBeUndefined();
    expect(parseInternalAllowlist(' ')).toBeUndefined();
    expect(parseInternalAllowlist('10.0.0.0/8, ::1')).toEqual(['10.0.0.0/8', '::1']);
  });
  it('refuses malformed values and allow-everything', () => {
    for (const bad of ['nope', '10.0.0.0/33', '10.0.0.0/8/1', '0.0.0.0/0', '::/0']) {
      expect(() => parseInternalAllowlist(bad)).toThrow(ConfigError);
    }
  });
  it('is required in production when the internal token is set', () => {
    expect(() => loadConfig({ ...prod, INTERNAL_API_TOKEN: token })).toThrow(/INTERNAL_ALLOWED_CIDRS is required/);
    expect(loadConfig({ ...prod, INTERNAL_API_TOKEN: token, INTERNAL_ALLOWED_CIDRS: '10.0.0.0/8' }).internalAllowedCidrs).toEqual(['10.0.0.0/8']);
    expect(loadConfig(prod).internalApiToken).toBeUndefined();
  });
});
