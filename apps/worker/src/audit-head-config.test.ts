import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { generateSigningKey, parseMasterKey } from '@igaro/core';
import { ConfigError, loadWorkerConfig } from './config.js';
import { assertHeadInsertPrivilege } from './audit-head.js';
import type { Pool } from 'pg';

const base = {
  APP_DATABASE_URL: 'postgresql://igaro_app:pw@127.0.0.1:5432/igaro',
  SMTP_HOST: '127.0.0.1',
  SMTP_FROM: 'no-reply@igaro.test',
  WEB_BASE_URL: 'http://127.0.0.1:3000',
  // Required in production since T-041 (ADR 0030); harmless elsewhere.
  DELIVERY_PAYLOAD_KEY: randomBytes(32).toString('base64'),
};
const wrap = randomBytes(32).toString('base64');
const key = generateSigningKey(parseMasterKey(wrap));
const WORKER_URL = 'postgresql://igaro_worker:pw@127.0.0.1:5432/igaro';
const headEnv = { AUDIT_HEAD_WRAP_KEY: wrap, AUDIT_HEAD_SIGNING_KEY: key.encryptedPrivateKey, AUDIT_HEAD_KEY_ID: key.kid };

describe('audit head and OTS config', () => {
  it('defaults: job off and no network outside production', () => {
    const c = loadWorkerConfig(base);
    expect(c.auditHead).toBeUndefined();
    expect(c.otsCalendars).toEqual([]);
  });

  it('enables the job when the platform head key is configured', () => {
    const c = loadWorkerConfig({ ...base, ...headEnv, OTS_CALENDAR_URLS: 'https://a.test/, https://b.test' });
    expect(c.auditHead).toMatchObject({ kid: key.kid, cron: '10 0 * * *', wrapKey: wrap });
    expect(c.otsCalendars).toEqual(['https://a.test', 'https://b.test']);
  });

  it('H1: never reads MASTER_KEY; the wrap key must be AUDIT_HEAD_WRAP_KEY', () => {
    const noWrap = { AUDIT_HEAD_SIGNING_KEY: headEnv.AUDIT_HEAD_SIGNING_KEY, AUDIT_HEAD_KEY_ID: headEnv.AUDIT_HEAD_KEY_ID };
    // A MASTER_KEY in the environment is ignored and cannot stand in for the wrap key.
    expect(() => loadWorkerConfig({ ...base, ...noWrap, MASTER_KEY: wrap })).toThrow(/AUDIT_HEAD_WRAP_KEY is required/);
    const c = loadWorkerConfig({ ...base, ...headEnv, MASTER_KEY: randomBytes(32).toString('base64') });
    expect(JSON.stringify(c)).not.toContain('MASTER');
    expect(c.auditHead?.wrapKey).toBe(wrap);
  });

  it('production requires the key, WORKER_DATABASE_URL (M2) and defaults to the public calendars', () => {
    const prod = { ...base, NODE_ENV: 'production', WEB_BASE_URL: 'https://app.igaro.test' };
    expect(() => loadWorkerConfig(prod)).toThrow(ConfigError);
    expect(() => loadWorkerConfig({ ...prod, ...headEnv })).toThrow(/WORKER_DATABASE_URL/);
    const c = loadWorkerConfig({ ...prod, ...headEnv, WORKER_DATABASE_URL: WORKER_URL });
    expect(c.otsCalendars.length).toBeGreaterThan(0);
    expect(c.otsCalendars.every((u) => u.startsWith('https://'))).toBe(true);
    const off = loadWorkerConfig({
      ...prod,
      WORKER_DATABASE_URL: WORKER_URL,
      ...headEnv,
      AUDIT_HEAD_SIGNING_KEY: 'x',
      AUDIT_HEAD_KEY_ID: 'k',
      OTS_CALENDAR_URLS: 'disabled',
    });
    expect(off.otsCalendars).toEqual([]);
  });

  it('L1: production refuses http calendars, development allows them', () => {
    const prod = { ...base, NODE_ENV: 'production', WEB_BASE_URL: 'https://app.igaro.test', WORKER_DATABASE_URL: WORKER_URL, ...headEnv };
    expect(() => loadWorkerConfig({ ...prod, OTS_CALENDAR_URLS: 'http://cal.test' })).toThrow(/https/);
    expect(loadWorkerConfig({ ...prod, OTS_CALENDAR_URLS: 'https://cal.test' }).otsCalendars).toEqual(['https://cal.test']);
    expect(loadWorkerConfig({ ...base, OTS_CALENDAR_URLS: 'http://cal.test' }).otsCalendars).toEqual(['http://cal.test']);
  });

  it('rejects bad values without echoing secrets', () => {
    for (const env of [
      { ...base, AUDIT_HEAD_SIGNING_KEY: key.encryptedPrivateKey },
      { ...base, AUDIT_HEAD_SIGNING_KEY: key.encryptedPrivateKey, AUDIT_HEAD_KEY_ID: 'k' },
      { ...base, AUDIT_HEAD_SIGNING_KEY: key.encryptedPrivateKey, AUDIT_HEAD_KEY_ID: 'k', AUDIT_HEAD_WRAP_KEY: 'short' },
      { ...base, OTS_CALENDAR_URLS: 'ftp://nope' },
      { ...base, ...headEnv, AUDIT_HEAD_SIGNING_KEY: 'x', AUDIT_HEAD_KEY_ID: 'k', AUDIT_HEAD_CRON: '* * *' },
    ]) {
      let msg = '';
      try {
        loadWorkerConfig(env);
      } catch (e) {
        expect(e).toBeInstanceOf(ConfigError);
        msg = (e as Error).message;
      }
      expect(msg).not.toBe('');
      expect(msg).not.toContain(key.encryptedPrivateKey);
      expect(msg).not.toContain(wrap);
    }
  });
});

describe('head insert startup self-check (M2)', () => {
  const poolWith = (ok: boolean): { pool: Pool; queries: string[] } => {
    const queries: string[] = [];
    const client = {
      query: async (sql: string) => {
        queries.push(sql);
        return { rows: [{ ok }] };
      },
      release: () => undefined,
    };
    return { pool: { connect: async () => client } as unknown as Pool, queries };
  };

  it('passes when the role has INSERT and uses has_table_privilege on current_user', async () => {
    const { pool, queries } = poolWith(true);
    await expect(assertHeadInsertPrivilege(pool)).resolves.toBeUndefined();
    expect(queries[0]).toContain(`has_table_privilege(current_user, 'audit_head_hashes', 'INSERT')`);
  });

  it('fails loudly when the role lacks INSERT', async () => {
    const { pool } = poolWith(false);
    await expect(assertHeadInsertPrivilege(pool)).rejects.toThrow(/no INSERT on audit_head_hashes/);
  });
});
