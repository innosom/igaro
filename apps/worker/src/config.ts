// Environment parsing for the worker. Fails fast (ConfigError); messages name the variable, never its value.

import { parseMasterKey } from '@igaro/core';
import { AUDIT_DAILY_HEAD_CRON } from './audit-head.js';
import { parseCalendarUrls } from './ots.js';

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

export interface WorkerConfig {
  nodeEnv: 'development' | 'test' | 'production';
  logLevel: string;
  /** Postgres URL for pg-boss (WORKER_DATABASE_URL, else APP_DATABASE_URL). Never the owner DATABASE_URL. */
  databaseUrl: string;
  /** pg-boss schema. Holds only queue tables, never tenant data. */
  pgbossSchema: string;
  smtp: {
    host: string;
    port: number;
    from: string;
    secure: boolean;
    user: string | undefined;
    pass: string | undefined;
  };
  /** Public base URL of the web app, no trailing slash. Used to build links in mail. */
  webBaseUrl: string;
  /**
   * Daily audit head job (T-028, ADR 0019). `undefined` = job not registered (allowed outside production).
   * The key is the PLATFORM head key (an igaro.key.v1 envelope under AUDIT_HEAD_WRAP_KEY, never MASTER_KEY);
   * never an institution key. The worker does not read MASTER_KEY at all (ADR 0019).
   */
  auditHead:
    | { keyEnvelope: string; kid: string; wrapKey: string; cron: string }
    | undefined;
  /** OpenTimestamps calendar base URLs. Empty = timestamping disabled (heads are still signed). */
  otsCalendars: string[];
}

type Env = Record<string, string | undefined>;

const PLACEHOLDER = /replace[_-]?me|change[_-]?me|your[_-]|<.*>/i;

function parseDbUrl(raw: string, name: string, env: Env): string {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new ConfigError(`${name} is not a valid URL`);
  }
  if (u.protocol !== 'postgresql:' && u.protocol !== 'postgres:') {
    throw new ConfigError(`${name} must be a postgresql:// URL`);
  }
  if (PLACEHOLDER.test(raw)) throw new ConfigError(`${name} looks like a placeholder`);
  if (env.DATABASE_URL && env.DATABASE_URL === raw) {
    throw new ConfigError(`${name} must differ from the owner DATABASE_URL`);
  }
  return raw;
}

function parseWebBaseUrl(raw: string | undefined, nodeEnv: string): string {
  if (!raw) throw new ConfigError('WEB_BASE_URL is required');
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new ConfigError('WEB_BASE_URL is not a valid URL');
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') {
    throw new ConfigError('WEB_BASE_URL must be http(s)');
  }
  if (nodeEnv === 'production' && u.protocol !== 'https:') {
    throw new ConfigError('WEB_BASE_URL must be https in production');
  }
  if (u.username || u.password || u.search || u.hash) {
    throw new ConfigError('WEB_BASE_URL must not contain credentials, query or fragment');
  }
  return `${u.origin}${u.pathname.replace(/\/+$/, '')}`;
}

export function loadWorkerConfig(env: Env = process.env): WorkerConfig {
  const nodeEnv = env.NODE_ENV ?? 'development';
  if (nodeEnv !== 'development' && nodeEnv !== 'test' && nodeEnv !== 'production') {
    throw new ConfigError('NODE_ENV must be development, test or production');
  }
  const dbName = env.WORKER_DATABASE_URL ? 'WORKER_DATABASE_URL' : 'APP_DATABASE_URL';
  const rawDb = env.WORKER_DATABASE_URL || env.APP_DATABASE_URL;
  if (!rawDb) throw new ConfigError('WORKER_DATABASE_URL or APP_DATABASE_URL is required');

  const host = env.SMTP_HOST;
  if (!host) throw new ConfigError('SMTP_HOST is required');
  const portRaw = env.SMTP_PORT ?? '1025';
  const port = Number(portRaw);
  if (!/^\d+$/.test(portRaw) || port < 1 || port > 65535) {
    throw new ConfigError('SMTP_PORT must be an integer between 1 and 65535');
  }
  const from = env.SMTP_FROM;
  if (!from || /[\r\n]/.test(from)) throw new ConfigError('SMTP_FROM is required');
  if (env.SMTP_SECURE !== undefined && env.SMTP_SECURE !== 'true' && env.SMTP_SECURE !== 'false') {
    throw new ConfigError('SMTP_SECURE must be true or false');
  }
  const schema = env.PGBOSS_SCHEMA ?? 'pgboss';
  if (!/^[a-z_][a-z0-9_]{0,62}$/.test(schema)) {
    throw new ConfigError('PGBOSS_SCHEMA must be a simple lower-case identifier');
  }

  return {
    nodeEnv,
    logLevel: env.LOG_LEVEL ?? 'info',
    databaseUrl: parseDbUrl(rawDb, dbName, env),
    pgbossSchema: schema,
    smtp: {
      host,
      port,
      from,
      secure: env.SMTP_SECURE === 'true',
      user: env.SMTP_USER || undefined,
      pass: env.SMTP_PASS || undefined,
    },
    webBaseUrl: parseWebBaseUrl(env.WEB_BASE_URL || env.PUBLIC_WEB_URL, nodeEnv),
    auditHead: parseAuditHead(env, nodeEnv),
    otsCalendars: parseOtsCalendars(env, nodeEnv),
  };
}

const DEFAULT_OTS_CALENDARS = [
  'https://alice.btc.calendar.opentimestamps.org',
  'https://bob.btc.calendar.opentimestamps.org',
  'https://finney.calendar.eternitywall.com',
];

function parseOtsCalendars(env: Env, nodeEnv: string): string[] {
  const raw = env.OTS_CALENDAR_URLS;
  // Unset: public calendars in production only; development and tests never touch the network.
  if (raw === undefined) return nodeEnv === 'production' ? DEFAULT_OTS_CALENDARS : [];
  if (raw.trim() === '' || raw.trim() === 'disabled') return [];
  try {
    return parseCalendarUrls(raw, { requireHttps: nodeEnv === 'production' });
  } catch (e) {
    throw new ConfigError(e instanceof Error ? e.message.replace(/^OTS calendar/, 'OTS_CALENDAR_URLS entry') : 'OTS_CALENDAR_URLS invalid');
  }
}

function parseAuditHead(env: Env, nodeEnv: string): WorkerConfig['auditHead'] {
  const keyEnvelope = env.AUDIT_HEAD_SIGNING_KEY;
  if (!keyEnvelope) {
    if (nodeEnv === 'production') throw new ConfigError('AUDIT_HEAD_SIGNING_KEY is required in production');
    return undefined;
  }
  const kid = env.AUDIT_HEAD_KEY_ID;
  if (!kid || !/^[A-Za-z0-9_-]{1,64}$/.test(kid)) throw new ConfigError('AUDIT_HEAD_KEY_ID is required (letters, digits, _ and -)');
  const wrapKey = env.AUDIT_HEAD_WRAP_KEY;
  if (!wrapKey) throw new ConfigError('AUDIT_HEAD_WRAP_KEY is required with AUDIT_HEAD_SIGNING_KEY');
  try {
    parseMasterKey(wrapKey);
  } catch {
    throw new ConfigError('AUDIT_HEAD_WRAP_KEY must decode to 32 bytes');
  }
  // M2: the head INSERT grant exists only for igaro_worker, so production must use its dedicated login.
  if (nodeEnv === 'production' && !env.WORKER_DATABASE_URL) {
    throw new ConfigError('WORKER_DATABASE_URL (igaro_worker login) is required in production for the audit head job');
  }
  const cron = env.AUDIT_HEAD_CRON ?? AUDIT_DAILY_HEAD_CRON;
  if (!/^[0-9*/,\- ]+$/.test(cron) || cron.trim().split(/\s+/).length !== 5) {
    throw new ConfigError('AUDIT_HEAD_CRON must be a 5-field cron expression');
  }
  return { keyEnvelope, kid, wrapKey, cron };
}
