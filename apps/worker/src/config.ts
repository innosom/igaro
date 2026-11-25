// Environment parsing for the worker. Fails fast (ConfigError); messages name the variable, never its value.

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
  };
}
