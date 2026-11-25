import { randomBytes } from 'node:crypto';

// Environment parsing for the API. Fails fast (throws ConfigError) on anything invalid.
// Error messages name the variable but never echo its value (URLs and keys can hold secrets).

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

export interface Config {
  nodeEnv: 'development' | 'test' | 'production';
  host: string;
  port: number;
  logLevel: string;
  appDatabaseUrl: string;
  /** 32-byte AES-256-GCM key-encryption key, or undefined when not configured. */
  masterKey: Buffer | undefined;
  /** HMAC-SHA256 key for hashing client IPs in every log (ADR 0003). */
  ipHashKey: Buffer;
  /**
   * Fastify trustProxy (ADR 0003): false = clients connect directly; a number = trusted proxy hop count;
   * a string = comma-separated trusted proxy IPs/CIDRs. "Trust everything" (true) is not allowed.
   */
  trustProxy: false | number | string;
  cookie: { name: string; secure: boolean; sameSite: 'lax'; domain: string | undefined };
  /** Session lifetimes in seconds: idle (sliding) timeout and absolute maximum age. */
  session: { idleSeconds: number; maxSeconds: number };
  /** Lifetimes of single-use invite and password-reset tokens, in seconds (ADR 0005). */
  tokenTtl: { inviteSeconds: number; resetSeconds: number };
  rateLimit: RateLimitConfig;
}

/** Fixed-window limits (ADR 0005). Counts are per process; windows are in seconds. */
export interface RateLimitConfig {
  /** Login: every attempt counts per IP; attempts count per account (email) until a success. */
  login: { ipMax: number; accountMax: number; windowSeconds: number };
  /** Password-reset requests (a mail is sent per request): per IP and per email address. */
  reset: { ipMax: number; accountMax: number; windowSeconds: number };
  /** Invite accept and reset confirm (token endpoints): per IP. */
  token: { ipMax: number; windowSeconds: number };
}

export const DEFAULT_RATE_LIMIT: RateLimitConfig = {
  login: { ipMax: 30, accountMax: 5, windowSeconds: 900 },
  reset: { ipMax: 10, accountMax: 3, windowSeconds: 3600 },
  token: { ipMax: 20, windowSeconds: 900 },
};

export const DEFAULT_TOKEN_TTL = { inviteSeconds: 72 * 3600, resetSeconds: 3600 };

function parseSeconds(
  raw: string | undefined,
  name: string,
  unitSeconds: number,
  def: number,
  min: number,
  max: number,
): number {
  if (raw === undefined || raw === '') return def * unitSeconds;
  if (!/^\d+$/.test(raw)) throw new ConfigError(`${name} must be a whole number`);
  const n = Number(raw);
  if (n < min || n > max) throw new ConfigError(`${name} must be between ${min} and ${max}`);
  return n * unitSeconds;
}

function parseCount(raw: string | undefined, name: string, def: number, max = 100000): number {
  if (raw === undefined || raw === '') return def;
  if (!/^\d+$/.test(raw)) throw new ConfigError(`${name} must be a whole number`);
  const n = Number(raw);
  if (n < 1 || n > max) throw new ConfigError(`${name} must be between 1 and ${max}`);
  return n;
}

type Env = Record<string, string | undefined>;

// Roles that are superusers or owners by convention. The API must run as the restricted
// igaro_app role so RLS applies (docs/dev-setup.md).
const FORBIDDEN_DB_USERS = new Set(['postgres', 'root', 'admin', 'superuser', 'igaro']);
const PLACEHOLDER = /replace[_-]?me|change[_-]?me|your[_-]|<.*>/i;

function parseDbUrl(raw: string, env: Env): string {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new ConfigError('APP_DATABASE_URL is not a valid URL');
  }
  if (u.protocol !== 'postgresql:' && u.protocol !== 'postgres:') {
    throw new ConfigError('APP_DATABASE_URL must be a postgresql:// URL');
  }
  if (PLACEHOLDER.test(raw)) throw new ConfigError('APP_DATABASE_URL looks like a placeholder');
  const user = decodeURIComponent(u.username);
  if (!user) throw new ConfigError('APP_DATABASE_URL must name a database user');
  if (FORBIDDEN_DB_USERS.has(user.toLowerCase())) {
    throw new ConfigError(
      'APP_DATABASE_URL must use the restricted igaro_app role, not a superuser/owner role',
    );
  }
  if (env.DATABASE_URL && env.DATABASE_URL === raw) {
    throw new ConfigError('APP_DATABASE_URL must differ from the owner DATABASE_URL');
  }
  return raw;
}

function parseMasterKey(raw: string | undefined): Buffer | undefined {
  if (raw === undefined || raw === '') return undefined;
  if (PLACEHOLDER.test(raw)) throw new ConfigError('MASTER_KEY looks like a placeholder');
  const buf = Buffer.from(raw, 'base64');
  // Round-trip check rejects strings that are not canonical base64.
  if (buf.length !== 32 || buf.toString('base64') !== raw.trim()) {
    throw new ConfigError('MASTER_KEY must be base64 encoding of exactly 32 bytes');
  }
  return buf;
}

function parseIpHashKey(raw: string | undefined, nodeEnv: string): Buffer {
  if (raw === undefined || raw === '') {
    if (nodeEnv === 'production') throw new ConfigError('IP_HASH_KEY is required in production');
    // Dev/test: a per-process random key. Hashes still correlate within one run.
    return randomBytes(32);
  }
  if (PLACEHOLDER.test(raw)) throw new ConfigError('IP_HASH_KEY looks like a placeholder');
  const buf = Buffer.from(raw, 'base64');
  if (buf.length < 32 || buf.toString('base64') !== raw.trim()) {
    throw new ConfigError('IP_HASH_KEY must be base64 encoding of at least 32 bytes');
  }
  return buf;
}

const IP_OR_CIDR = /^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]*:[0-9a-f:.]*)(?:\/\d{1,3})?$/i;

function parseTrustProxy(raw: string | undefined): false | number | string {
  const v = (raw ?? '').trim();
  if (v === '' || v === 'false') return false;
  if (/^\d+$/.test(v)) {
    const hops = Number(v);
    if (hops < 1 || hops > 10) throw new ConfigError('TRUST_PROXY hop count must be 1-10');
    return hops;
  }
  if (v === 'true') {
    throw new ConfigError('TRUST_PROXY=true trusts any client; use a hop count or proxy CIDRs');
  }
  const parts = v.split(',').map((x) => x.trim());
  if (parts.some((x) => !IP_OR_CIDR.test(x))) {
    throw new ConfigError('TRUST_PROXY must be false, a hop count, or comma-separated IPs/CIDRs');
  }
  return parts.join(',');
}

export function loadConfig(env: Env = process.env): Config {
  const nodeEnv = env.NODE_ENV ?? 'development';
  if (nodeEnv !== 'development' && nodeEnv !== 'test' && nodeEnv !== 'production') {
    throw new ConfigError('NODE_ENV must be development, test or production');
  }
  const rawUrl = env.APP_DATABASE_URL;
  if (!rawUrl) throw new ConfigError('APP_DATABASE_URL is required');

  const portRaw = env.PORT ?? env.API_PORT ?? '4000';
  const port = Number(portRaw);
  if (!/^\d+$/.test(portRaw) || port < 1 || port > 65535) {
    throw new ConfigError('PORT must be an integer between 1 and 65535');
  }

  const masterKey = parseMasterKey(env.MASTER_KEY);
  if (nodeEnv === 'production' && !masterKey) {
    throw new ConfigError('MASTER_KEY is required in production');
  }

  const secureRaw = env.COOKIE_SECURE;
  if (secureRaw !== undefined && secureRaw !== 'true' && secureRaw !== 'false') {
    throw new ConfigError('COOKIE_SECURE must be true or false');
  }
  const secure = secureRaw === undefined ? nodeEnv === 'production' : secureRaw === 'true';
  if (nodeEnv === 'production' && !secure) {
    throw new ConfigError('COOKIE_SECURE must be true in production');
  }

  const session = {
    idleSeconds: parseSeconds(env.SESSION_IDLE_MINUTES, 'SESSION_IDLE_MINUTES', 60, 60, 1, 1440),
    maxSeconds: parseSeconds(env.SESSION_MAX_HOURS, 'SESSION_MAX_HOURS', 3600, 12, 1, 720),
  };
  if (session.idleSeconds > session.maxSeconds) {
    throw new ConfigError('SESSION_IDLE_MINUTES must not exceed SESSION_MAX_HOURS');
  }

  const d = DEFAULT_RATE_LIMIT;
  const rateLimit: RateLimitConfig = {
    login: {
      ipMax: parseCount(env.RATE_LIMIT_LOGIN_IP_MAX, 'RATE_LIMIT_LOGIN_IP_MAX', d.login.ipMax),
      accountMax: parseCount(
        env.RATE_LIMIT_LOGIN_ACCOUNT_MAX,
        'RATE_LIMIT_LOGIN_ACCOUNT_MAX',
        d.login.accountMax,
      ),
      windowSeconds: parseCount(
        env.RATE_LIMIT_LOGIN_WINDOW_SECONDS,
        'RATE_LIMIT_LOGIN_WINDOW_SECONDS',
        d.login.windowSeconds,
        86400,
      ),
    },
    reset: {
      ipMax: parseCount(env.RATE_LIMIT_RESET_IP_MAX, 'RATE_LIMIT_RESET_IP_MAX', d.reset.ipMax),
      accountMax: parseCount(
        env.RATE_LIMIT_RESET_ACCOUNT_MAX,
        'RATE_LIMIT_RESET_ACCOUNT_MAX',
        d.reset.accountMax,
      ),
      windowSeconds: parseCount(
        env.RATE_LIMIT_RESET_WINDOW_SECONDS,
        'RATE_LIMIT_RESET_WINDOW_SECONDS',
        d.reset.windowSeconds,
        86400,
      ),
    },
    token: {
      ipMax: parseCount(env.RATE_LIMIT_TOKEN_IP_MAX, 'RATE_LIMIT_TOKEN_IP_MAX', d.token.ipMax),
      windowSeconds: parseCount(
        env.RATE_LIMIT_TOKEN_WINDOW_SECONDS,
        'RATE_LIMIT_TOKEN_WINDOW_SECONDS',
        d.token.windowSeconds,
        86400,
      ),
    },
  };

  const tokenTtl = {
    inviteSeconds: parseSeconds(env.INVITE_TTL_HOURS, 'INVITE_TTL_HOURS', 3600, 72, 1, 720),
    resetSeconds: parseSeconds(env.RESET_TTL_MINUTES, 'RESET_TTL_MINUTES', 60, 60, 5, 1440),
  };

  return {
    session,
    tokenTtl,
    rateLimit,
    nodeEnv,
    host: env.API_HOST ?? '127.0.0.1',
    port,
    logLevel: env.LOG_LEVEL ?? 'info',
    appDatabaseUrl: parseDbUrl(rawUrl, env),
    masterKey,
    ipHashKey: parseIpHashKey(env.IP_HASH_KEY, nodeEnv),
    trustProxy: parseTrustProxy(env.TRUST_PROXY),
    cookie: {
      name: env.COOKIE_NAME ?? 'igaro_session',
      secure,
      sameSite: 'lax',
      domain: env.COOKIE_DOMAIN || undefined,
    },
  };
}
