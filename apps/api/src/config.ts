import { randomBytes } from 'node:crypto';
import { isIP } from 'node:net';
import type { S3Config } from './storage.js';

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
  /** Private object storage (ADR 0008), or undefined when not configured (uploads answer 503). */
  s3: S3Config | undefined;
  /** Largest accepted logo upload in bytes (LOGO_MAX_BYTES, default 1 MB). */
  logoMaxBytes: number;
  /** Largest accepted holder photo upload in bytes (PHOTO_MAX_BYTES, default 2 MB). */
  photoMaxBytes: number;
  /**
   * Public keys of the platform audit-head signer (T-028, ADR 0019), kid to raw base64url Ed25519 key, from
   * AUDIT_HEAD_PUBLIC_KEYS="kid:key,kid2:key2". verify-chain checks head signatures against them; rotation
   * keeps old entries. Empty = signatures are reported as unverified, not failed.
   */
  auditHeadPublicKeys: Record<string, string>;
  /**
   * DELIVERY_PAYLOAD_KEY (T-041, ADR 0030): 32-byte AES-256-GCM key that seals the holder token and address in the
   * email.deliver job. Same value as the worker's. Not MASTER_KEY. Undefined = no holder delivery email is queued.
   */
  deliveryPayloadKey?: Buffer | undefined;
  /**
   * INTERNAL_API_TOKEN (T-044, ADR 0034): shared secret the import worker presents as a Bearer token on the internal
   * import endpoints. 32-512 characters. Unset = those endpoints are not registered. Never logged.
   */
  internalApiToken?: string | undefined;
  /**
   * INTERNAL_ALLOWED_CIDRS (T-047, ADR 0035): comma-separated IPs/CIDRs allowed to reach /api/v1/internal/* (socket
   * peer address, never X-Forwarded-For). Required in production when INTERNAL_API_TOKEN is set. Unset = loopback only.
   */
  internalAllowedCidrs?: string[] | undefined;
  /** Where invite/reset mail jobs go (ADR 0006): dropped (default) or the pg-boss queue the worker consumes. */
  accountMail:
    | { driver: 'noop' }
    | {
        driver: 'pgboss';
        databaseUrl: string;
        schema: string | undefined;
        /**
         * PGBOSS_SCHEMA_MODE (ADR 0038). `external` (production default): the pg-boss schema and queues were provisioned
         * by the owner (`pnpm db:pgboss`) and this role only enqueues; it creates and migrates nothing.
         */
        schemaMode: 'auto' | 'external';
      };
}

/** Fixed-window limits (ADR 0005). Counts are per process; windows are in seconds. */
export interface RateLimitConfig {
  /** Login: every attempt counts per IP; attempts count per account (email) until a success. */
  login: { ipMax: number; accountMax: number; windowSeconds: number };
  /** Password-reset requests (a mail is sent per request): per IP and per email address. */
  reset: { ipMax: number; accountMax: number; windowSeconds: number };
  /** Invite accept and reset confirm (token endpoints): per IP. */
  token: { ipMax: number; windowSeconds: number };
  /** Public verification (T-032, ADR 0022): per IP and per token. Optional so older callers keep working; defaults apply. */
  verify?: { ipMax: number; tokenMax: number; windowSeconds: number };
}

export const DEFAULT_RATE_LIMIT: RateLimitConfig = {
  login: { ipMax: 30, accountMax: 5, windowSeconds: 900 },
  reset: { ipMax: 10, accountMax: 3, windowSeconds: 3600 },
  token: { ipMax: 20, windowSeconds: 900 },
};

export const DEFAULT_VERIFY_LIMIT = { ipMax: 60, tokenMax: 120, windowSeconds: 60 };

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

function parseS3(env: Env, nodeEnv: string): S3Config | undefined {
  const bucket = env.S3_BUCKET;
  const accessKey = env.S3_ACCESS_KEY;
  const secretKey = env.S3_SECRET_KEY;
  if (!bucket && !accessKey && !secretKey) return undefined;
  if (!bucket || !accessKey || !secretKey) {
    throw new ConfigError('S3_BUCKET, S3_ACCESS_KEY and S3_SECRET_KEY must be set together');
  }
  if (PLACEHOLDER.test(secretKey) || PLACEHOLDER.test(accessKey)) {
    throw new ConfigError('S3 credentials look like placeholders');
  }
  if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(bucket)) {
    throw new ConfigError('S3_BUCKET is not a valid bucket name');
  }
  const region = env.S3_REGION || 'us-east-1';
  const endpoint = env.S3_ENDPOINT || `https://s3.${region}.amazonaws.com`;
  let u: URL;
  try {
    u = new URL(endpoint);
  } catch {
    throw new ConfigError('S3_ENDPOINT is not a valid URL');
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new ConfigError('S3_ENDPOINT must be http(s)');
  if (u.username || u.password) throw new ConfigError('S3_ENDPOINT must not contain credentials');
  if (nodeEnv === 'production' && u.protocol !== 'https:') {
    throw new ConfigError('S3_ENDPOINT must use https in production');
  }
  const fps = env.S3_FORCE_PATH_STYLE;
  if (fps !== undefined && fps !== '' && fps !== 'true' && fps !== 'false') {
    throw new ConfigError('S3_FORCE_PATH_STYLE must be true or false');
  }
  return {
    endpoint,
    region,
    bucket,
    accessKey,
    secretKey,
    forcePathStyle: fps === undefined || fps === '' ? Boolean(env.S3_ENDPOINT) : fps === 'true',
  };
}

/** "kid:key,kid2:key2". Values are public keys (32 raw bytes, base64url); anything else is a startup error. */
export function parseAuditHeadPublicKeys(raw: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!raw || raw.trim() === '') return out;
  for (const part of raw.split(',')) {
    const [kid, key, extra] = part.trim().split(':');
    if (!kid || !key || extra !== undefined || !/^[A-Za-z0-9_-]{1,64}$/.test(kid) || !/^[A-Za-z0-9_-]{43}$/.test(key)) {
      throw new ConfigError('AUDIT_HEAD_PUBLIC_KEYS must be comma-separated kid:base64url-public-key pairs');
    }
    out[kid] = key;
  }
  return out;
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
    verify: {
      ipMax: parseCount(env.RATE_LIMIT_VERIFY_IP_MAX, 'RATE_LIMIT_VERIFY_IP_MAX', DEFAULT_VERIFY_LIMIT.ipMax),
      tokenMax: parseCount(env.RATE_LIMIT_VERIFY_TOKEN_MAX, 'RATE_LIMIT_VERIFY_TOKEN_MAX', DEFAULT_VERIFY_LIMIT.tokenMax),
      windowSeconds: parseCount(
        env.RATE_LIMIT_VERIFY_WINDOW_SECONDS,
        'RATE_LIMIT_VERIFY_WINDOW_SECONDS',
        DEFAULT_VERIFY_LIMIT.windowSeconds,
        86400,
      ),
    },
  };

  const tokenTtl = {
    inviteSeconds: parseSeconds(env.INVITE_TTL_HOURS, 'INVITE_TTL_HOURS', 3600, 72, 1, 720),
    resetSeconds: parseSeconds(env.RESET_TTL_MINUTES, 'RESET_TTL_MINUTES', 60, 60, 5, 1440),
  };

  const driver = env.ACCOUNT_MAIL_QUEUE ?? 'noop';
  if (driver !== 'noop' && driver !== 'pgboss') {
    throw new ConfigError('ACCOUNT_MAIL_QUEUE must be noop or pgboss');
  }
  let accountMail: Config['accountMail'] = { driver: 'noop' };
  if (driver === 'pgboss') {
    // T-053 (ADR 0039): the API enqueues as its own restricted role. The worker login can read job data, so it is
    // never accepted here; WORKER_DATABASE_URL belongs to the worker only.
    if (env.WORKER_DATABASE_URL) {
      throw new ConfigError('WORKER_DATABASE_URL must not be set for the API: the queue uses APP_DATABASE_URL (enqueue-only)');
    }
    const queueUrl = rawUrl;
    const schema = env.PGBOSS_SCHEMA || undefined;
    if (schema !== undefined && !/^[a-z_][a-z0-9_]{0,62}$/.test(schema)) {
      throw new ConfigError('PGBOSS_SCHEMA must be a simple lower-case identifier');
    }
    const modeRaw = env.PGBOSS_SCHEMA_MODE;
    if (modeRaw !== undefined && modeRaw !== '' && modeRaw !== 'auto' && modeRaw !== 'external') {
      throw new ConfigError('PGBOSS_SCHEMA_MODE must be auto or external');
    }
    const schemaMode: 'auto' | 'external' =
      modeRaw === 'auto' || modeRaw === 'external' ? modeRaw : nodeEnv === 'production' ? 'external' : 'auto';
    accountMail = { driver: 'pgboss', databaseUrl: queueUrl, schema, schemaMode };
  }

  // Holder delivery key (ADR 0030): distinct from MASTER_KEY, required in production once the queue is on.
  const deliveryRaw = env.DELIVERY_PAYLOAD_KEY;
  let deliveryPayloadKey: Buffer | undefined;
  if (deliveryRaw !== undefined && deliveryRaw !== '') {
    if (PLACEHOLDER.test(deliveryRaw)) throw new ConfigError('DELIVERY_PAYLOAD_KEY looks like a placeholder');
    const buf = Buffer.from(deliveryRaw, 'base64');
    if (buf.length !== 32 || buf.toString('base64') !== deliveryRaw.trim()) {
      throw new ConfigError('DELIVERY_PAYLOAD_KEY must be base64 encoding of exactly 32 bytes');
    }
    if (env.MASTER_KEY && env.MASTER_KEY.trim() === deliveryRaw.trim()) {
      throw new ConfigError('DELIVERY_PAYLOAD_KEY must differ from MASTER_KEY');
    }
    deliveryPayloadKey = buf;
  } else if (nodeEnv === 'production' && accountMail.driver === 'pgboss') {
    throw new ConfigError('DELIVERY_PAYLOAD_KEY is required in production when ACCOUNT_MAIL_QUEUE=pgboss');
  }

  const internalRaw = env.INTERNAL_API_TOKEN;
  let internalApiToken: string | undefined;
  if (internalRaw !== undefined && internalRaw !== '') {
    if (PLACEHOLDER.test(internalRaw)) throw new ConfigError('INTERNAL_API_TOKEN looks like a placeholder');
    if (internalRaw.length < 32 || internalRaw.length > 512 || /\s/.test(internalRaw)) {
      throw new ConfigError('INTERNAL_API_TOKEN must be 32-512 characters without whitespace');
    }
    if (env.MASTER_KEY && env.MASTER_KEY.trim() === internalRaw) throw new ConfigError('INTERNAL_API_TOKEN must differ from MASTER_KEY');
    internalApiToken = internalRaw;
  }

  const logoMaxBytes = parseCount(env.LOGO_MAX_BYTES, 'LOGO_MAX_BYTES', 1024 * 1024, 10 * 1024 * 1024);

  const photoMaxBytes = parseCount(env.PHOTO_MAX_BYTES, 'PHOTO_MAX_BYTES', 2 * 1024 * 1024, 10 * 1024 * 1024);

  const ipHashKey = parseIpHashKey(env.IP_HASH_KEY, nodeEnv);
  const auditHeadPublicKeys = parseAuditHeadPublicKeys(env.AUDIT_HEAD_PUBLIC_KEYS);
  if (nodeEnv === 'production' && Object.keys(auditHeadPublicKeys).length === 0) {
    throw new ConfigError('AUDIT_HEAD_PUBLIC_KEYS is required in production');
  }

  // Production must state its proxy topology on purpose: an unset or false value buckets every client behind the
  // ingress under one IP (rate limits, hashed-IP logs).
  const trustProxy = parseTrustProxy(env.TRUST_PROXY);
  const internalAllowedCidrs = parseInternalAllowlist(env.INTERNAL_ALLOWED_CIDRS);
  if (nodeEnv === 'production' && internalApiToken && !internalAllowedCidrs) {
    throw new ConfigError('INTERNAL_ALLOWED_CIDRS is required in production when INTERNAL_API_TOKEN is set');
  }
  if (nodeEnv === 'production' && trustProxy === false) {
    throw new ConfigError('TRUST_PROXY must be set to a hop count or proxy IPs/CIDRs in production');
  }

  return {
    s3: parseS3(env, nodeEnv),
    logoMaxBytes,
    photoMaxBytes,
    accountMail,
    deliveryPayloadKey,
    internalApiToken,
    internalAllowedCidrs,
    auditHeadPublicKeys,
    session,
    tokenTtl,
    rateLimit,
    nodeEnv,
    host: env.API_HOST ?? '127.0.0.1',
    port,
    logLevel: env.LOG_LEVEL ?? 'info',
    appDatabaseUrl: parseDbUrl(rawUrl, env),
    masterKey,
    ipHashKey,
    trustProxy,
    cookie: {
      name: env.COOKIE_NAME ?? 'igaro_session',
      secure,
      sameSite: 'lax',
      domain: env.COOKIE_DOMAIN || undefined,
    },
  };
}

/** Parse INTERNAL_ALLOWED_CIDRS: comma-separated IPv4/IPv6 addresses or CIDRs. Unset/empty = undefined. */
export function parseInternalAllowlist(raw: string | undefined): string[] | undefined {
  if (raw === undefined || raw.trim() === '') return undefined;
  const items = raw.split(',').map((x) => x.trim()).filter(Boolean);
  for (const it of items) {
    const [addr, bits, extra] = it.split('/');
    const fam = addr ? isIP(addr) : 0;
    const max = fam === 4 ? 32 : 128;
    if (!fam || extra !== undefined || (bits !== undefined && !(/^\d{1,3}$/.test(bits) && Number(bits) <= max))) {
      throw new ConfigError('INTERNAL_ALLOWED_CIDRS must be comma-separated IPs or CIDRs');
    }
    if (bits !== undefined && Number(bits) === 0) throw new ConfigError('INTERNAL_ALLOWED_CIDRS must not allow every address');
  }
  return items;
}
