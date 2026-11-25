// Authentication: Argon2id passwords, opaque server-side sessions, CSRF (T-009, ADR 0002, ADR 0004).
//
// A session token is 256 random bits, sent only in an httpOnly cookie. The database stores only
// SHA-256(token) (hex). The CSRF token is derived from the raw token (SHA-256 with a domain prefix),
// so the database cannot produce it, and is handed to the client in the login/me response body.
// Tenant scope comes from the session row (never from the request) and feeds Db.withTenant.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { hash as argonHash, verify as argonVerify } from '@node-rs/argon2';
import type { FastifyReply, FastifyRequest, preHandlerAsyncHookHandler } from 'fastify';
import type pg from 'pg';
import type { Config } from './config.js';
import type { Db, Session } from './db.js';
import { AppError } from './errors.js';

export type Role = 'PLATFORM_ADMIN' | 'INSTITUTION_ADMIN';

/** What request.session holds after authentication. Extends Session; pass it to Db.withTenant. */
export type AuthSession = Session & { readonly sessionId: string; readonly role: Role };

export interface AuthMe {
  user: { id: string; email: string; name: string; role: Role };
  institution: { id: string; name: string; slug: string; status: string } | null;
}

export interface AuthOptions {
  cookie: Config['cookie'];
  session: Config['session'];
  /** Used to hash the client IP before it is stored on the session row (ADR 0003). */
  hashIp: (ip: string | undefined) => string | undefined;
}

// Argon2id, OWASP minimum (m=19 MiB, t=2, p=1). Same parameters as packages/db seed.
export const ARGON2ID_PARAMS = {
  algorithm: 2,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
} as const;

export const CSRF_HEADER = 'x-csrf-token';
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
/** Do not write to the DB on every request: slide the idle deadline at most once a minute. */
const EXTEND_THROTTLE_SECONDS = 60;

export const sha256Hex = (s: string): string => createHash('sha256').update(s).digest('hex');
export const hashSessionToken = (token: string): string => sha256Hex(token);
export const csrfTokenFor = (token: string): string =>
  createHash('sha256').update(`igaro.csrf.v1:${token}`).digest('base64url');

export const newSessionToken = (): string => randomBytes(32).toString('base64url');

const unauthenticated = () => new AppError(401, 'UNAUTHENTICATED', 'Authentication required');

// A verification against this hash makes unknown-user and wrong-password paths cost the same.
let dummyHash: Promise<string> | undefined;
const getDummyHash = (): Promise<string> =>
  (dummyHash ??= argonHash(randomBytes(16).toString('hex'), ARGON2ID_PARAMS));

export async function verifyPassword(
  storedHash: string | null,
  password: string,
): Promise<boolean> {
  const target = storedHash ?? (await getDummyHash());
  let ok = false;
  try {
    ok = await argonVerify(target, password);
  } catch {
    ok = false; // malformed stored hash: treat as a mismatch
  }
  return storedHash !== null && ok;
}

export const hashPassword = (password: string): Promise<string> =>
  argonHash(password, ARGON2ID_PARAMS);

// --- cookies -------------------------------------------------------------------------------------

export function readCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    if (part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return undefined;
}

function serializeCookie(o: Config['cookie'], value: string, maxAgeSeconds: number): string {
  const attrs = [
    `${o.name}=${value}`,
    'Path=/',
    `Max-Age=${maxAgeSeconds}`,
    'HttpOnly',
    'SameSite=Lax',
  ];
  if (o.secure) attrs.push('Secure');
  if (o.domain) attrs.push(`Domain=${o.domain}`);
  return attrs.join('; ');
}

// --- session store ---------------------------------------------------------------------------------

interface ResolvedRow {
  sessionId: string;
  me: AuthMe;
  role: Role;
  institutionId: string | null;
}

/**
 * Look the session up by token hash and enforce idle/absolute expiry and user status. Runs inside a
 * lookup transaction (only app.session_token_hash set); after the row is found, the scope is taken
 * from that row so the user and institution can be read and the session extended or deleted.
 */
async function resolveInTx(
  c: pg.PoolClient,
  tokenHash: string,
  opts: AuthOptions,
): Promise<ResolvedRow | null> {
  const s = await c.query<{
    id: string;
    user_id: string;
    institution_id: string | null;
    idle_ok: boolean;
    abs_ok: boolean;
    needs_extend: boolean;
  }>(
    `SELECT id, user_id, institution_id,
            expires_at > now() AS idle_ok,
            created_at + make_interval(secs => $2) > now() AS abs_ok,
            expires_at < now() + make_interval(secs => $3) AS needs_extend
       FROM sessions WHERE token_hash = $1`,
    [tokenHash, opts.session.maxSeconds, opts.session.idleSeconds - EXTEND_THROTTLE_SECONDS],
  );
  const row = s.rows[0];
  if (!row) return null;

  // Scope derived from the row we matched by hash, never from the request.
  if (row.institution_id) {
    await c.query(`SELECT set_config('app.institution_id', $1, true)`, [row.institution_id]);
  } else {
    await c.query(`SELECT set_config('app.is_platform_admin', 'true', true)`);
  }

  const u = await c.query<{
    id: string;
    email: string;
    name: string;
    role: Role;
    status: string;
  }>(`SELECT id, email, name, role, status FROM users WHERE id = $1`, [row.user_id]);
  const user = u.rows[0];

  if (!row.idle_ok || !row.abs_ok || !user || user.status !== 'ACTIVE') {
    await c.query(`DELETE FROM sessions WHERE id = $1`, [row.id]);
    return null;
  }

  let institution: AuthMe['institution'] = null;
  if (row.institution_id) {
    const i = await c.query<{ id: string; name: string; slug: string; status: string }>(
      `SELECT id, name, slug, status FROM institutions WHERE id = $1`,
      [row.institution_id],
    );
    institution = i.rows[0] ?? null;
    if (!institution) return null;
  }

  if (row.needs_extend) {
    await c.query(
      `UPDATE sessions
          SET expires_at = LEAST(now() + make_interval(secs => $2),
                                 created_at + make_interval(secs => $3))
        WHERE id = $1`,
      [row.id, opts.session.idleSeconds, opts.session.maxSeconds],
    );
  }

  return {
    sessionId: row.id,
    role: user.role,
    institutionId: row.institution_id,
    me: {
      user: { id: user.id, email: user.email, name: user.name, role: user.role },
      institution,
    },
  };
}

export class AuthService {
  constructor(
    readonly db: Db,
    readonly opts: AuthOptions,
  ) {}

  /** Password login. Returns null for every failure so callers cannot tell the causes apart. */
  async login(
    email: string,
    password: string,
    meta: { ip: string | undefined; userAgent: string | undefined },
  ): Promise<{ token: string; me: AuthMe } | null> {
    const normalized = email.trim().toLowerCase();
    const user = await this.db.withLookup({ 'app.login_email': normalized }, async (c) => {
      const r = await c.query<{
        id: string;
        institution_id: string | null;
        email: string;
        name: string;
        password_hash: string | null;
        role: Role;
        status: string;
      }>(
        `SELECT id, institution_id, email, name, password_hash, role, status
           FROM users WHERE email = $1`,
        [normalized],
      );
      return r.rows[0];
    });

    // Always run one Argon2id verification, whatever the outcome of the lookup.
    const passwordOk = await verifyPassword(user?.password_hash ?? null, password);
    if (!user || !passwordOk || user.status !== 'ACTIVE') return null;

    const token = newSessionToken();
    const scope: Session = user.institution_id
      ? { kind: 'tenant', userId: user.id, institutionId: user.institution_id }
      : { kind: 'platform', userId: user.id };

    const me = await this.db.withTenant(scope, async (c) => {
      await c.query(
        `INSERT INTO sessions (id, institution_id, user_id, token_hash, expires_at, ip, user_agent)
         VALUES (gen_random_uuid(), $1, $2, $3, now() + make_interval(secs => $4), $5, $6)`,
        [
          user.institution_id,
          user.id,
          hashSessionToken(token),
          this.opts.session.idleSeconds,
          this.opts.hashIp(meta.ip) ?? null, // hashed, never the raw address (ADR 0003, ADR 0004)
          meta.userAgent ? meta.userAgent.slice(0, 200) : null,
        ],
      );
      let institution: AuthMe['institution'] = null;
      if (user.institution_id) {
        const i = await c.query<{ id: string; name: string; slug: string; status: string }>(
          `SELECT id, name, slug, status FROM institutions WHERE id = $1`,
          [user.institution_id],
        );
        institution = i.rows[0] ?? null;
      }
      return {
        user: { id: user.id, email: user.email, name: user.name, role: user.role },
        institution,
      } satisfies AuthMe;
    });
    return { token, me };
  }

  /** Resolve a raw cookie token to a live session, or null. */
  async resolve(token: string): Promise<ResolvedRow | null> {
    if (!TOKEN_RE.test(token)) return null;
    const tokenHash = hashSessionToken(token);
    return this.db.withLookup({ 'app.session_token_hash': tokenHash }, (c) =>
      resolveInTx(c, tokenHash, this.opts),
    );
  }

  /** Delete the session (idempotent). Requires the resolved scope so RLS permits the DELETE. */
  async destroy(auth: AuthSession): Promise<void> {
    await this.db.withTenant(auth, async (c) => {
      await c.query(`DELETE FROM sessions WHERE id = $1`, [auth.sessionId]);
    });
  }

  /** Best-effort removal of a session by raw token (used when logging in over an old cookie). */
  async destroyByToken(token: string): Promise<void> {
    const r = await this.resolve(token);
    if (r) await this.destroy(toAuthSession(r));
  }

  sessionCookie(token: string): string {
    return serializeCookie(this.opts.cookie, token, this.opts.session.maxSeconds);
  }
  clearCookie(): string {
    return serializeCookie(this.opts.cookie, '', 0);
  }
}

export function toAuthSession(r: ResolvedRow): AuthSession {
  const base = { sessionId: r.sessionId, role: r.role };
  return r.institutionId
    ? { kind: 'tenant', userId: r.me.user.id, institutionId: r.institutionId, ...base }
    : { kind: 'platform', userId: r.me.user.id, ...base };
}

// --- Fastify integration ---------------------------------------------------------------------------

declare module 'fastify' {
  interface FastifyRequest {
    /** Set by app.authenticate. null until then / when unauthenticated. */
    session: AuthSession | null;
    /** Profile payload for /auth/me, set together with session. */
    authMe: AuthMe | null;
    /** The raw session token from the cookie (for CSRF derivation). Never log it. */
    sessionToken: string | null;
  }
  interface FastifyInstance {
    auth: AuthService | undefined;
    /** preHandler: requires a valid session (401) and, for mutating methods, the CSRF header (403). */
    authenticate: preHandlerAsyncHookHandler;
    /** preHandler factory: authenticate, then require one of the roles (403). */
    requireRole: (...roles: Role[]) => preHandlerAsyncHookHandler;
  }
}

export function csrfOk(req: FastifyRequest): boolean {
  const sent = req.headers[CSRF_HEADER];
  if (typeof sent !== 'string' || !req.sessionToken) return false;
  const a = Buffer.from(sent);
  const b = Buffer.from(csrfTokenFor(req.sessionToken));
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Load the session from the cookie onto the request, without enforcing anything. */
export async function loadSession(req: FastifyRequest, svc: AuthService): Promise<void> {
  req.session = null;
  req.authMe = null;
  req.sessionToken = null;
  const token = readCookie(req.headers.cookie, svc.opts.cookie.name);
  if (!token) return;
  const r = await svc.resolve(token);
  if (!r) return;
  req.session = toAuthSession(r);
  req.authMe = r.me;
  req.sessionToken = token;
}

export function setNoStore(reply: FastifyReply): void {
  void reply.header('Cache-Control', 'no-store');
}

export function enforceCsrf(req: FastifyRequest): void {
  if (!SAFE_METHODS.has(req.method) && !csrfOk(req)) {
    throw new AppError(403, 'CSRF_REQUIRED', 'Missing or invalid CSRF token');
  }
}

export { unauthenticated };
