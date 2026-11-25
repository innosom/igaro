import type { FastifyInstance, FastifyRequest } from 'fastify';
import {
  AuthService,
  csrfTokenFor,
  enforceCsrf,
  loadSession,
  readCookie,
  setNoStore,
  unauthenticated,
  type AuthOptions,
  type Role,
} from './auth.js';
import { MAX_PASSWORD, normalizeEmail, type AccountService } from './account.js';
import type { RateLimitConfig } from './config.js';
import { AppError, RateLimitedError } from './errors.js';
import { RateLimiter } from './rate-limit.js';
import { sha256Hex } from './auth.js';

const MAX_EMAIL = 254;
const MAX_TOKEN = 128;
const MAX_NAME = 200;

const LOGIN_FAILED = () => new AppError(401, 'INVALID_CREDENTIALS', 'Invalid email or password');

// Unauthenticated JSON endpoints have no CSRF token. They are safe against cross-site posts because
// they accept only application/json (a cross-site form cannot send it without a CORS preflight and
// no CORS is enabled). Fastify also parses text/plain by default, which a form can send: refuse it.
function requireJson(req: FastifyRequest): void {
  if (!/^application\/json\s*(;|$)/i.test(req.headers['content-type'] ?? '')) {
    throw new AppError(415, 'UNSUPPORTED_MEDIA_TYPE', 'Invalid request');
  }
}

const bodyOf = (req: FastifyRequest): Record<string, unknown> => {
  const b = req.body;
  return b && typeof b === 'object' && !Array.isArray(b) ? (b as Record<string, unknown>) : {};
};

const str = (v: unknown, max: number): string => {
  if (typeof v !== 'string' || v.length === 0 || v.length > max) {
    throw new AppError(400, 'BAD_REQUEST', 'Invalid request');
  }
  return v;
};

/** Decorates the app with authenticate/requireRole and registers the /auth/* routes. */
export function registerAuth(
  app: FastifyInstance,
  svc: AuthService,
  account: AccountService,
  limits: RateLimitConfig,
): void {
  const mk = (max: number, windowSeconds: number) => new RateLimiter({ max, windowSeconds });
  const loginIp = mk(limits.login.ipMax, limits.login.windowSeconds);
  const loginAccount = mk(limits.login.accountMax, limits.login.windowSeconds);
  const resetIp = mk(limits.reset.ipMax, limits.reset.windowSeconds);
  const resetAccount = mk(limits.reset.accountMax, limits.reset.windowSeconds);
  const tokenIp = mk(limits.token.ipMax, limits.token.windowSeconds);
  // Keys are hashed: no raw IP or email sits in memory tables. Namespaced per limiter family.
  const ipKey = (req: FastifyRequest) => svc.opts.hashIp(req.ip) ?? 'unknown';
  const acctKey = (email: string) => sha256Hex(`acct:${normalizeEmail(email)}`);
  const enforce = (limiter: RateLimiter, key: string): void => {
    const wait = limiter.consume(key);
    if (wait > 0) throw new RateLimitedError(wait);
  };

  app.decorate('auth', svc);
  app.decorateRequest('session', null);
  app.decorateRequest('authMe', null);
  app.decorateRequest('sessionToken', null);

  const authenticate = async (req: FastifyRequest): Promise<void> => {
    await loadSession(req, svc);
    if (!req.session) throw unauthenticated();
    enforceCsrf(req);
  };
  app.decorate('authenticate', authenticate);
  app.decorate('requireRole', (...roles: Role[]) => async (req: FastifyRequest) => {
    await authenticate(req);
    if (!req.session || !roles.includes(req.session.role)) {
      throw new AppError(403, 'FORBIDDEN', 'Insufficient role');
    }
  });

  app.post('/auth/login', async (req, reply) => {
    setNoStore(reply);
    // Login is exempt from the CSRF header (there is no session yet); see requireJson and ADR 0004.
    requireJson(req);
    const b = bodyOf(req);
    const email = str(b.email, MAX_EMAIL);
    const password = str(b.password, MAX_PASSWORD);

    // Per IP: every attempt. Per account: every attempt until a success (cleared below), so
    // parallel guesses cannot overshoot. Both run before any Argon2id work. The account key is
    // derived from the submitted email whether or not the account exists.
    enforce(loginIp, ipKey(req));
    const aKey = acctKey(email);
    enforce(loginAccount, aKey);

    const result = await svc.login(email, password, {
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });
    if (!result) throw LOGIN_FAILED();
    loginAccount.reset(aKey);

    // Replace any session the browser already holds (session fixation / stale cookie).
    const old = readCookie(req.headers.cookie, svc.opts.cookie.name);
    if (old) await svc.destroyByToken(old).catch(() => undefined);

    void reply.header('Set-Cookie', svc.sessionCookie(result.token));
    return { ...result.me, csrfToken: csrfTokenFor(result.token) };
  });

  app.post('/auth/invites/accept', async (req, reply) => {
    setNoStore(reply);
    requireJson(req);
    enforce(tokenIp, ipKey(req));
    const b = bodyOf(req);
    const token = str(b.token, MAX_TOKEN);
    const password = str(b.password, MAX_PASSWORD + 1);
    const name = b.name === undefined ? undefined : str(b.name, MAX_NAME);
    await account.acceptInvite(token, password, name);
    return reply.status(204).send();
  });

  app.post('/auth/password-reset', async (req, reply) => {
    setNoStore(reply);
    requireJson(req);
    const b = bodyOf(req);
    if (b.token !== undefined) {
      // Confirm mode: { token, password }
      enforce(tokenIp, ipKey(req));
      const token = str(b.token, MAX_TOKEN);
      const password = str(b.password, MAX_PASSWORD + 1);
      await account.confirmReset(token, password);
      // The user's sessions are gone; drop the cookie of this browser too.
      void reply.header('Set-Cookie', svc.clearCookie());
      return reply.status(204).send();
    }
    // Request mode: { email }. Always 202, whatever the email is (no account enumeration). The
    // limits apply to the address as typed, whether or not it has an account.
    const email = str(b.email, MAX_EMAIL);
    enforce(resetIp, ipKey(req));
    enforce(resetAccount, acctKey(email));
    try {
      await account.requestReset(email);
    } catch (err) {
      // Same response for internal failures as for success or unknown email; log without the email.
      req.log.error({ err }, 'password reset request failed');
    }
    return reply.status(202).send({ status: 'accepted' });
  });

  app.post('/auth/logout', async (req, reply) => {
    setNoStore(reply);
    await loadSession(req, svc);
    if (req.session) {
      enforceCsrf(req);
      await svc.destroy(req.session);
    }
    // Idempotent: also clears a stale/unknown cookie.
    void reply.header('Set-Cookie', svc.clearCookie());
    return reply.status(204).send();
  });

  app.get('/auth/me', { preHandler: app.authenticate }, async (req, reply) => {
    setNoStore(reply);
    return { ...req.authMe, csrfToken: csrfTokenFor(req.sessionToken ?? '') };
  });
}

export type { AuthOptions };
