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
import { AppError } from './errors.js';

const MAX_EMAIL = 254;
const MAX_PASSWORD = 256;

const LOGIN_FAILED = () => new AppError(401, 'INVALID_CREDENTIALS', 'Invalid email or password');

/** Decorates the app with authenticate/requireRole and registers /auth/login, /logout, /me. */
export function registerAuth(app: FastifyInstance, svc: AuthService): void {
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
    // Login is exempt from the CSRF header (there is no session yet). It is safe against login CSRF
    // because the body parser accepts only application/json (a cross-site form cannot send it
    // without a CORS preflight, and no CORS is enabled) and the cookie is SameSite=Lax.
    // Fastify also parses text/plain by default, which a cross-site form can send: refuse it here.
    if (!/^application\/json\s*(;|$)/i.test(req.headers['content-type'] ?? '')) {
      throw new AppError(415, 'UNSUPPORTED_MEDIA_TYPE', 'Invalid request');
    }
    const body = req.body as { email?: unknown; password?: unknown } | null | undefined;
    const email = body?.email;
    const password = body?.password;
    if (
      typeof email !== 'string' ||
      typeof password !== 'string' ||
      email.length === 0 ||
      email.length > MAX_EMAIL ||
      password.length === 0 ||
      password.length > MAX_PASSWORD
    ) {
      throw new AppError(400, 'BAD_REQUEST', 'Invalid request');
    }

    const result = await svc.login(email, password, {
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });
    if (!result) throw LOGIN_FAILED();

    // Replace any session the browser already holds (session fixation / stale cookie).
    const old = readCookie(req.headers.cookie, svc.opts.cookie.name);
    if (old) await svc.destroyByToken(old).catch(() => undefined);

    void reply.header('Set-Cookie', svc.sessionCookie(result.token));
    return { ...result.me, csrfToken: csrfTokenFor(result.token) };
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
