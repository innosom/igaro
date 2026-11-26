import { randomBytes } from 'node:crypto';
import Fastify, { type FastifyError, type FastifyInstance } from 'fastify';
import type { DestinationStream } from 'pino';
import { AccountService } from './account.js';
import { DEFAULT_RATE_LIMIT, type Config } from './config.js';
import type { Db } from './db.js';
import { AppError, RateLimitedError } from './errors.js';
import type { AccountMailQueue, CardRenderQueue, HolderDeliveryQueue } from './notifications.js';
import { registerCardEndpoints } from './card-endpoints.js';
import { AuthService } from './auth.js';
import { registerAuth } from './auth-routes.js';
import { InstitutionService, registerInstitutions } from './institutions.js';
import { SigningKeyService, registerSigningKeys, type KeyChangeRateLimit } from './signing-keys.js';
import { DEFAULT_LOGO_MAX_BYTES, registerInstitutionProfile } from './institution-profile.js';
import { registerCredentialTypes } from './credential-types.js';
import { CredentialService, registerCredentials } from './credentials.js';
import { CredentialLifecycleService, registerCredentialLifecycle } from './credential-lifecycle.js';
import { CredentialQueryService, registerCredentialQueries } from './credential-queries.js';
import { DEFAULT_PHOTO_MAX_BYTES, registerHolders } from './holders.js';
import type { ObjectStorage } from './storage.js';
import { PublicLookupService, registerHolderView, registerPublicKeys } from './public-lookups.js';
import { VerifyService, registerVerify } from './verify.js';
import { hashIp, loggerOptions } from './logging.js';

// Safe defaults when a caller (tests) does not pass cookie/session config: Secure cookie, 1 h idle, 12 h max.
const DEFAULT_COOKIE: Config['cookie'] = {
  name: 'igaro_session',
  secure: true,
  sameSite: 'lax',
  domain: undefined,
};
const DEFAULT_SESSION: Config['session'] = { idleSeconds: 3600, maxSeconds: 12 * 3600 };

export const API_PREFIX = '/api/v1';

export interface BuildAppOptions {
  /** ipHashKey and trustProxy come from loadConfig in production; tests may omit them. */
  config: Pick<Config, 'logLevel'> &
    Partial<
      Pick<
        Config,
        'ipHashKey' | 'trustProxy' | 'cookie' | 'session' | 'tokenTtl' | 'rateLimit' | 'masterKey' | 'logoMaxBytes' | 'photoMaxBytes' | 'auditHeadPublicKeys'
      >
    >;
  db?: Db;
  /** Where invite/reset mail jobs go. Defaults to a no-op until the worker queue exists (T-011). */
  accountMail?: AccountMailQueue;
  /** Where card.render jobs go after issuance/reissue commit (ids only). Without it nothing is queued. */
  cardRender?: CardRenderQueue;
  /** Holder email delivery after issue/reissue (T-041, ADR 0030). Omitted = nothing is queued. */
  holderDelivery?: HolderDeliveryQueue;
  /** Private object storage for logos. Without it POST /institution/logo answers 503. */
  storage?: ObjectStorage;
  /** Per-institution limit for key rotation and compromise (default 10 per hour). */
  keyChangeRateLimit?: KeyChangeRateLimit;
  /** Log destination; tests capture logs here. */
  logStream?: DestinationStream;
}

declare module 'fastify' {
  interface FastifyInstance {
    db: Db | undefined;
  }
}

/** Map the TRUST_PROXY setting to Fastify: a hop count trusts the nearest N proxies (ADR 0003). */
function fastifyTrustProxy(
  v: false | number | string,
): boolean | string | ((addr: string, i: number) => boolean) {
  if (typeof v === 'number') return (_addr: string, i: number) => i < v;
  return v;
}

const errBody = (code: string, message: string) => ({ error: { code, message } });

export async function buildApp(opts: BuildAppOptions): Promise<FastifyInstance> {
  const ipHashKey = opts.config.ipHashKey ?? randomBytes(32);
  const base = loggerOptions(opts.config.logLevel, ipHashKey);
  const app = Fastify({
    logger: opts.logStream ? { ...base, stream: opts.logStream } : base,
    trustProxy: fastifyTrustProxy(opts.config.trustProxy ?? false),
    bodyLimit: 1024 * 1024,
    routerOptions: { maxParamLength: 1024 }, // so over-long verification tokens reach the handler as a normal NOT_FOUND
  });
  app.decorate('db', opts.db);

  app.setErrorHandler((err: FastifyError | AppError, req, reply) => {
    if (err instanceof RateLimitedError) {
      void reply.header('Retry-After', String(err.retryAfterSeconds));
    }
    if (err instanceof AppError) {
      return reply.status(err.statusCode).send(errBody(err.code, err.message));
    }
    const status = (err as FastifyError).statusCode;
    if (status && status >= 400 && status < 500) {
      // Fastify's own client errors (bad JSON, too large, ...). Fixed messages, nothing echoed.
      const code =
        status === 413
          ? 'PAYLOAD_TOO_LARGE'
          : status === 415
            ? 'UNSUPPORTED_MEDIA_TYPE'
            : 'BAD_REQUEST';
      return reply.status(status).send(errBody(code, 'Invalid request'));
    }
    req.log.error({ err }, 'unhandled error');
    return reply.status(500).send(errBody('INTERNAL', 'Internal server error'));
  });
  app.setNotFoundHandler((_req, reply) =>
    reply.status(404).send(errBody('NOT_FOUND', 'Not found')),
  );

  const publicLookups = opts.db
    ? new PublicLookupService({ db: opts.db, hashIp: (ip) => hashIp(ip, ipHashKey), rateLimit: opts.config.rateLimit?.verify, storage: opts.storage, log: app.log })
    : undefined;
  // Public keys live at the site root (/i/:slug/keys.json), outside /api/v1 (ADR 0023).
  if (publicLookups) registerPublicKeys(app, publicLookups);

  await app.register(
    async (api) => {
      api.get('/health', async () => ({ status: 'ok' }));
      if (opts.db) {
        const account = new AccountService(opts.db, {
          queue: opts.accountMail,
          tokenTtl: opts.config.tokenTtl,
          log: app.log,
        });
        registerAuth(
          api,
          new AuthService(opts.db, {
            cookie: opts.config.cookie ?? DEFAULT_COOKIE,
            session: opts.config.session ?? DEFAULT_SESSION,
            hashIp: (ip) => hashIp(ip, ipHashKey),
          }),
          account,
          opts.config.rateLimit ?? DEFAULT_RATE_LIMIT,
        );
        registerInstitutions(
          api,
          new InstitutionService(opts.db, account, {
            masterKey: opts.config.masterKey,
            log: app.log,
            hashIp: (ip) => hashIp(ip, ipHashKey),
          }),
          app.log,
        );
        registerSigningKeys(
          api,
          new SigningKeyService(opts.db, opts.config.masterKey, {
            ...(opts.keyChangeRateLimit ? { rateLimit: opts.keyChangeRateLimit } : {}),
            hashIp: (ip) => hashIp(ip, ipHashKey),
          }),
          app.log,
        );
        registerInstitutionProfile(api, {
          db: opts.db,
          storage: opts.storage,
          logoMaxBytes: opts.config.logoMaxBytes ?? DEFAULT_LOGO_MAX_BYTES,
          log: app.log,
          hashIp: (ip) => hashIp(ip, ipHashKey),
        });
        registerCredentialTypes(api, { db: opts.db, log: app.log, hashIp: (ip) => hashIp(ip, ipHashKey) });
        const credentialOpts = { masterKey: opts.config.masterKey, hashIp: (ip: string | undefined) => hashIp(ip, ipHashKey) };
        const delivery = opts.holderDelivery ? { queue: opts.holderDelivery, db: opts.db } : undefined;
        registerCredentials(api, new CredentialService(opts.db, credentialOpts), app.log, opts.cardRender, delivery);
        registerCredentialLifecycle(api, new CredentialLifecycleService(opts.db, credentialOpts), app.log, opts.cardRender, delivery);
        registerCardEndpoints(api, { db: opts.db, storage: opts.storage, log: app.log });
        registerCredentialQueries(api, new CredentialQueryService(opts.db, opts.config.auditHeadPublicKeys ?? {}));
        registerVerify(
          api,
          new VerifyService({
            db: opts.db,
            storage: opts.storage,
            log: app.log,
            hashIp: (ip) => hashIp(ip, ipHashKey),
            rateLimit: opts.config.rateLimit?.verify,
          }),
        );
        if (publicLookups) registerHolderView(api, publicLookups);
        registerHolders(api, {
          db: opts.db,
          storage: opts.storage,
          photoMaxBytes: opts.config.photoMaxBytes ?? DEFAULT_PHOTO_MAX_BYTES,
          log: app.log,
          hashIp: (ip) => hashIp(ip, ipHashKey),
        });
      }
    },
    { prefix: API_PREFIX },
  );

  return app;
}
