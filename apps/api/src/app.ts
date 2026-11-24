import Fastify, { type FastifyError, type FastifyInstance } from 'fastify';
import type { DestinationStream } from 'pino';
import type { Config } from './config.js';
import type { Db } from './db.js';
import { AppError } from './errors.js';
import { loggerOptions } from './logging.js';

export const API_PREFIX = '/api/v1';

export interface BuildAppOptions {
  config: Pick<Config, 'logLevel'>;
  db?: Db;
  /** Log destination; tests capture logs here. */
  logStream?: DestinationStream;
}

declare module 'fastify' {
  interface FastifyInstance {
    db: Db | undefined;
  }
}

const errBody = (code: string, message: string) => ({ error: { code, message } });

export async function buildApp(opts: BuildAppOptions): Promise<FastifyInstance> {
  const base = loggerOptions(opts.config.logLevel);
  const app = Fastify({
    logger: opts.logStream ? { ...base, stream: opts.logStream } : base,
    trustProxy: false,
    bodyLimit: 1024 * 1024,
  });
  app.decorate('db', opts.db);

  app.setErrorHandler((err: FastifyError | AppError, req, reply) => {
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

  await app.register(
    async (api) => {
      api.get('/health', async () => ({ status: 'ok' }));
    },
    { prefix: API_PREFIX },
  );

  return app;
}
