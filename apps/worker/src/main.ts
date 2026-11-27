// Worker entrypoint: `pnpm --filter @igaro/worker start`.
import { assertRuntimeRole } from '@igaro/db';
import pg from 'pg';
import { ConfigError, loadWorkerConfig } from './config.js';
import { createLogger } from './logger.js';
import { startWorkerFromConfig } from './worker.js';

let config;
try {
  config = loadWorkerConfig();
} catch (err) {
  // ConfigError messages name the variable, never the value.
  console.error(err instanceof ConfigError ? err.message : 'invalid worker configuration');
  process.exit(1);
}

const logger = createLogger(config.logLevel);
// T-050 (ADR 0037): refuse to start in production on a role that would bypass RLS.
{
  const checkPool = new pg.Pool({ connectionString: config.databaseUrl, max: 1 });
  try {
    await assertRuntimeRole(checkPool, { nodeEnv: config.nodeEnv, warn: (m) => logger.warn(m) });
  } catch (err) {
    console.error(err instanceof Error ? err.message : 'runtime database role check failed');
    process.exit(1);
  } finally {
    await checkPool.end();
  }
}
const worker = await startWorkerFromConfig(config, logger);

let stopping = false;
const shutdown = (signal: string) => {
  if (stopping) return;
  stopping = true;
  logger.info({ signal }, 'shutting down');
  worker.stop().then(
    () => process.exit(0),
    () => process.exit(1),
  );
};
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
