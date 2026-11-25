// Worker entrypoint: `pnpm --filter @igaro/worker start`.
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
