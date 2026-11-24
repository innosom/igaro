// Entry point for `pnpm db:seed`. Connects with DATABASE_URL (owner role).
// Logs counts on success and only the error code + message on failure (no row detail, no values).
import pg from 'pg';
import { loadSeedConfig, runSeed } from './seed.js';

function fail(e: unknown): never {
  const err = e as { code?: unknown; message?: unknown };
  const code = typeof err.code === 'string' ? err.code : 'ERROR';
  // pg errors may carry a `detail` with row values; it is deliberately not printed.
  const message = typeof err.message === 'string' ? err.message : 'seed failed';
  console.error(`seed failed [${code}]: ${message}`);
  process.exit(1);
}

const url = process.env.DATABASE_URL;
if (!url) fail(new Error('DATABASE_URL is not set'));

let client: pg.Client | undefined;
try {
  const config = loadSeedConfig();
  client = new pg.Client({ connectionString: url });
  await client.connect();
  const { created } = await runSeed(client, config);
  console.log(
    `seed complete: ${JSON.stringify(created)} (rows newly created; all zero means already seeded)`,
  );
} catch (e) {
  fail(e);
} finally {
  await client?.end().catch(() => undefined);
}
