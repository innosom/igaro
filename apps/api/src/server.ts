import { buildApp } from './app.js';
import { loadConfig } from './config.js';
import { Db } from './db.js';
import { S3ObjectStorage } from './storage.js';
import { NoopAccountMailQueue, type AccountMailQueue } from './notifications.js';

const config = loadConfig();
const db = new Db({ connectionString: config.appDatabaseUrl });

// Account mail goes through pg-boss when ACCOUNT_MAIL_QUEUE=pgboss (ADR 0006); otherwise it is dropped.
let accountMail: AccountMailQueue = new NoopAccountMailQueue();
let stopQueue: (() => Promise<void>) | undefined;
if (config.accountMail.driver === 'pgboss') {
  // Lazy: needs the worker package built (`pnpm --filter @igaro/worker build`; `pnpm -r build` orders it).
  const { connectAccountMailQueue } = await import('@igaro/worker/producer');
  const q = await connectAccountMailQueue({
    connectionString: config.accountMail.databaseUrl,
    schema: config.accountMail.schema,
  });
  accountMail = q.queue;
  stopQueue = q.stop;
}

const storage = config.s3 ? new S3ObjectStorage(config.s3) : undefined;
const app = await buildApp({ config, db, accountMail, storage });
app.addHook('onClose', async () => {
  await stopQueue?.();
  await db.close();
});
await app.listen({ host: config.host, port: config.port });
