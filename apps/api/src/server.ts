import { buildApp } from './app.js';
import { loadConfig } from './config.js';
import { Db } from './db.js';
import { S3ObjectStorage } from './storage.js';
import { NoopAccountMailQueue, NoopCardRenderQueue, type AccountMailQueue, type CardRenderQueue } from './notifications.js';

const config = loadConfig();
const db = new Db({ connectionString: config.appDatabaseUrl });

// Account mail goes through pg-boss when ACCOUNT_MAIL_QUEUE=pgboss (ADR 0006); otherwise it is dropped.
let accountMail: AccountMailQueue = new NoopAccountMailQueue();
let cardRender: CardRenderQueue = new NoopCardRenderQueue();
let stopQueue: (() => Promise<void>) | undefined;
if (config.accountMail.driver === 'pgboss') {
  // Lazy: needs the worker package built (`pnpm --filter @igaro/worker build`; `pnpm -r build` orders it).
  const { connectProducerQueues } = await import('@igaro/worker/producer');
  // One pg-boss connection for both producers (account mail and card render).
  const q = await connectProducerQueues({
    connectionString: config.accountMail.databaseUrl,
    schema: config.accountMail.schema,
  });
  accountMail = q.accountMail;
  cardRender = q.cardRender;
  stopQueue = q.stop;
}

const storage = config.s3 ? new S3ObjectStorage(config.s3) : undefined;
const app = await buildApp({ config, db, accountMail, cardRender, storage });
app.addHook('onClose', async () => {
  await stopQueue?.();
  await db.close();
});
await app.listen({ host: config.host, port: config.port });
