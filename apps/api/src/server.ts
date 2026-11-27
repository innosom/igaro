import { assertRuntimeRole } from '@igaro/db';
import { buildApp } from './app.js';
import { loadConfig } from './config.js';
import { Db } from './db.js';
import { S3ObjectStorage } from './storage.js';
import {
  NoopAccountMailQueue,
  NoopCardRenderQueue,
  NoopHolderDeliveryQueue,
  NoopImportBatchQueue,
  type AccountMailQueue,
  type CardRenderQueue,
  type HolderDeliveryQueue,
  type ImportBatchQueue,
} from './notifications.js';

const config = loadConfig();
const db = new Db({ connectionString: config.appDatabaseUrl });
// T-050 (ADR 0037): refuse to start in production on a role that would bypass RLS.
await assertRuntimeRole(db.pool, {
  nodeEnv: config.nodeEnv,
  warn: (m) => console.warn(m),
});

// Account mail goes through pg-boss when ACCOUNT_MAIL_QUEUE=pgboss (ADR 0006); otherwise it is dropped.
let accountMail: AccountMailQueue = new NoopAccountMailQueue();
let cardRender: CardRenderQueue = new NoopCardRenderQueue();
let holderDelivery: HolderDeliveryQueue = new NoopHolderDeliveryQueue();
let importBatch: ImportBatchQueue = new NoopImportBatchQueue();
let stopQueue: (() => Promise<void>) | undefined;
if (config.accountMail.driver === 'pgboss') {
  // Lazy: needs the worker package built (`pnpm --filter @igaro/worker build`; `pnpm -r build` orders it).
  const { connectProducerQueues } = await import('@igaro/worker/producer');
  // One pg-boss connection for both producers (account mail and card render).
  const q = await connectProducerQueues({
    connectionString: config.accountMail.databaseUrl,
    schema: config.accountMail.schema,
    deliveryKey: config.deliveryPayloadKey,
    schemaMode: config.accountMail.schemaMode,
  });
  // Invite and reset tokens are sealed with DELIVERY_PAYLOAD_KEY (ADR 0038). Without it (allowed outside production)
  // no account mail is queued: a clear token never goes into the job table.
  if (q.accountMail) accountMail = q.accountMail;
  else console.warn('DELIVERY_PAYLOAD_KEY not set: invite and password reset mail is not queued');
  cardRender = q.cardRender;
  importBatch = q.importBatch;
  // Without DELIVERY_PAYLOAD_KEY (allowed outside production) no holder email is queued.
  if (q.holderDelivery) holderDelivery = q.holderDelivery;
  stopQueue = q.stop;
}

const storage = config.s3 ? new S3ObjectStorage(config.s3) : undefined;
const app = await buildApp({ config, db, accountMail, cardRender, holderDelivery, importBatch, storage });
app.addHook('onClose', async () => {
  await stopQueue?.();
  await db.close();
});
await app.listen({ host: config.host, port: config.port });
