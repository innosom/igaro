import { buildApp } from './app.js';
import { loadConfig } from './config.js';
import { Db } from './db.js';

const config = loadConfig();
const db = new Db({ connectionString: config.appDatabaseUrl });
const app = await buildApp({ config, db });
app.addHook('onClose', async () => db.close());
await app.listen({ host: config.host, port: config.port });
