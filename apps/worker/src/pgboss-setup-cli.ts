// `pnpm db:pgboss`: provision the pg-boss schema as the OWNER (ADR 0038). Run after `db:migrate`, and again after a
// pg-boss upgrade. Reads DATABASE_URL (owner, same variable as the migrations) and PGBOSS_SCHEMA. Prints no URLs.
import { setupPgbossSchema } from './pgboss-setup.js';

const ownerUrl = process.env.DATABASE_URL;
if (!ownerUrl) {
  console.error('DATABASE_URL (the owner/migrator connection) is required');
  process.exit(1);
}
const schema = process.env.PGBOSS_SCHEMA || 'pgboss';
try {
  await setupPgbossSchema({
    ownerUrl,
    schema,
    ...(process.env.PGBOSS_WORKER_ROLE ? { workerRole: process.env.PGBOSS_WORKER_ROLE } : {}),
    ...(process.env.PGBOSS_API_ROLE ? { apiRole: process.env.PGBOSS_API_ROLE } : {}),
  });
  console.log(`pg-boss schema "${schema}" provisioned: worker has full rights, API role may only enqueue`);
} catch (err) {
  // Error text could echo connection details: print the class and code only.
  const e = err as { name?: string; code?: string };
  console.error(`pg-boss setup failed (${e.name ?? 'Error'}${e.code ? ` ${e.code}` : ''})`);
  process.exit(1);
}
