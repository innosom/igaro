// Owner-side provisioning of the pg-boss schema with least-privilege grants (T-051, ADR 0038).
//
// Why: pg-boss keeps jobs outside RLS. The API role must be able to ENQUEUE and nothing else, so a SQL injection in the
// API cannot read, alter or delete pending jobs (threat-model row 16). The worker role runs the queue (full rights in
// this schema only). The schema is created by the OWNER (DATABASE_URL, the migrator), never by the runtime roles.
//
// What it does, all idempotent:
//   1. CREATE SCHEMA, REVOKE from PUBLIC, USAGE for both roles, CREATE for the worker, default privileges for the worker.
//   2. Install or upgrade pg-boss (its own DDL and migrations) as the owner, and create every queue with the shared options.
//   3. Worker: ALL on every table, EXECUTE on every function.
//      API (igaro_app): SELECT on version and queue, INSERT on job and its partitions plus SELECT of the id and
//      start_after columns only (INSERT ... RETURNING needs it), EXECUTE on job_now(). Nothing else: the job data
//      (sealed or not) cannot be read; no UPDATE, DELETE or TRUNCATE.
// Re-run it after a pg-boss upgrade (the owner applies pg-boss migrations; runtime roles use PGBOSS_SCHEMA_MODE=external).
import pg from 'pg';
import { PgBoss } from 'pg-boss';
import { ACCOUNT_MAIL_QUEUE } from './account-mail-job.js';
import { ACCOUNT_MAIL_QUEUE_OPTIONS } from './account-mail-producer.js';
import { CARD_RENDER_QUEUE, CARD_RENDER_QUEUE_OPTIONS } from './card-render-job.js';
import { HOLDER_DELIVERY_QUEUE, HOLDER_DELIVERY_QUEUE_OPTIONS } from './holder-delivery-job.js';
import { IMPORT_BATCH_QUEUE, IMPORT_BATCH_QUEUE_OPTIONS } from './import-batch-job.js';

const IDENT = /^[a-z_][a-z0-9_]{0,62}$/;
const q = (ident: string): string => `"${ident}"`;

/** Every queue any process may send to. Created here so the API role never needs to create one. */
export const PGBOSS_QUEUES: readonly { name: string; options: object }[] = [
  { name: ACCOUNT_MAIL_QUEUE, options: ACCOUNT_MAIL_QUEUE_OPTIONS },
  { name: CARD_RENDER_QUEUE, options: CARD_RENDER_QUEUE_OPTIONS },
  { name: IMPORT_BATCH_QUEUE, options: IMPORT_BATCH_QUEUE_OPTIONS },
  { name: HOLDER_DELIVERY_QUEUE, options: HOLDER_DELIVERY_QUEUE_OPTIONS },
];

export interface PgbossSetupOptions {
  /** Owner / migrator connection (DATABASE_URL). Never a runtime role. */
  ownerUrl: string;
  schema?: string;
  workerRole?: string;
  apiRole?: string;
}

/** Statements that run BEFORE pg-boss creates its tables. The `pgboss` instance of this is also in a db migration. */
export function skeletonSql(schema: string, workerRole: string, apiRole: string): string[] {
  const s = q(schema);
  return [
    `CREATE SCHEMA IF NOT EXISTS ${s}`,
    `REVOKE ALL ON SCHEMA ${s} FROM PUBLIC`,
    `GRANT USAGE ON SCHEMA ${s} TO ${q(workerRole)}, ${q(apiRole)}`,
    `GRANT CREATE ON SCHEMA ${s} TO ${q(workerRole)}`,
    `ALTER DEFAULT PRIVILEGES IN SCHEMA ${s} GRANT ALL ON TABLES TO ${q(workerRole)}`,
    `ALTER DEFAULT PRIVILEGES IN SCHEMA ${s} GRANT ALL ON SEQUENCES TO ${q(workerRole)}`,
    `ALTER DEFAULT PRIVILEGES IN SCHEMA ${s} GRANT EXECUTE ON FUNCTIONS TO ${q(workerRole)}`,
  ];
}

/** Statements that run AFTER pg-boss has created its tables and functions. */
export function grantSql(schema: string, workerRole: string, apiRole: string): string[] {
  const s = q(schema);
  const w = q(workerRole);
  const a = q(apiRole);
  return [
    `REVOKE ALL ON ALL TABLES IN SCHEMA ${s} FROM PUBLIC, ${a}`,
    `REVOKE ALL ON ALL SEQUENCES IN SCHEMA ${s} FROM PUBLIC, ${a}`,
    `REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA ${s} FROM PUBLIC, ${a}`,
    `GRANT ALL ON ALL TABLES IN SCHEMA ${s} TO ${w}`,
    `GRANT ALL ON ALL SEQUENCES IN SCHEMA ${s} TO ${w}`,
    `GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA ${s} TO ${w}`,
    // Enqueue only.
    `GRANT SELECT ON ${s}.version, ${s}.queue TO ${a}`,
    // INSERT ... RETURNING id needs SELECT on the returned columns; nothing else of a job is readable (not data,
    // output, singleton_key or any other column).
    `GRANT INSERT, SELECT (id, start_after) ON ${s}.job TO ${a}`,
    `GRANT EXECUTE ON FUNCTION ${s}.job_now() TO ${a}`,
  ];
}

/** INSERT on every partition of the job table (the default one, and any per-queue partition that exists). */
const PARTITION_GRANT = (schema: string, apiRole: string): string => `
DO $do$
DECLARE r record;
BEGIN
  FOR r IN SELECT c.oid::regclass AS tbl FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
            WHERE i.inhparent = to_regclass('${q(schema)}.job')
  LOOP
    EXECUTE format('GRANT INSERT, SELECT (id, start_after) ON %s TO ${q(apiRole)}', r.tbl);
  END LOOP;
END
$do$`;

export async function setupPgbossSchema(opts: PgbossSetupOptions): Promise<void> {
  const schema = opts.schema ?? 'pgboss';
  const workerRole = opts.workerRole ?? 'igaro_worker';
  const apiRole = opts.apiRole ?? 'igaro_app';
  for (const [name, v] of [['schema', schema], ['worker role', workerRole], ['API role', apiRole]] as const) {
    if (!IDENT.test(v)) throw new Error(`pg-boss setup: ${name} must be a simple lower-case identifier`);
  }
  const client = new pg.Client({ connectionString: opts.ownerUrl });
  await client.connect();
  try {
    // One connection throughout: default privileges apply to objects created by the role that set them.
    for (const stmt of skeletonSql(schema, workerRole, apiRole)) await client.query(stmt);
  } finally {
    await client.end();
  }

  // pg-boss installs or migrates its own objects (as the owner) and the queues get created once, here.
  const boss = new PgBoss({
    connectionString: opts.ownerUrl,
    schema,
    supervise: false,
    schedule: false,
    registerInstance: false,
    max: 2,
  });
  boss.on('error', () => undefined);
  try {
    await boss.start();
    for (const queue of PGBOSS_QUEUES) await boss.createQueue(queue.name, queue.options);
  } finally {
    await boss.stop({ graceful: true, timeout: 5000 });
  }

  const after = new pg.Client({ connectionString: opts.ownerUrl });
  await after.connect();
  try {
    for (const stmt of grantSql(schema, workerRole, apiRole)) await after.query(stmt);
    await after.query(PARTITION_GRANT(schema, apiRole));
  } finally {
    await after.end();
  }
}
