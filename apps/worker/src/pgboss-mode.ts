// How a process treats the pg-boss schema (T-051, ADR 0038). Kept tiny: producers and the worker both import it.

/**
 * `auto`: this process creates and migrates the pg-boss schema and queues itself (development, tests; needs CREATE rights).
 * `external`: the schema was provisioned by the owner (`pnpm db:pgboss`, see pgboss-setup.ts); the process only checks
 * it and never creates or alters anything. Production default.
 */
export type PgbossSchemaMode = 'auto' | 'external';

/** pg-boss constructor options for a process that must not change the schema's structure. */
export const externalSchemaOptions = (mode: PgbossSchemaMode): { migrate?: false; createSchema?: false } =>
  mode === 'external' ? { migrate: false, createSchema: false } : {};

export function parsePgbossSchemaMode(raw: string | undefined, nodeEnv: string): PgbossSchemaMode {
  if (raw === undefined || raw === '') return nodeEnv === 'production' ? 'external' : 'auto';
  if (raw !== 'auto' && raw !== 'external') throw new Error('PGBOSS_SCHEMA_MODE must be auto or external');
  return raw;
}
