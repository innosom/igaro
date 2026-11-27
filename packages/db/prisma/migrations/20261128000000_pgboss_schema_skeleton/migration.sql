-- T-051 (ADR 0038): the pg-boss schema is created by the OWNER (this migration), not by the runtime roles.
-- pg-boss keeps jobs outside RLS, so the API role (igaro_app) must be able to enqueue and nothing else.
--
-- This migration is the stable, version-independent half for the default schema name "pgboss":
--   * the schema exists and is closed to PUBLIC;
--   * igaro_app and igaro_worker may USE it; igaro_worker may also CREATE in it (pg-boss maintenance partitions);
--   * every table, sequence and function the OWNER creates in it later is granted to igaro_worker automatically.
-- The version-dependent half (pg-boss's own tables and functions, the queues, and the enqueue-only grants for
-- igaro_app) is applied by `pnpm db:pgboss` (apps/worker/src/pgboss-setup.ts), which runs as the same owner role and
-- must be re-run after a pg-boss upgrade. A deployment that sets PGBOSS_SCHEMA to another name gets the same skeleton
-- from that command.
-- igaro_app gets no default privileges on purpose: it receives explicit grants on three tables and one function.
DO $$
DECLARE
  owner_role text := current_user;
BEGIN
  CREATE SCHEMA IF NOT EXISTS "pgboss";
  REVOKE ALL ON SCHEMA "pgboss" FROM PUBLIC;
  GRANT USAGE ON SCHEMA "pgboss" TO "igaro_worker", "igaro_app";
  GRANT CREATE ON SCHEMA "pgboss" TO "igaro_worker";
  EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA "pgboss" GRANT ALL ON TABLES TO "igaro_worker"', owner_role);
  EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA "pgboss" GRANT ALL ON SEQUENCES TO "igaro_worker"', owner_role);
  EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA "pgboss" GRANT EXECUTE ON FUNCTIONS TO "igaro_worker"', owner_role);
END
$$;
