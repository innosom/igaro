-- T-028 (ADR 0019): daily signed audit heads written by the worker only, OpenTimestamps proofs in an
-- append-only side table (audit_head_hashes itself refuses UPDATE, so a proof that arrives later
-- cannot be written into its row).

-- 1. A dedicated worker role. NOLOGIN here; grant LOGIN out of band, like igaro_app:
--      ALTER ROLE igaro_worker WITH LOGIN PASSWORD '<secret from your secret store>';
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'igaro_worker') THEN
    CREATE ROLE "igaro_worker" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END
$$;

DO $$
BEGIN
  EXECUTE format('GRANT USAGE ON SCHEMA %I TO "igaro_worker"', current_schema());
END
$$;

-- 2. Side table for timestamp proofs. One PENDING row (calendar receipt) and at most one COMPLETE row
--    (upgraded, Bitcoin-attested proof) per head. Never updated or deleted.
CREATE TABLE "audit_head_timestamps" (
    "id" UUID NOT NULL,
    "head_id" UUID NOT NULL,
    "institution_id" UUID,
    "state" TEXT NOT NULL,
    "ots_proof" BYTEA NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "audit_head_timestamps_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "audit_head_timestamps_state_chk" CHECK ("state" IN ('PENDING', 'COMPLETE')),
    CONSTRAINT "audit_head_timestamps_head_state_key" UNIQUE ("head_id", "state"),
    CONSTRAINT "audit_head_timestamps_head_id_fkey" FOREIGN KEY ("head_id")
      REFERENCES "audit_head_hashes"("id") ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT "audit_head_timestamps_institution_id_fkey" FOREIGN KEY ("institution_id")
      REFERENCES "institutions"("id") ON DELETE RESTRICT ON UPDATE RESTRICT
);
CREATE INDEX "audit_head_timestamps_institution_id_idx" ON "audit_head_timestamps"("institution_id");

CREATE TRIGGER "audit_head_timestamps_no_update_trg"
  BEFORE UPDATE OR DELETE ON "audit_head_timestamps"
  FOR EACH ROW EXECUTE FUNCTION "igaro_forbid_modification"();
CREATE TRIGGER "audit_head_timestamps_no_truncate_trg"
  BEFORE TRUNCATE ON "audit_head_timestamps"
  FOR EACH STATEMENT EXECUTE FUNCTION "igaro_forbid_modification"();

-- The timestamp row must belong to the same chain as its head.
CREATE FUNCTION "igaro_enforce_timestamp_chain"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM "audit_head_hashes" h
    WHERE h."id" = NEW."head_id" AND h."institution_id" IS NOT DISTINCT FROM NEW."institution_id"
  ) THEN
    RAISE EXCEPTION 'audit_head_timestamps.institution_id must equal the head''s institution_id'
      USING ERRCODE = 'foreign_key_violation';
  END IF;
  RETURN NEW;
END;
$$;
-- Fixed search_path, like every other igaro_* function (migration 20261124010000, part 5).
DO $$
BEGIN
  EXECUTE format(
    'ALTER FUNCTION %I.%I() SET search_path = pg_catalog, %I, pg_temp',
    current_schema(), 'igaro_enforce_timestamp_chain', current_schema()
  );
END
$$;
CREATE TRIGGER "audit_head_timestamps_chain_trg"
  BEFORE INSERT ON "audit_head_timestamps"
  FOR EACH ROW EXECUTE FUNCTION "igaro_enforce_timestamp_chain"();

ALTER TABLE "audit_head_timestamps" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "audit_head_timestamps" FORCE ROW LEVEL SECURITY;

CREATE POLICY "audit_head_timestamps_select" ON "audit_head_timestamps" FOR SELECT
  USING ("institution_id" = app_institution_id() OR app_is_platform_admin());

-- 3. Writes to the head tables belong to the worker role only. igaro_app (API) can still read them.
REVOKE INSERT ON "audit_head_hashes" FROM "igaro_app";
DROP POLICY "audit_head_hashes_insert" ON "audit_head_hashes";
-- The worker writes one chain at a time, scoped to it; the NULL platform chain needs platform scope.
CREATE POLICY "audit_head_hashes_insert" ON "audit_head_hashes" FOR INSERT TO "igaro_worker"
  WITH CHECK (
    ("institution_id" IS NOT NULL AND "institution_id" = app_institution_id())
    OR ("institution_id" IS NULL AND app_is_platform_admin())
  );
CREATE POLICY "audit_head_timestamps_insert" ON "audit_head_timestamps" FOR INSERT TO "igaro_worker"
  WITH CHECK (
    ("institution_id" IS NOT NULL AND "institution_id" = app_institution_id())
    OR ("institution_id" IS NULL AND app_is_platform_admin())
  );

GRANT SELECT ON "audit_head_timestamps" TO "igaro_app";
GRANT SELECT ON "institutions", "audit_logs" TO "igaro_worker";
GRANT SELECT, INSERT ON "audit_head_hashes" TO "igaro_worker";
GRANT SELECT, INSERT ON "audit_head_timestamps" TO "igaro_worker";
-- No other table, no UPDATE, no DELETE, no key material (institution_keys is not readable by the worker).
