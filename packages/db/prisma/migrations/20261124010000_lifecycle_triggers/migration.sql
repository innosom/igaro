-- ===========================================================================
-- T-006: database-level lifecycle and append-only enforcement.
-- Hand-written; builds on 20261124000000_init (does not edit it).
--
-- Error codes: lifecycle/immutability violations raise check_violation (23514); attempts to
-- modify or delete append-only data raise insufficient_privilege (42501), the same code the
-- missing grants produce, so callers see one error for "not allowed".
-- Superusers can still disable triggers; the application role is neither superuser nor owner.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- 1. credential_events.txid: which transaction wrote the event.
--
-- Lifecycle design: "status changes only through credential_events". A credentials.status
-- UPDATE is accepted only if the SAME transaction has already inserted a credential_events row
-- for that credential whose type matches the transition:
--     DRAFT      -> ACTIVE      ISSUED
--     ACTIVE     -> SUSPENDED   SUSPENDED
--     SUSPENDED  -> ACTIVE      REINSTATED
--     ACTIVE     -> REVOKED     REVOKED      (terminal)
--     ACTIVE     -> SUPERSEDED  REISSUED     (terminal; superseded_by is set in the same UPDATE)
-- So the API must: INSERT the event, then UPDATE the status, in one transaction. txid is
-- txid_current() (top-level transaction id, stable across savepoints) and is forced by a trigger,
-- so a client cannot back-date or borrow an event from another transaction.
-- ---------------------------------------------------------------------------
-- seq is insert order only (created_at is identical for events in one transaction); it is
-- overwritten by the stamp trigger and no rule depends on it. It is a BIGSERIAL, so the app role
-- gets USAGE on the sequence.
ALTER TABLE "credential_events" ADD COLUMN "txid" BIGINT NOT NULL DEFAULT txid_current();
ALTER TABLE "credential_events" ADD COLUMN "seq" BIGSERIAL;
GRANT USAGE ON SEQUENCE "credential_events_seq_seq" TO "igaro_app";

-- One event per credential per transaction (see section 2c).
ALTER TABLE "credential_events" ADD CONSTRAINT "credential_events_credential_txid_key"
  UNIQUE ("credential_id", "txid");

-- credentials.status_txid: transaction that last changed status (set on insert and on every
-- status change by the triggers below; the app role has no UPDATE grant on it).
ALTER TABLE "credentials" ADD COLUMN "status_txid" BIGINT NOT NULL DEFAULT txid_current();

-- credentials.created_txid: transaction that inserted the row (used to recognise a DRAFT
-- replacement created in the same transaction as the reissue). Forced on insert.
ALTER TABLE "credentials" ADD COLUMN "created_txid" BIGINT NOT NULL DEFAULT txid_current();

CREATE FUNCTION "igaro_credential_event_stamp"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  NEW."txid" := txid_current();
  NEW."seq" := nextval('credential_events_seq_seq');
  RETURN NEW;
END;
$$;
CREATE TRIGGER "credential_events_stamp_trg"
  BEFORE INSERT ON "credential_events"
  FOR EACH ROW EXECUTE FUNCTION "igaro_credential_event_stamp"();

-- ---------------------------------------------------------------------------
-- 2. credentials: lifecycle, REVOKED is final, signed data immutable, no DELETE.
-- ---------------------------------------------------------------------------
CREATE FUNCTION "igaro_guard_credential_update"() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  needed_event "credential_event_type";
  target_status "credential_status";
  target_txid bigint;
BEGIN
  -- REVOKED is terminal: nothing in the row may change.
  IF OLD."status" = 'REVOKED' THEN
    IF to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
      RAISE EXCEPTION 'credential % is REVOKED and cannot be changed', OLD."id"
        USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;

  -- Identity is immutable in every status.
  IF NEW."id" IS DISTINCT FROM OLD."id"
     OR NEW."institution_id" IS DISTINCT FROM OLD."institution_id"
     OR NEW."credential_number" IS DISTINCT FROM OLD."credential_number"
     OR NEW."verification_token" IS DISTINCT FROM OLD."verification_token"
     OR NEW."created_txid" IS DISTINCT FROM OLD."created_txid"
     OR NEW."created_at" IS DISTINCT FROM OLD."created_at" THEN
    RAISE EXCEPTION 'credential identity columns are immutable'
      USING ERRCODE = 'check_violation';
  END IF;

  -- Signed and issuance columns are writable only while DRAFT (they are fixed at issuance).
  -- Corrections after issuance are reissues (new credential), never edits.
  IF OLD."status" <> 'DRAFT' AND (
       NEW."payload" IS DISTINCT FROM OLD."payload"
    OR NEW."data_hash" IS DISTINCT FROM OLD."data_hash"
    OR NEW."signature" IS DISTINCT FROM OLD."signature"
    OR NEW."issuer_kid" IS DISTINCT FROM OLD."issuer_kid"
    OR NEW."holder_id" IS DISTINCT FROM OLD."holder_id"
    OR NEW."type_id" IS DISTINCT FROM OLD."type_id"
    OR NEW."issued_at" IS DISTINCT FROM OLD."issued_at"
    OR NEW."expires_at" IS DISTINCT FROM OLD."expires_at") THEN
    RAISE EXCEPTION 'signed credential data is immutable once issued (reissue instead)'
      USING ERRCODE = 'check_violation';
  END IF;

  -- status_txid is trigger-owned: it only moves (to this transaction) with a status change below.
  NEW."status_txid" := OLD."status_txid";

  IF NEW."status" IS NOT DISTINCT FROM OLD."status" THEN
    IF NEW."superseded_by" IS DISTINCT FROM OLD."superseded_by" THEN
      RAISE EXCEPTION 'superseded_by can only be set by the transition to SUPERSEDED'
        USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;

  needed_event := CASE
    WHEN OLD."status" = 'DRAFT'     AND NEW."status" = 'ACTIVE'     THEN 'ISSUED'
    WHEN OLD."status" = 'ACTIVE'    AND NEW."status" = 'SUSPENDED'  THEN 'SUSPENDED'
    WHEN OLD."status" = 'SUSPENDED' AND NEW."status" = 'ACTIVE'     THEN 'REINSTATED'
    WHEN OLD."status" = 'ACTIVE'    AND NEW."status" = 'REVOKED'    THEN 'REVOKED'
    WHEN OLD."status" = 'ACTIVE'    AND NEW."status" = 'SUPERSEDED' THEN 'REISSUED'
    ELSE NULL
  END;
  IF needed_event IS NULL THEN
    RAISE EXCEPTION 'credential status transition % -> % is not allowed', OLD."status", NEW."status"
      USING ERRCODE = 'check_violation';
  END IF;

  -- Reissue target: the replacement must be a different credential of the same institution that
  -- is ACTIVE, or a DRAFT created in this transaction. That excludes an already SUPERSEDED,
  -- REVOKED or SUSPENDED target (no chains into dead credentials, no cycles). FOR SHARE stops a
  -- concurrent transaction from changing the target underneath us.
  IF NEW."status" = 'SUPERSEDED' THEN
    SELECT t."status", t."created_txid" INTO target_status, target_txid
      FROM "credentials" t
     WHERE t."id" = NEW."superseded_by" AND t."institution_id" = OLD."institution_id"
       FOR SHARE;
    IF NOT FOUND
       OR NEW."superseded_by" = OLD."id"
       OR NOT (target_status = 'ACTIVE' OR (target_status = 'DRAFT' AND target_txid = txid_current())) THEN
      RAISE EXCEPTION 'superseded_by must reference another ACTIVE credential (or a DRAFT created in this transaction)'
        USING ERRCODE = 'check_violation';
    END IF;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM "credential_events" e
     WHERE e."credential_id" = OLD."id"
       AND e."institution_id" = OLD."institution_id"
       AND e."type" = needed_event
       AND e."txid" = txid_current()
  ) THEN
    RAISE EXCEPTION 'status change % -> % requires a % credential_events row in the same transaction',
      OLD."status", NEW."status", needed_event
      USING ERRCODE = 'check_violation';
  END IF;

  NEW."status_txid" := txid_current();
  RETURN NEW;
END;
$$;
CREATE TRIGGER "credentials_guard_update_trg"
  BEFORE UPDATE ON "credentials"
  FOR EACH ROW EXECUTE FUNCTION "igaro_guard_credential_update"();

-- 2b. INSERT guard. A credential is created DRAFT, or ACTIVE together with its ISSUED event.
-- Any other status on insert (SUSPENDED, REVOKED, SUPERSEDED) is refused. For ACTIVE the
-- DEFERRABLE INITIALLY DEFERRED constraint trigger below requires, at COMMIT, an ISSUED event for
-- the credential written by the same transaction (so event and credential may be inserted in
-- either order). Tests can force the check early with SET CONSTRAINTS ... IMMEDIATE.
CREATE FUNCTION "igaro_guard_credential_insert"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW."status" NOT IN ('DRAFT', 'ACTIVE') THEN
    RAISE EXCEPTION 'a credential must be inserted as DRAFT or ACTIVE, not %', NEW."status"
      USING ERRCODE = 'check_violation';
  END IF;
  NEW."created_txid" := txid_current();
  NEW."status_txid" := txid_current();
  RETURN NEW;
END;
$$;
CREATE TRIGGER "credentials_guard_insert_trg"
  BEFORE INSERT ON "credentials"
  FOR EACH ROW EXECUTE FUNCTION "igaro_guard_credential_insert"();

CREATE FUNCTION "igaro_check_credential_issued"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW."status" = 'ACTIVE' AND NOT EXISTS (
    SELECT 1 FROM "credential_events" e
     WHERE e."credential_id" = NEW."id"
       AND e."institution_id" = NEW."institution_id"
       AND e."type" = 'ISSUED'
       AND e."txid" = txid_current()
  ) THEN
    RAISE EXCEPTION 'credential % inserted ACTIVE without an ISSUED event in the same transaction', NEW."id"
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER "credentials_issued_event_ctrg"
  AFTER INSERT ON "credentials"
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION "igaro_check_credential_issued"();

-- 2c. Event/status consistency, checked at COMMIT for EVERY inserted event (no "latest event"
-- shortcut, so nothing can be hidden behind a later event). The credential must be in the status
-- that the event type implies AND that status must have been set by this very transaction
-- (credentials.status_txid = event txid):
--     ISSUED -> ACTIVE, SUSPENDED -> SUSPENDED, REINSTATED -> ACTIVE, REVOKED -> REVOKED,
--     REISSUED -> SUPERSEDED.
-- Together with UNIQUE (credential_id, txid) on credential_events (one event per credential per
-- transaction) this means: every event is backed by exactly one status change in the same
-- transaction, and a status change cannot happen without its event (guard trigger above).
-- A credential therefore changes status at most once per transaction.
-- seq is insert order only (diagnostics); no rule depends on it.
CREATE FUNCTION "igaro_check_event_status"() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  expected "credential_status";
  actual "credential_status";
  changed_in bigint;
BEGIN
  expected := CASE NEW."type"
    WHEN 'ISSUED' THEN 'ACTIVE'
    WHEN 'SUSPENDED' THEN 'SUSPENDED'
    WHEN 'REINSTATED' THEN 'ACTIVE'
    WHEN 'REVOKED' THEN 'REVOKED'
    WHEN 'REISSUED' THEN 'SUPERSEDED'
  END;
  SELECT c."status", c."status_txid" INTO actual, changed_in FROM "credentials" c
   WHERE c."id" = NEW."credential_id" AND c."institution_id" = NEW."institution_id";
  IF actual IS DISTINCT FROM expected OR changed_in IS DISTINCT FROM NEW."txid" THEN
    RAISE EXCEPTION 'credential % event % is not backed by a matching status change in the same transaction (status %)',
      NEW."credential_id", NEW."type", actual
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END;
$$;

-- M-A: a reissue target must still be ACTIVE at COMMIT (a DRAFT replacement must have been
-- issued by then; a target revoked/suspended later in the same transaction is refused).
CREATE FUNCTION "igaro_check_supersede_target"() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  target_status "credential_status";
BEGIN
  IF NEW."status" = 'SUPERSEDED' THEN
    SELECT t."status" INTO target_status FROM "credentials" t
     WHERE t."id" = NEW."superseded_by" AND t."institution_id" = NEW."institution_id";
    IF target_status IS DISTINCT FROM 'ACTIVE' THEN
      RAISE EXCEPTION 'credential % superseded by % which is not ACTIVE at commit', NEW."id", NEW."superseded_by"
        USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER "credentials_supersede_target_ctrg"
  AFTER UPDATE OF "status" ON "credentials"
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION "igaro_check_supersede_target"();
CREATE CONSTRAINT TRIGGER "credential_events_status_ctrg"
  AFTER INSERT ON "credential_events"
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION "igaro_check_event_status"();

-- Generic refusal used for DELETE, TRUNCATE and (where applicable) UPDATE on append-only tables.
CREATE FUNCTION "igaro_forbid_modification"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% on % is not allowed (append-only / never deleted)', TG_OP, TG_TABLE_NAME
    USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER "credentials_no_delete_trg"
  BEFORE DELETE ON "credentials"
  FOR EACH ROW EXECUTE FUNCTION "igaro_forbid_modification"();
CREATE TRIGGER "credentials_no_truncate_trg"
  BEFORE TRUNCATE ON "credentials"
  FOR EACH STATEMENT EXECUTE FUNCTION "igaro_forbid_modification"();

-- ---------------------------------------------------------------------------
-- 3. Append-only tables.
--    audit_logs, audit_head_hashes, verification_logs: no UPDATE, DELETE or TRUNCATE.
--    credential_events: no DELETE/TRUNCATE; UPDATE only to set anchored_at once (outbox).
--    (The app role has no UPDATE/DELETE/TRUNCATE grants on any of them either.)
-- ---------------------------------------------------------------------------
CREATE TRIGGER "audit_logs_no_update_trg"
  BEFORE UPDATE OR DELETE ON "audit_logs"
  FOR EACH ROW EXECUTE FUNCTION "igaro_forbid_modification"();
CREATE TRIGGER "audit_logs_no_truncate_trg"
  BEFORE TRUNCATE ON "audit_logs"
  FOR EACH STATEMENT EXECUTE FUNCTION "igaro_forbid_modification"();

CREATE TRIGGER "audit_head_hashes_no_update_trg"
  BEFORE UPDATE OR DELETE ON "audit_head_hashes"
  FOR EACH ROW EXECUTE FUNCTION "igaro_forbid_modification"();
CREATE TRIGGER "audit_head_hashes_no_truncate_trg"
  BEFORE TRUNCATE ON "audit_head_hashes"
  FOR EACH STATEMENT EXECUTE FUNCTION "igaro_forbid_modification"();

CREATE TRIGGER "verification_logs_no_update_trg"
  BEFORE UPDATE OR DELETE ON "verification_logs"
  FOR EACH ROW EXECUTE FUNCTION "igaro_forbid_modification"();
CREATE TRIGGER "verification_logs_no_truncate_trg"
  BEFORE TRUNCATE ON "verification_logs"
  FOR EACH STATEMENT EXECUTE FUNCTION "igaro_forbid_modification"();

CREATE FUNCTION "igaro_guard_credential_event_update"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF to_jsonb(NEW) - 'anchored_at' IS DISTINCT FROM to_jsonb(OLD) - 'anchored_at' THEN
    RAISE EXCEPTION 'credential_events are append-only; only anchored_at may be set'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD."anchored_at" IS NOT NULL AND NEW."anchored_at" IS DISTINCT FROM OLD."anchored_at" THEN
    RAISE EXCEPTION 'credential_events.anchored_at is already set'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER "credential_events_guard_update_trg"
  BEFORE UPDATE ON "credential_events"
  FOR EACH ROW EXECUTE FUNCTION "igaro_guard_credential_event_update"();
CREATE TRIGGER "credential_events_no_delete_trg"
  BEFORE DELETE ON "credential_events"
  FOR EACH ROW EXECUTE FUNCTION "igaro_forbid_modification"();
CREATE TRIGGER "credential_events_no_truncate_trg"
  BEFORE TRUNCATE ON "credential_events"
  FOR EACH STATEMENT EXECUTE FUNCTION "igaro_forbid_modification"();

-- Belt and braces: make sure the app role holds none of these privileges.
REVOKE UPDATE, DELETE, TRUNCATE ON "audit_logs", "audit_head_hashes", "verification_logs",
  "credential_events" FROM "igaro_app";
REVOKE DELETE, TRUNCATE ON "credentials" FROM "igaro_app";

-- The one column the app may update on credential_events: the Phase 1 anchoring outbox marker.
-- The guard trigger limits it to a single NULL -> value change.
GRANT UPDATE ("anchored_at") ON "credential_events" TO "igaro_app";

-- ---------------------------------------------------------------------------
-- 4. verification_logs: a log row naming a credential must name its institution.
-- ---------------------------------------------------------------------------
ALTER TABLE "verification_logs" ADD CONSTRAINT "verification_logs_credential_institution_chk"
  CHECK ("credential_id" IS NULL OR "institution_id" IS NOT NULL);

-- ---------------------------------------------------------------------------
-- 5. Fixed search_path on every trigger function (init + this migration), so a role that can
--    create objects in another schema or pg_temp cannot shadow tables/functions. The current
--    schema is substituted at migration time (public in production).
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  fn text;
BEGIN
  FOREACH fn IN ARRAY ARRAY[
    'igaro_enforce_user_institution',
    'igaro_guard_institution_status',
    'igaro_guard_institution_key',
    'igaro_credential_event_stamp',
    'igaro_guard_credential_update',
    'igaro_forbid_modification',
    'igaro_guard_credential_event_update',
    'igaro_guard_credential_insert',
    'igaro_check_credential_issued',
    'igaro_check_event_status',
    'igaro_check_supersede_target'
  ] LOOP
    EXECUTE format(
      'ALTER FUNCTION %I.%I() SET search_path = pg_catalog, %I, pg_temp',
      current_schema(), fn, current_schema()
    );
  END LOOP;
END
$$;
