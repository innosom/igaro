-- T-017 (ADR 0009): the Institution Admin rotates and revokes trust in its OWN signing keys.
-- The init migration made institution_keys read-only for tenants. The API is the only component that
-- touches keys, and it takes the institution from the session; RLS below is the second layer.
-- The igaro_app role already holds INSERT and UPDATE("status","retired_at") only: no other column
-- (kid, public_key, encrypted_private_key, institution_id) can ever change.
CREATE POLICY "institution_keys_tenant_insert" ON "institution_keys" FOR INSERT
  WITH CHECK ("institution_id" = app_institution_id() AND "status" = 'ACTIVE');
CREATE POLICY "institution_keys_tenant_update" ON "institution_keys" FOR UPDATE
  USING ("institution_id" = app_institution_id())
  WITH CHECK ("institution_id" = app_institution_id());

-- Key status only moves forward: ACTIVE -> RETIRED | COMPROMISED, RETIRED -> COMPROMISED.
-- COMPROMISED is final and nothing can reactivate a key (applies to every role).
CREATE FUNCTION institution_keys_status_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  -- retired_at is write-once: it records when the key stopped being ACTIVE.
  IF OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at THEN
    RAISE EXCEPTION 'signing key retired_at cannot change' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.status = OLD.status THEN
    RETURN NEW;
  END IF;
  IF OLD.status = 'COMPROMISED' OR NEW.status = 'ACTIVE' OR NEW.retired_at IS NULL THEN
    RAISE EXCEPTION 'illegal signing key status change % -> %', OLD.status, NEW.status
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER institution_keys_status_guard BEFORE UPDATE ON "institution_keys"
  FOR EACH ROW EXECUTE FUNCTION institution_keys_status_guard();
