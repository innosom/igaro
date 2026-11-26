-- T-039 (ADR 0028): the card render job (igaro_worker) must read what a card shows. Column-level SELECT only:
-- no signature, data_hash, holder_token_hash, holder e-mail, key material or any write. The existing
-- tenant RLS policies (app.institution_id) apply to igaro_worker unchanged, so the job reads one tenant at a time.
GRANT SELECT ("id", "institution_id", "holder_id", "type_id", "credential_number", "status", "payload",
              "verification_token", "issued_at", "expires_at")
  ON "credentials" TO "igaro_worker";
GRANT SELECT ("id", "institution_id", "full_name", "external_id", "photo_key", "photo_sha256")
  ON "credential_holders" TO "igaro_worker";
GRANT SELECT ("id", "institution_id", "name", "kind")
  ON "credential_types" TO "igaro_worker";
