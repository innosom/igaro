-- T-052 (ADR 0040): fixed-window rate-limit counters shared by every API instance.
-- Not tenant data: there is no institution_id and no RLS policy. Keys are namespaced per limiter family and
-- are hashes (IP, email, token) or institution ids; no raw IP, email or token is ever stored. Least privilege:
-- the API role may read, insert, update and delete counters and nothing else; no other runtime role has access.
CREATE TABLE "rate_limit_counters" (
  "key"      text        NOT NULL,
  "count"    integer     NOT NULL,
  "reset_at" timestamptz NOT NULL,
  CONSTRAINT "rate_limit_counters_pkey" PRIMARY KEY ("key")
);
-- Opportunistic cleanup deletes expired rows in batches.
CREATE INDEX "rate_limit_counters_reset_at_idx" ON "rate_limit_counters" ("reset_at");

REVOKE ALL ON "rate_limit_counters" FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON "rate_limit_counters" TO "igaro_app";
