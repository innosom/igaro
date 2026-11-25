-- T-009: idle timeout for sessions.
-- sessions.expires_at is the sliding IDLE deadline; the API extends it on use (throttled) and
-- separately enforces an absolute lifetime from created_at. The init migration granted no UPDATE
-- on sessions, so grant exactly this one column. token_hash, user_id and institution_id stay
-- immutable for the app role.
GRANT UPDATE ("expires_at") ON "sessions" TO "igaro_app";
