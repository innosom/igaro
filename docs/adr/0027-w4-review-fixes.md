# ADR 0027 — W4 review fixes (recommended option taken under the owner's standing permission)

- Photo shown on /v/:token is addressed by the signed `photoSha256` (object key rebuilt from it; only png/jpg extension read from the column) and the web photo route re-hashes the bytes, failing closed (404) on mismatch.
- In production the API refuses to start unless `TRUST_PROXY` is explicitly set to a hop count or CIDRs (not `false`), so rate-limit buckets are per client. Amends ADR 0003's default for production only.
- Open Lows: holder view reads unsigned columns (L1); keys.json lacks institutionId for the CLI (L2); double verification per page with photo (L3); no web header tests (L4, QA in T-048); SUPERSEDED exposes the new token (L5, matches ADR 0022).
