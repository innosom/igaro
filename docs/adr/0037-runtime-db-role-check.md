# ADR 0037: Runtime database role check at startup

Status: accepted (recommended option taken under the owner's standing permission). Task T-050.

RLS (invariant 5) only holds if the API/worker role is not a superuser, has no BYPASSRLS and does not
own the tenant tables. `packages/db/src/role-check.ts` checks `current_user` at boot (API `server.ts`,
worker `main.ts`). In production a violation aborts startup; in development/test it logs a warning.
Safest option chosen over warn-only: fail closed. Messages name the problem, never a credential.
Ownership and superuser/BYPASSRLS checks include inherited membership (pg_has_role); only the current
schema is inspected. The test assumes the CI DATABASE_URL user is a superuser.
Tests: `packages/db/src/role-check.test.ts` (superuser, BYPASSRLS, owner, production refuse, dev warn).
