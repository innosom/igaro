# ADR 0039: API queue role is enqueue-only and pg-boss objects are owned by the migrator (T-053)

Status: accepted. Every choice below is the recommended option, taken under the owner's standing permission.

## Context
T-051 review: (M1) the API could be pointed at the worker login via `WORKER_DATABASE_URL`, which can read job data, defeating
the enqueue-only grants of ADR 0038. (M2) `pnpm db:pgboss` trusted whatever already existed in the schema; a schema
pre-created by `igaro_app` would let that role grant itself SELECT on job data.

## Decisions
1. The API queue connection is always `APP_DATABASE_URL`. `WORKER_DATABASE_URL` set in the API environment is a ConfigError
   (refuse, rather than silently ignore, so a wrong deployment is noticed). Rejected: allowing it with a role check only.
2. `assertQueueRole` (packages/db) runs at API start when the queue is on: the role must not be or inherit `igaro_worker` and
   must not hold SELECT on `job.data`. Production refuses to start; elsewhere it warns (as ADR 0037).
3. `setupPgbossSchema` fails closed (no ALTER OWNER) if the schema, or any relation in it, is owned by someone other than the
   migrator. Relations owned by the worker role are tolerated: pg-boss creates stats partitions as the worker (ADR 0038 limit b).
   Checked before and after pg-boss installs. Rejected: ALTER OWNER, which would silently legitimise a runtime role's objects.
4. The API warns when `PGBOSS_SCHEMA_MODE=auto` in production. `createQueue` was already gated on auto mode.
5. `pnpm db:pgboss` is part of the release step in docs/deploy/staging.md.

## Limits
A worker-owned relation is trusted; only the API role and unknown owners are refused.
