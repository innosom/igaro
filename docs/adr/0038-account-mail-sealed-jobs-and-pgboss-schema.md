# ADR 0038: sealed account-mail jobs and a pre-created pg-boss schema with enqueue-only grants (T-051)

Status: accepted. Every choice below is the recommended option, taken under the owner's standing permission.

## Context
Review finding M2 (threat-model row 16): invite and password-reset jobs carried the RAW one-time token and the recipient in
the pg-boss job row. The pg-boss schema sits outside RLS and was created at runtime by whatever role first connected, so the API
role (the one a SQL injection would own) could read pending jobs, and the job table and its backups held usable tokens
(ADR 0002 says tokens are stored only as hashes). ADR 0030 already solved the same problem for the holder link by sealing.

## Decisions
1. **Seal, do not carry ids.** The mail must contain the raw token, which exists in one place only: the API request that created
   it (the invite or reset row keeps a hash). The worker therefore cannot rebuild it from ids, and it has no grant on the
   invite/reset tables and should not get one. Same as ADR 0030, the job is
   `{kind, ref, expiresAt, [institutionId], sealed}`; `sealed = v1.<iv>.<ciphertext>.<tag>` (base64url), AES-256-GCM over
   `{to, token}`, random 96-bit IV, AAD `igaro.account-mail.v1:<kind>:<institutionId|->:<expiresAt>:<ref>`. `ref` is a random
   UUID per job. Moving a sealed blob to another kind, tenant, expiry or job, or flipping any bit, fails authentication and the
   job is dropped. Rejected: a worker grant on `invites` and `password_resets` (impossible anyway, only hashes are stored);
   a worker-minted token (the worker must not write account tables and the token would then be unknown to the API); keeping the
   clear token with a shorter life (still readable by the API role while pending).
2. **Key.** Reuse `DELIVERY_PAYLOAD_KEY` (ADR 0030): one key for everything the API hands the worker. The AAD prefix separates
   the two uses, so a holder-delivery blob cannot be opened as account mail or the reverse. Not `MASTER_KEY`. The API already
   requires it in production when `ACCOUNT_MAIL_QUEUE=pgboss`, and so does the worker. Outside production, without the key the
   API queues no invite or reset mail (a warning at start) and the worker does not register `account.mail`: fail closed, never a
   clear token in the table. Existing dev setups that used `ACCOUNT_MAIL_QUEUE=pgboss` must now set the key (documented in
   `.env.example`). Rotation as in ADR 0030: change both after the queue drained (jobs live minutes).
3. **Old jobs.** The worker accepts only the sealed form. A clear-text job queued by an older API before the deploy is dropped
   (logged by id only), not mailed. Tokens live one hour (reset) to three days (invite) and queued jobs minutes, so deploy API
   and worker together; a dropped invite is re-issued from the dashboard, a reset is requested again.
4. **Short life is kept.** `deleteAfterSeconds: 60`, retention bounded by the token expiry, retries as before. Now a stale row
   holds only a sealed blob.
5. **The pg-boss schema is created by the owner.** `PGBOSS_SCHEMA_MODE=auto|external`. `external` (the default when
   `NODE_ENV=production`): the API producer and the worker start pg-boss with `migrate: false, createSchema: false`, the producer
   also with `registerInstance: false`, and create no queue. They fail at start if the schema is missing, instead of creating it.
   `auto` (default elsewhere): the previous behaviour, so local dev and the existing integration tests need no extra step.
6. **Two parts, because pg-boss's DDL is version-specific.** Embedding pg-boss 12's generated DDL (partitioned tables, plpgsql
   functions, clock) in a Prisma migration would pin it to one version and make pg-boss's own upgrades fail on objects the
   worker role does not own. So:
   - **Migration `20261128000000_pgboss_schema_skeleton` (packages/db)**: `CREATE SCHEMA pgboss`, closed to PUBLIC; USAGE for
     `igaro_app` and `igaro_worker`; CREATE for `igaro_worker` (pg-boss creates daily stats partitions); default privileges so
     everything the owner creates there later is granted to `igaro_worker` (ALL on tables and sequences, EXECUTE on functions).
     `igaro_app` gets no default privilege.
   - **`pnpm db:pgboss` (apps/worker, `setupPgbossSchema`)**, run by the owner (`DATABASE_URL`) after `db:migrate` and after each
     pg-boss upgrade, idempotent: applies the same skeleton to any `PGBOSS_SCHEMA` name, installs or migrates pg-boss, creates all
     four queues with the shared options (the API role never creates a queue), then applies the grants. It prints no URL.
7. **Enqueue-only grants for `igaro_app`**, found by trying them against pg-boss 12.39: SELECT on `version` and `queue`
   (config, no job content); INSERT on `job` and on each of its partitions (today `job_common`); SELECT on the columns `id` and
   `start_after` only (`INSERT ... RETURNING` needs SELECT on what it returns); EXECUTE on `job_now()`. EXECUTE on every other
   function in the schema is revoked from PUBLIC (so `create_queue` and `delete_queue` are not callable). There is no SELECT
   of `data`, `output`, `singleton_key` or any other column, and no UPDATE, DELETE or TRUNCATE. `igaro_worker` gets ALL in the
   schema. Accepted leak: `id` is readable, so a row count is, and the ids are random UUIDs.
8. **Limits.** (a) A queue created with `partition: true` makes a table owned by its creator; re-run `pnpm db:pgboss` so the API
   role gets INSERT on it (none of our queues partition). (b) Partitions the worker creates itself (stats) are owned by the
   worker, so a later owner-run pg-boss migration may need `REASSIGN OWNED` or the schema dropped in dev; production should upgrade
   pg-boss only through `pnpm db:pgboss` with the worker stopped. (c) The migration closes an existing `pgboss` schema to PUBLIC;
   a deployment whose runtime roles were not `igaro_app` or `igaro_worker` must grant its own role USAGE. (d) Someone holding the
   key and read access to the queue (the worker host, `igaro_worker`) can open pending jobs; the database alone cannot.
   (e) The enqueue-only role also covers the API's card render, import and holder-delivery jobs.
9. **Logging.** Unchanged: job id and outcome only; never data, token, link, recipient or sealed blob. The producer's
   `connect*` functions log only an error class.
10. **Tests.**
    - Unit (`account-mail.test.ts`): seal/open round trip, the stored form contains neither token nor address, wrong key, every
      moved or edited routing field, the old clear-text form, malformed data, bad recipients/tokens/keys, error text, producer
      payload, config (`PGBOSS_SCHEMA_MODE`).
    - Integration, real pg-boss on `$DATABASE_URL` (`account-mail.integration.test.ts`): mail with the link; a queued job row
      (whole row as text) has no token and no address; an old clear-text job is dropped; logs clean.
    - Integration (`pgboss-setup.integration.test.ts`): `setupPgbossSchema` into a scratch schema; the API connects as a login
      role that is a member of `igaro_app`, the worker as a member of `igaro_worker`, both in `external` mode. The API enqueues
      invite and reset jobs; the raw rows hold no token or address; the API role is refused (42501) SELECT of `data`, `output`,
      `singleton_key`, `*`, UPDATE, DELETE, TRUNCATE, writes to `queue`, `create_queue`, `delete_queue` and CREATE TABLE; the
      worker, with only `igaro_worker` rights, delivers both mails from the sealed jobs; an external-mode producer on a missing
      schema fails without creating it; setup is idempotent; logs clean.
    - db (`pgboss-skeleton.test.ts`): schema closed to PUBLIC, privileges of both roles, default privileges.
    - API: config tests for `PGBOSS_SCHEMA_MODE`.

## Not done here
Pre-creating a queue-per-tenant partition scheme; a key id in the sealed format (v2); a Postgres role used only for enqueue
(the API still uses `igaro_app`; a dedicated `igaro_queue` role would be a further step); an automated pg-boss upgrade runbook
beyond "run `pnpm db:pgboss` with the worker stopped".
