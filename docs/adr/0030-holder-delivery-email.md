# ADR 0030: holder delivery email, `email.deliver` (T-041)

Status: accepted. Every choice below is the recommended option, taken under the owner's standing permission.

## Context
After issuance the holder gets an email with a private link `/h/{holderToken}` to view and download the card and the signed
credential file. ADR 0002 stores the holder token only as a SHA-256 hash, so a database read cannot rebuild the link. The raw
token exists in one place: the issuance response. The job that sends the mail therefore needs the raw token, and the
holder's address (the worker role has no grant on `credential_holders.email`, and should not get one).

## Decisions
1. **The API puts the raw token in the job, sealed.** After the issuing transaction commits, the API reads the holder's email
   (under RLS plus `institution_id = app_institution_id()`) and queues `email.deliver`. The pg-boss payload is
   `{institutionId, credentialId, sealed}`. `sealed` = `v1.<iv>.<ciphertext>.<tag>` (base64url), AES-256-GCM over
   `{to, holderToken}` with a random 96-bit IV and AAD `igaro.holder-delivery.v1:<institutionId>:<credentialId>`. A copied or
   edited payload (other credential, other tenant, other key, any bit flipped) fails authentication and is dropped. The job
   table and its backups therefore never hold a usable token or address in clear. Rejected: plain token in the job (the account
   mail precedent, but those tokens expire in an hour or three days; a holder token does not expire); a worker grant on the
   email column plus a token stored in clear (breaks ADR 0002); a new holder token minted by the worker (the worker must not
   write credentials, and the 201 response already shows the token the issuing admin sees).
2. **Key.** `DELIVERY_PAYLOAD_KEY`, 32 bytes base64, held by the API and the worker only. It is not `MASTER_KEY` (the worker
   never reads that, ADR 0019); the API refuses a value equal to it. Required in production (API when
   `ACCOUNT_MAIL_QUEUE=pgboss`; worker always). Outside production, unset means the API queues nothing and the worker does not
   register the job (startup warning), so existing setups keep working. Rotation: set the new key on both, after the queue has
   drained (jobs live for minutes; the worker drops a payload it cannot open). No key id is carried in v1; a `v2` format would add one.
3. **Short life, deleted on completion.** Queue options: `deleteAfterSeconds: 60` (completed and failed jobs), `retentionSeconds`
   24 h (a never-started job is dropped), `expireInSeconds: 120`. The worker also calls `deleteJob` right after a successful
   or skipped send, so the sealed blob usually disappears at once; the 60 s setting is the backstop. After the final failed
   retry the job (still sealed) is deleted within 60 s and the failure is logged by id.
4. **Idempotent per credential.** Queue policy `short` and `singletonKey = email.deliver:<credentialId>`: a second enqueue while
   one is queued is a declined no-op, not an error. Retries (5, 30 s, exponential backoff) re-run the same job. Delivery is
   at-least-once: a crash between the SMTP accept and the job completion can send one repeat, which is acceptable for a
   private link. Reissue creates a new credential id and token and queues its own delivery. The old link keeps working until
   the old credential is no longer ACTIVE and shows its status.
5. **Checks before sending.** The worker opens the job (validates ids, address and token shape; CR/LF or a second address are
   refused), then reads the credential inside the job's tenant scope with the existing `igaro_worker` column grants (no new
   migration): status, signed payload (holder name), type name, institution name. A credential that is not ACTIVE completes as
   `skipped_not_active` (no "here is your card" mail for a revoked or suspended credential). A row that is not visible yet
   throws and retries. Cross-tenant ids find nothing.
6. **The mail.** From `SMTP_FROM`, to the holder; plain text and HTML. The link is `WEB_BASE_URL + /h/<token>` (path form, as
   in the white paper; the web page must send `Referrer-Policy: no-referrer` and the API already masks the token in logs,
   ADR 0023). Names are HTML-escaped; control, bidi and zero-width characters are removed from the subject and body text. The mail
   says to keep the link private and to verify only at verify.igaro.app. Mailpit receives it locally (`SMTP_HOST=127.0.0.1`,
   `SMTP_PORT=1025`).
7. **Failure never fails issuance.** `enqueueDeliveryAfterCommit` swallows errors and logs `delivery.enqueue_failed` with ids and
   the error class only; a holder with no email logs `delivery.skipped_no_email` (ids only). The card render enqueue is
   independent. Reissue behaves the same way.
8. **Logging.** Only ids, outcome and counts. The pino redact list gained `sealed` and `holderToken`. SMTP errors become a
   message-free `MailSendError`, because provider errors can echo the recipient. Tests assert that the token, address, link and
   sealed blob are absent from API and worker logs and from stored job output.
9. **Wiring.** `connectProducerQueues({deliveryKey})` creates the `email.deliver` queue and returns `holderDelivery`
   (`PgBossHolderDeliveryQueue`, which seals before sending). `buildApp({holderDelivery})`, with `NoopHolderDeliveryQueue` and
   `MemoryHolderDeliveryQueue` in `notifications.ts`. The worker registers the handler in `startWorker({holderDelivery})` with
   concurrency 1 and reuses the account-mail transport, sender and `WEB_BASE_URL`.
10. **Tests.** Unit: seal/open round trip, wrong key, tampering, moved ids, malformed data, bad recipients, producer payload and
    singleton key, rendering and escaping, handler with fakes, config. Integration (Postgres, real pg-boss, in-process SMTP
    server): mail with link, job removed after sending, no clear token in the queued row, duplicate enqueue creates one job,
    non-ACTIVE skipped, cross-tenant job sends nothing, SMTP failure goes to `retry` with no leak, wrong-key payload dropped,
    logs clean. API: enqueue after issue and reissue, token hash matches the queued token, no email means no job, failed
    issue or foreign holder queues nothing, queue failure does not fail issuance, logs clean, config.

## Not done here
The holder page `/h/:token` and its card and file downloads (T-042), "resend link" (new token, replaces the hash, ADR 0002),
batch delivery for CSV import (T-044 queues through the same path), a bounce or delivery-status record, Resend/SES HTTP drivers
(SMTP only, as for account mail), a key id in the sealed format.
