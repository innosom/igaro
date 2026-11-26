// email.deliver enqueue after issuance (T-041, ADR 0030). Runs after the issuing transaction has committed.
// The holder token exists in clear only in the 201 response and here; the queue implementation seals it. Failure is
// logged (ids and error class only) and never fails issuance: an admin can reissue, and a resend-link action can follow.
import type { FastifyBaseLogger } from 'fastify';
import type { Db, TenantSession } from './db.js';
import type { HolderDeliveryQueue } from './notifications.js';

export interface HolderDeliveryHook {
  queue: HolderDeliveryQueue;
  db: Db;
}

const EMAIL = /^[^\s@<>,;"]+@[^\s@<>,;"]+$/;

/** The holder's email, read under RLS plus an explicit tenant filter. Null when the holder has none. */
async function holderEmail(db: Db, scope: TenantSession, holderId: string): Promise<string | null> {
  return db.withTenant(scope, async (c) => {
    const r = await c.query<{ email: string | null }>(
      `SELECT email FROM credential_holders WHERE id = $1 AND institution_id = app_institution_id()`,
      [holderId],
    );
    return r.rows[0]?.email ?? null;
  });
}

/** Queue the holder email for a freshly issued credential. Never throws; never logs the token or the address. */
export async function enqueueDeliveryAfterCommit(
  hook: HolderDeliveryHook | undefined,
  log: FastifyBaseLogger,
  scope: TenantSession,
  issued: { id: string; holderId: string; holderToken: string },
): Promise<void> {
  if (!hook) return;
  try {
    const to = await holderEmail(hook.db, scope, issued.holderId);
    if (!to || !EMAIL.test(to)) {
      log.info(
        { event: 'delivery.skipped_no_email', institutionId: scope.institutionId, credentialId: issued.id },
        'holder has no usable email; no delivery queued',
      );
      return;
    }
    await hook.queue.enqueue({
      institutionId: scope.institutionId,
      credentialId: issued.id,
      to,
      holderToken: issued.holderToken,
    });
  } catch (err) {
    log.error(
      {
        event: 'delivery.enqueue_failed',
        institutionId: scope.institutionId,
        credentialId: issued.id,
        errorClass: err instanceof Error ? err.name : 'UnknownError',
      },
      'holder delivery job could not be queued',
    );
  }
}
