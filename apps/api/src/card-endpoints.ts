// Card rendering hooks and card downloads (T-040, ADR 0029).
//
// Enqueue: after the issuing transaction commits, one card.render job (ids only) is queued. A queue failure is logged
// (ids and error class only) and never fails issuance: the card is regenerable.
//
// Serve: GET /credentials/:id/card.{png,pdf}. The tenant comes from the session; unknown, foreign and malformed ids are
// the same 404. Before redirecting to a short-lived signed URL the stored credential is re-checked with @igaro/core
// (SHA-256(JCS(payload)) == data_hash and the signature verifies under the issuer's public key), so a tampered row is
// never presented as a valid card. Failure is an ops alert (ids only) and a uniform 404.
import type { FastifyBaseLogger, FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { verifyCredentialIntegrity } from '@igaro/core';
import { cardStorageKeys } from '@igaro/worker/producer';
import type { AuthSession } from './auth.js';
import { isUuid, type Db, type TenantSession } from './db.js';
import { AppError, NotFoundError } from './errors.js';
import type { CardRenderQueue } from './notifications.js';
import type { ObjectStorage } from './storage.js';

/** Lifetime of the redirect target. Short on purpose; the redirect itself is never cached. */
export const CARD_URL_SECONDS = 60;
/** Suggested wait when the card has not been rendered yet. */
export const CARD_RETRY_AFTER_SECONDS = 15;

/** Queue a render after commit. Never throws; logs ids and the error class only. */
export async function enqueueCardAfterCommit(
  queue: CardRenderQueue | undefined,
  log: FastifyBaseLogger,
  job: { institutionId: string; credentialId: string },
): Promise<void> {
  if (!queue) return;
  try {
    await queue.enqueue({ institutionId: job.institutionId, credentialId: job.credentialId });
  } catch (err) {
    log.error(
      {
        event: 'card.enqueue_failed',
        institutionId: job.institutionId,
        credentialId: job.credentialId,
        errorClass: err instanceof Error ? err.name : 'UnknownError',
      },
      'card render job could not be queued',
    );
  }
}

interface CardRow {
  id: string;
  status: string;
  payload: unknown;
  data_hash: string;
  signature: string;
  key_public: string | null;
  key_status: string | null;
}

const tenantScope = (req: FastifyRequest): TenantSession => {
  const s: AuthSession | null = req.session;
  if (!s || s.kind !== 'tenant') throw new AppError(403, 'FORBIDDEN', 'Insufficient role');
  return { kind: 'tenant', userId: s.userId, institutionId: s.institutionId };
};

export interface CardEndpointContext {
  db: Db;
  storage?: ObjectStorage | undefined;
  log: FastifyBaseLogger;
}

export function registerCardEndpoints(app: FastifyInstance, ctx: CardEndpointContext): void {
  const ia = { preHandler: app.requireRole('INSTITUTION_ADMIN') };

  const serve = async (req: FastifyRequest<{ Params: { id: string } }>, reply: FastifyReply, ext: 'png' | 'pdf') => {
    void reply.header('Cache-Control', 'no-store');
    const scope = tenantScope(req);
    const id = req.params.id;
    if (!isUuid(id)) throw new NotFoundError();

    const row = await ctx.db.withTenant(scope, async (c) => {
      const r = await c.query<CardRow>(
        `SELECT c.id, c.status::text AS status,
                c.payload, c.data_hash, c.signature, k.public_key AS key_public, k.status::text AS key_status
           FROM credentials c
           LEFT JOIN institution_keys k ON k.institution_id = c.institution_id AND k.kid = c.issuer_kid
          WHERE c.id = $1 AND c.institution_id = app_institution_id()`,
        [id],
      );
      return r.rows[0];
    });
    if (!row) throw new NotFoundError();
    const payload = row.payload as { credentialId?: unknown; institutionId?: unknown; expiresAt?: unknown } | null;
    const ok =
      row.key_public !== null &&
      row.key_status !== 'COMPROMISED' &&
      payload?.credentialId === row.id &&
      payload?.institutionId === scope.institutionId &&
      verifyCredentialIntegrity(row.payload, row.data_hash, row.signature, row.key_public) === 'OK';
    if (!ok) {
      ctx.log.error(
        { event: 'card.integrity_failure', institutionId: scope.institutionId, credentialId: row.id },
        'stored credential failed integrity check; card not served',
      );
      throw new NotFoundError();
    }
    // Integrity first (invariant 7), then state. Only a live credential has a card; every other state is the same 404.
    // Expiry comes from the signed payload, never the unsigned column.
    const exp = payload?.expiresAt;
    const expired = typeof exp === 'string' && Date.parse(exp) <= Date.now();
    if (row.status !== 'ACTIVE' || expired) throw new NotFoundError();

    if (!ctx.storage) throw new AppError(503, 'STORAGE_UNAVAILABLE', 'Cards are not available right now');
    const key = cardStorageKeys(scope.institutionId, row.id)[ext];
    let url: string;
    try {
      if (!(await ctx.storage.exists(key))) {
        void reply.header('Retry-After', String(CARD_RETRY_AFTER_SECONDS));
        return reply.status(404).send({ error: { code: 'CARD_NOT_READY', message: 'The card is not ready yet' } });
      }
      url = await ctx.storage.signedGetUrl(key, CARD_URL_SECONDS);
    } catch {
      ctx.log.error(
        { event: 'card.storage_failed', institutionId: scope.institutionId, credentialId: row.id },
        'card storage lookup failed',
      );
      throw new AppError(503, 'STORAGE_UNAVAILABLE', 'Cards are not available right now');
    }
    // The URL is a bearer credential: it is only placed in the Location header, never logged.
    ctx.log.info({ event: 'card.served', actorId: scope.userId, institutionId: scope.institutionId, credentialId: row.id, format: ext }, 'card redirect issued');
    void reply.header('Referrer-Policy', 'no-referrer');
    return reply.redirect(url, 302);
  };

  app.get<{ Params: { id: string } }>('/credentials/:id/card.png', ia, (req, reply) => serve(req, reply, 'png'));
  app.get<{ Params: { id: string } }>('/credentials/:id/card.pdf', ia, (req, reply) => serve(req, reply, 'pdf'));
}
