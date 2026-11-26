// Credential lifecycle (T-026, ADR 0017): suspend, reinstate, revoke, reissue.
// Rules come from @igaro/core (planTransition); the DB triggers are the backstop. A status change is only ever
// made by inserting the credential_events row and then updating credentials.status in the SAME transaction.
// The institution comes from the session only; another tenant's credential id is a 404. Every change appends its
// audit entry in the same transaction, with the reason (revoke/suspend/reissue) in the audit metadata.
import { randomUUID } from 'node:crypto';
import type { FastifyBaseLogger, FastifyInstance } from 'fastify';
import type { PoolClient } from 'pg';
import { LifecycleError, planTransition, type CredentialStatus, type LifecycleAction } from '@igaro/core';
import { appendAudit } from './audit.js';
import { enqueueCardAfterCommit } from './card-endpoints.js';
import type { CardRenderQueue } from './notifications.js';
import type { AuthSession } from './auth.js';
import {
  BAD_TEXT_RE,
  badRequest,
  isIsoSeconds,
  issueInTransaction,
  type IssuedCredential,
  type IssueInput,
} from './credentials.js';
import { isUuid, type Db, type TenantSession } from './db.js';
import { AppError, NotFoundError } from './errors.js';

const MAX_REASON = 500;
const MAX_ATTR_KEYS = 30;

export interface LifecycleBody {
  reason?: string;
}
export interface ReissueBody extends LifecycleBody {
  reason: string;
  attributes?: Record<string, unknown>;
  expiresAt?: string | null;
}

function objectBody(body: unknown, known: string[]): Record<string, unknown> {
  if (body === undefined || body === null) return {};
  if (typeof body !== 'object' || Array.isArray(body)) throw badRequest('BAD_REQUEST', 'Invalid request');
  const b = body as Record<string, unknown>;
  if (Object.keys(b).some((k) => !known.includes(k))) throw badRequest('UNKNOWN_PROPERTY', 'Unknown property');
  return b;
}

/** Reason: 1-500 characters after trim, NFC, no control or formatting characters. Never echoed in errors. */
export function parseReason(v: unknown, required: boolean): string | undefined {
  if (v === undefined || v === null) {
    if (required) throw badRequest('REASON_REQUIRED', 'A reason is required');
    return undefined;
  }
  if (typeof v !== 'string') throw badRequest('INVALID_REASON', 'reason must be text');
  const t = v.normalize('NFC').trim();
  if (t === '') {
    if (required) throw badRequest('REASON_REQUIRED', 'A reason is required');
    return undefined;
  }
  if (t.length > MAX_REASON || BAD_TEXT_RE.test(t)) {
    throw badRequest('INVALID_REASON', `reason must be 1-${MAX_REASON} characters without control or formatting characters`);
  }
  return t;
}

export function parseLifecycleBody(body: unknown, reasonRequired: boolean): LifecycleBody {
  const b = objectBody(body, ['reason']);
  const reason = parseReason(b.reason, reasonRequired);
  return reason === undefined ? {} : { reason };
}

export function parseReissueBody(body: unknown): ReissueBody {
  const b = objectBody(body, ['reason', 'attributes', 'expiresAt']);
  const out: ReissueBody = { reason: parseReason(b.reason, true) as string };
  if (b.attributes !== undefined) {
    const a = b.attributes;
    if (!a || typeof a !== 'object' || Array.isArray(a)) throw badRequest('INVALID_ATTRIBUTES', 'attributes must be an object');
    if (Object.keys(a).length > MAX_ATTR_KEYS) throw badRequest('INVALID_ATTRIBUTES', 'Too many attributes');
    out.attributes = a as Record<string, unknown>;
  }
  if ('expiresAt' in b) {
    if (b.expiresAt !== null && !isIsoSeconds(b.expiresAt)) {
      throw badRequest('INVALID_EXPIRES_AT', 'expiresAt must be null or a UTC timestamp like 2027-01-31T00:00:00Z');
    }
    out.expiresAt = b.expiresAt as string | null;
  }
  return out;
}

export interface LifecycleResult {
  id: string;
  credentialNumber: string;
  status: CredentialStatus;
  previousStatus: CredentialStatus;
}
export interface ReissueResult {
  /** The newly issued credential, same shape as POST /credentials (the holder token is returned here once). */
  credential: IssuedCredential;
  /** The replaced credential: SUPERSEDED when it was ACTIVE, still REVOKED when reissuing after a revocation. */
  previous: { id: string; credentialNumber: string; status: CredentialStatus; supersededBy: string | null };
}

interface Ctx {
  institutionId: string;
  actorId: string | null;
  masterKey: Buffer | undefined;
  ipHash?: string | undefined;
}

interface Locked {
  id: string;
  credential_number: string;
  status: CredentialStatus;
  holder_id: string;
  type_code: string;
  payload: { attributes?: Record<string, string>; expiresAt?: string | null };
}

/** Lock the credential row (tenant filtered; a foreign or malformed id is a 404). Serialises concurrent changes. */
async function lockCredential(c: PoolClient, id: string): Promise<Locked> {
  if (!isUuid(id)) throw new NotFoundError();
  const r = await c.query<Locked>(
    `SELECT c.id, c.credential_number, c.status, c.holder_id, c.payload, t.code AS type_code
       FROM credentials c JOIN credential_types t ON t.id = c.type_id AND t.institution_id = c.institution_id
      WHERE c.id = $1 AND c.institution_id = app_institution_id() FOR UPDATE OF c`,
    [id],
  );
  if (!r.rows[0]) throw new NotFoundError();
  return r.rows[0];
}

function plan(from: CredentialStatus, action: LifecycleAction, reason: string | undefined) {
  try {
    return planTransition(from, action, reason);
  } catch (e) {
    if (e instanceof LifecycleError) {
      if (e.code === 'REASON_REQUIRED') throw badRequest('REASON_REQUIRED', 'A reason is required');
      throw new AppError(409, 'INVALID_TRANSITION', `This credential is ${from} and cannot be ${pastTense(action)}`);
    }
    throw e;
  }
}
const pastTense = (a: LifecycleAction): string =>
  ({ ISSUE: 'issued', SUSPEND: 'suspended', REINSTATE: 'reinstated', REVOKE: 'revoked', REISSUE: 'reissued' })[a];

export class CredentialLifecycleService {
  constructor(
    private readonly db: Db,
    private readonly opts: { masterKey: Buffer | undefined; hashIp?: (ip: string | undefined) => string | undefined },
  ) {}

  private ctx(s: TenantSession, ip?: string): Ctx {
    return { institutionId: s.institutionId, actorId: s.userId, masterKey: this.opts.masterKey, ipHash: this.opts.hashIp?.(ip) };
  }

  /** suspend / reinstate / revoke. */
  async change(
    session: TenantSession,
    id: string,
    action: 'SUSPEND' | 'REINSTATE' | 'REVOKE',
    body: LifecycleBody,
    ip?: string,
  ): Promise<LifecycleResult> {
    const ctx = this.ctx(session, ip);
    return this.db.withTenant(session, async (c) => {
      const cur = await lockCredential(c, id);
      const t = plan(cur.status, action, body.reason);
      await c.query(
        `INSERT INTO credential_events (id, institution_id, credential_id, type, payload)
         VALUES ($1, app_institution_id(), $2, $3::credential_event_type, $4::jsonb)`,
        [randomUUID(), cur.id, t.event, JSON.stringify({ from: cur.status, to: t.to })],
      );
      await c.query(`UPDATE credentials SET status = $2::credential_status, updated_at = now() WHERE id = $1 AND institution_id = app_institution_id()`, [
        cur.id,
        t.to,
      ]);
      await appendAudit(c, {
        institutionId: ctx.institutionId,
        actorId: ctx.actorId,
        action: `credential.${t.event.toLowerCase()}`,
        targetType: 'credential',
        targetId: cur.id,
        metadata: { credentialNumber: cur.credential_number, previousStatus: cur.status, status: t.to, ...(body.reason ? { reason: body.reason } : {}) },
        ip: ctx.ipHash ?? null,
      });
      return { id: cur.id, credentialNumber: cur.credential_number, status: t.to, previousStatus: cur.status };
    });
  }

  /**
   * Reissue: issue a new credential through the single issuance path, then supersede the old one (ACTIVE only) in the
   * same transaction. A REVOKED credential may be reissued (mistaken revocation): it stays REVOKED (the DB forbids
   * any change) and the link is recorded on the new credential's ISSUED event and audit entries.
   */
  async reissue(session: TenantSession, id: string, body: ReissueBody, ip?: string): Promise<ReissueResult> {
    const ctx = this.ctx(session, ip);
    return this.db.withTenant(session, async (c) => {
      const old = await lockCredential(c, id);
      let supersede = false;
      if (old.status === 'REVOKED') {
        supersede = false;
      } else {
        plan(old.status, 'REISSUE', body.reason); // ACTIVE only; anything else is 409
        supersede = true;
      }
      // One replacement per revoked credential (an ACTIVE one is single-use by becoming SUPERSEDED).
      const dup = await c.query(
        `SELECT 1 FROM credential_events WHERE institution_id = app_institution_id() AND type = 'ISSUED'
            AND payload->>'reissuedFrom' = $1 LIMIT 1`,
        [old.id],
      );
      if (dup.rows.length > 0) throw new AppError(409, 'ALREADY_REISSUED', 'This credential has already been reissued');

      const input: IssueInput = {
        holderId: old.holder_id,
        credentialTypeCode: old.type_code,
        attributes: body.attributes ?? { ...(old.payload.attributes ?? {}) },
        expiresAt: body.expiresAt !== undefined ? body.expiresAt : (old.payload.expiresAt ?? null),
      };
      const fresh = await issueInTransaction(c, ctx, input, { reissuedFrom: old.id });

      if (supersede) {
        await c.query(
          `INSERT INTO credential_events (id, institution_id, credential_id, type, payload)
           VALUES ($1, app_institution_id(), $2, 'REISSUED', $3::jsonb)`,
          [randomUUID(), old.id, JSON.stringify({ from: old.status, to: 'SUPERSEDED', supersededBy: fresh.id })],
        );
        await c.query(
          `UPDATE credentials SET status = 'SUPERSEDED', superseded_by = $2, updated_at = now()
            WHERE id = $1 AND institution_id = app_institution_id()`,
          [old.id, fresh.id],
        );
      }
      await appendAudit(c, {
        institutionId: ctx.institutionId,
        actorId: ctx.actorId,
        action: 'credential.reissued',
        targetType: 'credential',
        targetId: old.id,
        metadata: {
          credentialNumber: old.credential_number,
          previousStatus: old.status,
          status: supersede ? 'SUPERSEDED' : old.status,
          newCredentialId: fresh.id,
          newCredentialNumber: fresh.credentialNumber,
          reason: body.reason,
        },
        ip: ctx.ipHash ?? null,
      });
      return {
        credential: fresh,
        previous: {
          id: old.id,
          credentialNumber: old.credential_number,
          status: supersede ? 'SUPERSEDED' : old.status,
          supersededBy: supersede ? fresh.id : null,
        },
      };
    });
  }
}

const tenantScope = (s: AuthSession | null): TenantSession => {
  if (!s || s.kind !== 'tenant') throw new AppError(403, 'FORBIDDEN', 'Insufficient role');
  return { kind: 'tenant', userId: s.userId, institutionId: s.institutionId };
};

export function registerCredentialLifecycle(
  app: FastifyInstance,
  svc: CredentialLifecycleService,
  log: FastifyBaseLogger,
  cardRender?: CardRenderQueue,
): void {
  const ia = { preHandler: app.requireRole('INSTITUTION_ADMIN') };
  type P = { Params: { id: string } };

  const simple = (path: string, action: 'SUSPEND' | 'REINSTATE' | 'REVOKE', reasonRequired: boolean) => {
    app.post<P>(`/credentials/:id/${path}`, ia, async (req, reply) => {
      void reply.header('Cache-Control', 'no-store');
      const scope = tenantScope(req.session);
      const body = parseLifecycleBody(req.body, reasonRequired);
      const out = await svc.change(scope, req.params.id, action, body, req.ip);
      log.info({ event: `credential.${path}`, actorId: scope.userId, institutionId: scope.institutionId, credentialId: out.id }, 'credential status changed');
      return reply.status(200).send(out);
    });
  };
  simple('suspend', 'SUSPEND', true);
  simple('reinstate', 'REINSTATE', false);
  simple('revoke', 'REVOKE', true);

  app.post<P>('/credentials/:id/reissue', ia, async (req, reply) => {
    void reply.header('Cache-Control', 'no-store');
    const scope = tenantScope(req.session);
    const body = parseReissueBody(req.body);
    const out = await svc.reissue(scope, req.params.id, body, req.ip);
    log.info(
      { event: 'credential.reissued', actorId: scope.userId, institutionId: scope.institutionId, credentialId: req.params.id, newCredentialId: out.credential.id },
      'credential reissued',
    );
    // After commit: render the NEW credential's card. Failure is logged and never fails the reissue.
    await enqueueCardAfterCommit(cardRender, log, { institutionId: scope.institutionId, credentialId: out.credential.id });
    return reply.status(201).send(out);
  });
}
