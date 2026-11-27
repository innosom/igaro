// Signing key management for the session's own institution (T-017): list, rotate, mark compromised.
// Institution Admin only; the institution id comes from the session, never the request.
//
// Key custody (invariant 8): new keys are generated and returned already wrapped (generateSigningKey);
// this module never unwraps a private key and never returns or logs key material beyond the public key.
// A COMPROMISED key is terminal. At most one ACTIVE key exists: every change locks the institution row.
import type { FastifyBaseLogger, FastifyInstance, FastifyRequest } from 'fastify';
import type { PoolClient } from 'pg';
import { generateSigningKey } from '@igaro/core';
import type { AuthSession } from './auth.js';
import type { Db, TenantSession } from './db.js';
import { appendAudit } from './audit.js';
import { verifyPassword } from './auth.js';
import { AppError, NotFoundError, RateLimitedError } from './errors.js';
import { assertInstitutionActive } from './institution-guard.js';
import { PgRateLimiter } from './rate-limit.js';

const MAX_REASON = 500;
const MAX_KID_ATTEMPTS = 5;
const KID_RE = /^kid_[0-9a-f]{16}$/;

export type KeyStatus = 'ACTIVE' | 'RETIRED' | 'COMPROMISED';

export interface KeyView {
  kid: string;
  algorithm: string;
  publicKey: string;
  status: KeyStatus;
  createdAt: string;
  retiredAt: string | null;
}

interface KeyRow {
  kid: string;
  algorithm: string;
  public_key: string;
  status: KeyStatus;
  created_at: Date;
  retired_at: Date | null;
}

const COLS = `kid, algorithm, public_key, status, created_at, retired_at`;
const toView = (r: KeyRow): KeyView => ({
  kid: r.kid,
  algorithm: r.algorithm,
  publicKey: r.public_key,
  status: r.status,
  createdAt: r.created_at.toISOString(),
  retiredAt: r.retired_at ? r.retired_at.toISOString() : null,
});

const constraintOf = (e: unknown): string | undefined =>
  (e as { code?: string }).code === '23505' ? (e as { constraint?: string }).constraint : undefined;

export interface KeyChangeRateLimit {
  max: number;
  windowSeconds: number;
}
export const DEFAULT_KEY_CHANGE_RATE_LIMIT: KeyChangeRateLimit = { max: 10, windowSeconds: 3600 };

export interface SigningKeyOptions {
  rateLimit?: KeyChangeRateLimit;
  hashIp?: (ip: string | undefined) => string | undefined;
}

export class SigningKeyService {
  private readonly limiter: PgRateLimiter;

  constructor(
    private readonly db: Db,
    private readonly masterKey: Buffer | undefined,
    private readonly opts: SigningKeyOptions = {},
  ) {
    const rl = opts.rateLimit ?? DEFAULT_KEY_CHANGE_RATE_LIMIT;
    this.limiter = new PgRateLimiter({ db, family: 'keychange', max: rl.max, windowSeconds: rl.windowSeconds, onError: 'closed' });
  }

  /**
   * Per-institution rate limit (rotate and compromise share it; wrong passwords count), then password
   * re-entry against the session user's own hash (ADR 0012 decision 3). Runs before any key change.
   */
  private async authorise(session: TenantSession, password: string): Promise<void> {
    const wait = await this.limiter.consume(session.institutionId);
    if (wait > 0) throw new RateLimitedError(wait);
    const hash = await this.db.withTenant(session, async (c) => {
      const r = await c.query<{ password_hash: string | null }>(
        `SELECT password_hash FROM users WHERE id = $1 AND institution_id = app_institution_id() AND status = 'ACTIVE'`,
        [session.userId],
      );
      return r.rows[0]?.password_hash ?? null;
    });
    if (!(await verifyPassword(hash, password))) {
      throw new AppError(403, 'PASSWORD_INVALID', 'Password confirmation failed');
    }
  }

  private requireMaster(): Buffer {
    if (!this.masterKey) {
      throw new AppError(503, 'KEY_CUSTODY_UNAVAILABLE', 'Signing keys cannot be changed right now');
    }
    return this.masterKey;
  }

  async list(session: TenantSession): Promise<KeyView[]> {
    return this.db.withTenant(session, async (c) => {
      const r = await c.query<KeyRow>(
        `SELECT ${COLS} FROM institution_keys WHERE institution_id = app_institution_id()
          ORDER BY created_at, kid`,
      );
      return r.rows.map(toView);
    });
  }

  /** Retire the ACTIVE key (if any) and create a new ACTIVE one, in one transaction. */
  async rotate(
    session: TenantSession,
    password: string,
    ip?: string,
  ): Promise<{ active: KeyView; retiredKid: string | null }> {
    const master = this.requireMaster();
    await this.authorise(session, password);
    return this.db.withTenant(session, async (c) => {
      await this.lockInstitution(c);
      await assertInstitutionActive(c);
      const retired = await c.query<{ kid: string }>(
        `UPDATE institution_keys SET status = 'RETIRED', retired_at = now()
          WHERE institution_id = app_institution_id() AND status = 'ACTIVE' RETURNING kid`,
      );
      const active = await this.insertActive(c, master);
      const retiredKid = retired.rows[0]?.kid ?? null;
      await appendAudit(c, {
        institutionId: session.institutionId,
        actorId: session.userId,
        action: 'key.rotated',
        targetType: 'institution_key',
        targetId: active.kid,
        metadata: { kid: active.kid, retiredKid },
        ip: this.opts.hashIp?.(ip) ?? null,
      });
      return { active, retiredKid };
    });
  }

  /**
   * Mark a key COMPROMISED (terminal, idempotent). If it was the ACTIVE key a replacement is created in
   * the same transaction so the institution is never left without a signing key.
   */
  async markCompromised(
    session: TenantSession,
    kid: string,
    reason: string,
    password: string,
    ip?: string,
  ): Promise<{ key: KeyView; replacement: KeyView | null; previous: KeyStatus }> {
    if (!KID_RE.test(kid)) throw new NotFoundError();
    const master = this.requireMaster();
    await this.authorise(session, password);
    return this.db.withTenant(session, async (c) => {
      await this.lockInstitution(c);
      const cur = await c.query<KeyRow>(
        `SELECT ${COLS} FROM institution_keys
          WHERE institution_id = app_institution_id() AND kid = $1 FOR UPDATE`,
        [kid],
      );
      const row = cur.rows[0];
      if (!row) throw new NotFoundError();
      if (row.status === 'COMPROMISED') return { key: toView(row), replacement: null, previous: row.status };
      const upd = await c.query<KeyRow>(
        `UPDATE institution_keys SET status = 'COMPROMISED', retired_at = COALESCE(retired_at, now())
          WHERE institution_id = app_institution_id() AND kid = $1 RETURNING ${COLS}`,
        [kid],
      );
      const replacement = row.status === 'ACTIVE' ? await this.insertActive(c, master) : null;
      await appendAudit(c, {
        institutionId: session.institutionId,
        actorId: session.userId,
        action: 'key.compromised',
        targetType: 'institution_key',
        targetId: kid,
        metadata: { kid, previousStatus: row.status, replacementKid: replacement?.kid ?? null, reason },
        ip: this.opts.hashIp?.(ip) ?? null,
      });
      return { key: toView(upd.rows[0]!), replacement, previous: row.status };
    });
  }

  /** Serialises key changes per institution so there is never more than one ACTIVE key. */
  private async lockInstitution(c: PoolClient): Promise<void> {
    const r = await c.query(`SELECT 1 FROM institutions WHERE id = app_institution_id() FOR UPDATE`);
    if (!r.rowCount) throw new NotFoundError();
  }

  private async insertActive(c: PoolClient, master: Buffer): Promise<KeyView> {
    for (let attempt = 1; attempt <= MAX_KID_ATTEMPTS; attempt++) {
      const key = generateSigningKey(master);
      await c.query('SAVEPOINT key_insert');
      try {
        const r = await c.query<KeyRow>(
          `INSERT INTO institution_keys
             (id, institution_id, kid, algorithm, public_key, encrypted_private_key, status)
           VALUES (gen_random_uuid(), app_institution_id(), $1, 'Ed25519', $2, $3, 'ACTIVE')
           RETURNING ${COLS}`,
          [key.kid, key.publicKey, key.encryptedPrivateKey],
        );
        await c.query('RELEASE SAVEPOINT key_insert');
        return toView(r.rows[0]!);
      } catch (e) {
        if (constraintOf(e) !== 'institution_keys_kid_key' || attempt === MAX_KID_ATTEMPTS) throw e;
        await c.query('ROLLBACK TO SAVEPOINT key_insert');
      }
    }
    throw new Error('unreachable');
  }
}

const tenantScope = (req: FastifyRequest): TenantSession => {
  const s: AuthSession | null = req.session;
  if (!s || s.kind !== 'tenant') throw new AppError(403, 'FORBIDDEN', 'Insufficient role');
  return { kind: 'tenant', userId: s.userId, institutionId: s.institutionId };
};

/** Password re-entry (ADR 0012 decision 3). Never echoed or logged. */
function parsePassword(body: unknown): string {
  const p =
    body && typeof body === 'object' && !Array.isArray(body) ? (body as Record<string, unknown>).password : undefined;
  if (typeof p !== 'string' || p.length === 0 || p.length > 1024) {
    throw new AppError(400, 'PASSWORD_REQUIRED', 'Password confirmation is required');
  }
  return p;
}

export function registerSigningKeys(app: FastifyInstance, svc: SigningKeyService, log: FastifyBaseLogger): void {
  const ia = { preHandler: app.requireRole('INSTITUTION_ADMIN') };

  app.get('/institution/keys', ia, async (req, reply) => {
    void reply.header('Cache-Control', 'no-store');
    return { items: await svc.list(tenantScope(req)) };
  });

  app.post('/institution/keys/rotate', ia, async (req, reply) => {
    void reply.header('Cache-Control', 'no-store');
    const scope = tenantScope(req);
    const out = await svc.rotate(scope, parsePassword(req.body), req.ip);
    log.info(
      {
        event: 'key.rotated',
        actorId: scope.userId,
        institutionId: scope.institutionId,
        kid: out.active.kid,
        retiredKid: out.retiredKid,
      },
      'signing key rotated',
    );
    return reply.status(201).send(out);
  });

  app.post('/institution/keys/:kid/compromise', ia, async (req, reply) => {
    void reply.header('Cache-Control', 'no-store');
    const { kid } = req.params as { kid: string };
    const b = req.body;
    const reason =
      b && typeof b === 'object' && !Array.isArray(b) ? (b as Record<string, unknown>).reason : undefined;
    if (reason === undefined) throw new AppError(400, 'REASON_REQUIRED', 'A reason is required');
    if (typeof reason !== 'string' || reason.trim().length === 0 || reason.trim().length > MAX_REASON) {
      throw new AppError(400, 'BAD_REQUEST', 'Invalid request');
    }
    const scope = tenantScope(req);
    const out = await svc.markCompromised(scope, kid, reason.trim(), parsePassword(b), req.ip);
    if (out.previous !== 'COMPROMISED') {
      // The reason lives only in the audit entry (same transaction), never in application logs.
      log.warn(
        {
          event: 'key.compromised',
          actorId: scope.userId,
          institutionId: scope.institutionId,
          kid,
          from: out.previous,
          replacementKid: out.replacement?.kid ?? null,
        },
        'signing key marked compromised',
      );
    }
    return out;
  });
}
