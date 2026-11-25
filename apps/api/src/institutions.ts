// Platform-admin institution management (T-015): list, create (with first signing key and first-admin
// invite) and suspend/unsuspend. Every query runs in platform scope through Db.withTenant; the scope
// comes from the authenticated session, never from the request.
//
// Key custody (invariant 8): the new Ed25519 private key exists unwrapped only inside
// generateSigningKey (packages/core) and is returned already AES-256-GCM-wrapped under the master key,
// bound to its kid. This module never unwraps and never holds a plaintext private key.
import { randomUUID } from 'node:crypto';
import type { FastifyBaseLogger, FastifyInstance, FastifyRequest } from 'fastify';
import type { PoolClient } from 'pg';
import { generateSigningKey } from '@igaro/core';
import { newOneTimeToken, normalizeEmail, type AccountService } from './account.js';
import type { AuthSession } from './auth.js';
import { isUuid, type Db, type PlatformSession } from './db.js';
import { appendAudit } from './audit.js';
import { AppError, NotFoundError } from './errors.js';

export const SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{1,38}[a-z0-9])$/; // 3-40 chars, no leading/trailing hyphen
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_NAME = 200;
const MAX_EMAIL = 254;
const MAX_REASON = 500;
const MAX_KID_ATTEMPTS = 5;
export const DEFAULT_PAGE = 50;
export const MAX_PAGE = 200;

export type InstitutionStatus = 'ACTIVE' | 'SUSPENDED';

export interface InstitutionView {
  id: string;
  name: string;
  slug: string;
  status: InstitutionStatus;
  createdAt: string;
  updatedAt: string;
  /** kid of the ACTIVE signing key (public identifier). Key material is never returned. */
  activeKid: string | null;
}

interface InstitutionRow {
  id: string;
  name: string;
  slug: string;
  status: InstitutionStatus;
  created_at: Date;
  updated_at: Date;
  active_kid: string | null;
  created_cursor?: string;
}

const toView = (r: InstitutionRow): InstitutionView => ({
  id: r.id,
  name: r.name,
  slug: r.slug,
  status: r.status,
  createdAt: r.created_at.toISOString(),
  updatedAt: r.updated_at.toISOString(),
  activeKid: r.active_kid,
});

const badRequest = (message = 'Invalid request') => new AppError(400, 'BAD_REQUEST', message);

const SELECT_VIEW = `
  SELECT i.id, i.name, i.slug, i.status, i.created_at, i.updated_at,
         i.created_at::text AS created_cursor,
         (SELECT k.kid FROM institution_keys k
           WHERE k.institution_id = i.id AND k.status = 'ACTIVE') AS active_kid
    FROM institutions i`;

const constraintOf = (e: unknown): string | undefined =>
  (e as { code?: string; constraint?: string }).code === '23505'
    ? (e as { constraint?: string }).constraint
    : undefined;

export interface InstitutionServiceOptions {
  /** 32-byte master key (key-encryption key). Without it creation is refused with 503. */
  masterKey: Buffer | undefined;
  log?: FastifyBaseLogger;
  /** Keyed IP hash for audit entries (ADR 0003). Without it entries store no IP. */
  hashIp?: (ip: string | undefined) => string | undefined;
}

export class InstitutionService {
  constructor(
    private readonly db: Db,
    private readonly account: AccountService,
    private readonly opts: InstitutionServiceOptions,
  ) {}

  async list(
    scope: PlatformSession,
    page: { cursor?: string; limit?: number },
  ): Promise<{ items: InstitutionView[]; nextCursor: string | null }> {
    const limit = page.limit ?? DEFAULT_PAGE;
    let after: [string, string] | undefined;
    if (page.cursor !== undefined) {
      try {
        const v: unknown = JSON.parse(Buffer.from(page.cursor, 'base64url').toString('utf8'));
        if (
          Array.isArray(v) &&
          v.length === 2 &&
          typeof v[0] === 'string' &&
          !Number.isNaN(Date.parse(v[0])) &&
          isUuid(v[1])
        ) {
          after = [v[0], v[1]];
        }
      } catch {
        // falls through to the error below
      }
      if (!after) throw badRequest('Invalid cursor');
    }
    const rows = await this.db.withTenant(scope, async (c) => {
      // Keyset on (created_at, id). The cursor carries created_at as Postgres text so microseconds
      // survive (a JS Date would truncate them and skip or repeat rows).
      const r = await c.query<InstitutionRow>(
        `${SELECT_VIEW}
          WHERE ($1::timestamptz IS NULL OR (i.created_at, i.id) > ($1::timestamptz, $2::uuid))
          ORDER BY i.created_at, i.id
          LIMIT $3`,
        [after?.[0] ?? null, after?.[1] ?? null, limit + 1],
      );
      return r.rows;
    });
    const more = rows.length > limit;
    const items = rows.slice(0, limit);
    const last = items[items.length - 1];
    const nextCursor =
      more && last
        ? Buffer.from(JSON.stringify([last.created_cursor, last.id])).toString('base64url')
        : null;
    return { items: items.map(toView), nextCursor };
  }

  /**
   * Create the institution, its ACTIVE signing key and the first-admin invite in ONE transaction,
   * then enqueue the invite mail after commit.
   */
  async create(
    scope: PlatformSession,
    input: { name: string; slug: string; adminEmail: string },
    ip?: string,
  ): Promise<{ institution: InstitutionView; inviteQueued: boolean }> {
    const masterKey = this.opts.masterKey;
    if (!masterKey) {
      throw new AppError(503, 'KEY_CUSTODY_UNAVAILABLE', 'Signing keys cannot be created right now');
    }
    const email = normalizeEmail(input.adminEmail);
    const id = randomUUID();
    const token = newOneTimeToken();

    let result: { institution: InstitutionView; expiresAt: Date };
    try {
      result = await this.db.withTenant(scope, async (c) => {
        const taken = await c.query(`SELECT 1 FROM users WHERE email = $1`, [email]);
        if (taken.rowCount) throw new AppError(409, 'EMAIL_IN_USE', 'That email already has an account');

        await c.query(
          `INSERT INTO institutions (id, name, slug, status, updated_at)
           VALUES ($1, $2, $3, 'ACTIVE', now())`,
          [id, input.name, input.slug],
        );
        await this.insertActiveKey(c, id, masterKey);
        const expiresAt = await this.account.insertInvite(c, id, email, token);
        await appendAudit(c, {
          institutionId: id,
          actorId: scope.userId,
          action: 'institution.created',
          targetType: 'institution',
          targetId: id,
          metadata: { slug: input.slug },
          ip: this.opts.hashIp?.(ip),
        });
        const row = (await c.query<InstitutionRow>(`${SELECT_VIEW} WHERE i.id = $1`, [id])).rows[0]!;
        return { institution: toView(row), expiresAt };
      });
    } catch (e) {
      if (constraintOf(e) === 'institutions_slug_key') {
        throw new AppError(409, 'SLUG_TAKEN', 'That slug is already in use');
      }
      throw e;
    }

    // After commit. A queue failure must not undo the institution; report it instead.
    let inviteQueued = true;
    try {
      await this.account.sendInvite({
        email,
        token,
        expiresAt: result.expiresAt,
        institutionId: id,
      });
    } catch (err) {
      inviteQueued = false;
      this.opts.log?.error({ err, institutionId: id }, 'first-admin invite enqueue failed');
    }
    return { institution: result.institution, inviteQueued };
  }

  /** Generate and store the ACTIVE key, retrying (under a savepoint) if the random kid collides. */
  private async insertActiveKey(c: PoolClient, institutionId: string, masterKey: Buffer): Promise<string> {
    for (let attempt = 1; attempt <= MAX_KID_ATTEMPTS; attempt++) {
      const key = generateSigningKey(masterKey);
      await c.query('SAVEPOINT key_insert');
      try {
        await c.query(
          `INSERT INTO institution_keys
             (id, institution_id, kid, algorithm, public_key, encrypted_private_key, status)
           VALUES (gen_random_uuid(), $1, $2, 'Ed25519', $3, $4, 'ACTIVE')`,
          [institutionId, key.kid, key.publicKey, key.encryptedPrivateKey],
        );
        await c.query('RELEASE SAVEPOINT key_insert');
        return key.kid;
      } catch (e) {
        if (constraintOf(e) !== 'institution_keys_kid_key' || attempt === MAX_KID_ATTEMPTS) throw e;
        await c.query('ROLLBACK TO SAVEPOINT key_insert');
      }
    }
    throw new Error('unreachable');
  }

  /**
   * Suspend or reinstate an institution. Idempotent: setting the current status changes nothing.
   * Returns the previous status so the caller can record the change.
   */
  async setStatus(
    scope: PlatformSession,
    id: string,
    status: InstitutionStatus,
    reason?: string,
    ip?: string,
  ): Promise<{ institution: InstitutionView; previous: InstitutionStatus }> {
    if (!isUuid(id)) throw new NotFoundError();
    return this.db.withTenant(scope, async (c) => {
      const cur = await c.query<{ status: InstitutionStatus }>(
        `SELECT status FROM institutions WHERE id = $1 FOR UPDATE`,
        [id],
      );
      const previous = cur.rows[0]?.status;
      if (!previous) throw new NotFoundError();
      if (previous !== status) {
        await c.query(`UPDATE institutions SET status = $2, updated_at = now() WHERE id = $1`, [
          id,
          status,
        ]);
        await appendAudit(c, {
          institutionId: id,
          actorId: scope.userId,
          action: status === 'SUSPENDED' ? 'institution.suspended' : 'institution.reinstated',
          targetType: 'institution',
          targetId: id,
          metadata: { from: previous, to: status, ...(reason ? { reason } : {}) },
          ip: this.opts.hashIp?.(ip),
        });
      }
      const row = (await c.query<InstitutionRow>(`${SELECT_VIEW} WHERE i.id = $1`, [id])).rows[0]!;
      return { institution: toView(row), previous };
    });
  }
}

// --- HTTP -------------------------------------------------------------------------------------------

const bodyOf = (req: FastifyRequest): Record<string, unknown> => {
  const b = req.body;
  return b && typeof b === 'object' && !Array.isArray(b) ? (b as Record<string, unknown>) : {};
};

const text = (v: unknown, max: number): string => {
  if (typeof v !== 'string') throw badRequest();
  const t = v.trim();
  if (t.length === 0 || t.length > max) throw badRequest();
  // NUL / control characters and lone surrogates cannot be stored as JSONB (audit metadata).
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(t) || /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(t)) {
    throw badRequest();
  }
  return t;
};

const platformScope = (req: FastifyRequest): PlatformSession => {
  const s: AuthSession | null = req.session;
  if (!s || s.kind !== 'platform') throw new AppError(403, 'FORBIDDEN', 'Insufficient role');
  return { kind: 'platform', userId: s.userId };
};

export function registerInstitutions(
  app: FastifyInstance,
  svc: InstitutionService,
  log: FastifyBaseLogger,
): void {
  const pa = { preHandler: app.requireRole('PLATFORM_ADMIN') };

  app.get('/institutions', pa, async (req, reply) => {
    void reply.header('Cache-Control', 'no-store');
    const q = req.query as Record<string, unknown>;
    let limit: number | undefined;
    if (q.limit !== undefined) {
      if (typeof q.limit !== 'string' || !/^\d{1,4}$/.test(q.limit)) throw badRequest();
      limit = Number(q.limit);
      if (limit < 1 || limit > MAX_PAGE) throw badRequest();
    }
    if (q.cursor !== undefined && (typeof q.cursor !== 'string' || q.cursor.length > 200)) {
      throw badRequest('Invalid cursor');
    }
    return svc.list(platformScope(req), { cursor: q.cursor as string | undefined, limit });
  });

  app.post('/institutions', pa, async (req, reply) => {
    void reply.header('Cache-Control', 'no-store');
    const b = bodyOf(req);
    const name = text(b.name, MAX_NAME);
    const slug = text(b.slug, 40);
    if (!SLUG_RE.test(slug)) {
      throw new AppError(400, 'INVALID_SLUG', 'Slug must be 3-40 lowercase letters, digits or hyphens');
    }
    const adminEmail = text(b.adminEmail, MAX_EMAIL);
    if (!EMAIL_RE.test(adminEmail)) throw new AppError(400, 'INVALID_EMAIL', 'Invalid email address');

    const scope = platformScope(req);
    const out = await svc.create(scope, { name, slug, adminEmail }, req.ip);
    log.info(
      { event: 'institution.created', actorId: scope.userId, institutionId: out.institution.id },
      'institution created',
    );
    return reply.status(201).send(out);
  });

  app.patch('/institutions/:id/status', pa, async (req, reply) => {
    void reply.header('Cache-Control', 'no-store');
    const { id } = req.params as { id: string };
    const b = bodyOf(req);
    if (b.status !== 'ACTIVE' && b.status !== 'SUSPENDED') throw badRequest();
    let reason: string | undefined;
    if (b.status === 'SUSPENDED') {
      if (b.reason === undefined) throw new AppError(400, 'REASON_REQUIRED', 'A reason is required');
      reason = text(b.reason, MAX_REASON);
    } else if (b.reason !== undefined && b.reason !== null) {
      reason = text(b.reason, MAX_REASON);
    }
    const scope = platformScope(req);
    const out = await svc.setStatus(scope, id, b.status, reason, req.ip);
    if (out.previous !== b.status) {
      // The reason lives in the hash-chained audit log (same transaction), not in the log line.
      log.info(
        {
          event: 'institution.status_changed',
          actorId: scope.userId,
          institutionId: id,
          from: out.previous,
          to: b.status,
        },
        'institution status changed',
      );
    }
    return out.institution;
  });
}
