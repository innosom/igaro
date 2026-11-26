// Credential holders (T-018): CRUD and photo upload for the session's own institution. Institution Admin only.
// The institution id comes from the authenticated session, never from the request. Every query runs in
// Db.withTenant (RLS sets app.institution_id) and also filters on app_institution_id(). Another tenant's
// holder id is indistinguishable from an unknown one: 404.
import { createHash, randomUUID } from 'node:crypto';
import multipart from '@fastify/multipart';
import type { FastifyBaseLogger, FastifyInstance, FastifyRequest } from 'fastify';
import type { PoolClient } from 'pg';
import { appendAudit } from './audit.js';
import { assertInstitutionActive } from './institution-guard.js';
import type { AuthSession } from './auth.js';
import { isUuid, type Db, type TenantSession } from './db.js';
import { AppError, NotFoundError } from './errors.js';
import { extensionOf } from './image.js';
import { StorageError, type ObjectStorage } from './storage.js';
import { readImageUpload } from './uploads.js';

export const DEFAULT_PHOTO_MAX_BYTES = 2 * 1024 * 1024;
/** Lifetime of the signed GET URL returned with a holder (private bucket, ADR 0010). */
export const PHOTO_URL_TTL_SECONDS = 300;
const MAX_NAME = 200;
const MAX_EXTERNAL_ID = 100;
const MAX_EMAIL = 254;
const MAX_SEARCH = 100;
const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u001f\u007f]/;

export interface HolderView {
  id: string;
  fullName: string;
  externalId: string | null;
  email: string | null;
  hasPhoto: boolean;
  /** SHA-256 (hex) of the stored, metadata-stripped photo bytes: what credential payloads commit to. */
  photoSha256: string | null;
  credentialCount: number;
  createdAt: string;
  updatedAt: string;
  /** Short-lived signed URL; only on single-holder responses and only when storage is configured. */
  photoUrl?: string;
}

interface Row {
  id: string;
  full_name: string;
  external_id: string | null;
  email: string | null;
  photo_key: string | null;
  photo_sha256: string | null;
  credential_count: number;
  created_at: Date;
  updated_at: Date;
}

const SELECT = `SELECT h.id, h.full_name, h.external_id, h.email, h.photo_key, h.photo_sha256,
    (SELECT count(*)::int FROM credentials c
      WHERE c.holder_id = h.id AND c.institution_id = app_institution_id()) AS credential_count,
    h.created_at, h.updated_at
  FROM credential_holders h`;

const toView = (r: Row): HolderView => ({
  id: r.id,
  fullName: r.full_name,
  externalId: r.external_id,
  email: r.email,
  hasPhoto: r.photo_key !== null,
  photoSha256: r.photo_sha256,
  credentialCount: r.credential_count,
  createdAt: r.created_at.toISOString(),
  updatedAt: r.updated_at.toISOString(),
});

const badRequest = (code: string, message: string) => new AppError(400, code, message);

export interface HolderInput {
  fullName?: string;
  externalId?: string | null;
  email?: string | null;
}

function parseName(v: unknown): string {
  if (typeof v !== 'string') throw badRequest('INVALID_FULL_NAME', 'Full name is required');
  const t = v.trim();
  if (t.length < 1 || t.length > MAX_NAME || CONTROL_RE.test(t)) {
    throw badRequest('INVALID_FULL_NAME', 'Full name must be 1-200 characters');
  }
  return t;
}

function parseExternalId(v: unknown): string | null {
  if (v === null) return null;
  if (typeof v !== 'string') throw badRequest('INVALID_EXTERNAL_ID', 'Invalid external id');
  const t = v.trim();
  if (t.length < 1 || t.length > MAX_EXTERNAL_ID || CONTROL_RE.test(t)) {
    throw badRequest('INVALID_EXTERNAL_ID', 'External id must be 1-100 characters or null');
  }
  return t;
}

function parseEmail(v: unknown): string | null {
  if (v === null) return null;
  if (typeof v !== 'string') throw badRequest('INVALID_EMAIL', 'Invalid email');
  const t = v.trim().toLowerCase();
  if (t.length > MAX_EMAIL || !EMAIL_RE.test(t) || CONTROL_RE.test(t)) {
    throw badRequest('INVALID_EMAIL', 'Invalid email address');
  }
  return t;
}

/** Validate a create/patch body. Unknown properties are rejected; nothing from the body is echoed back. */
export function parseHolderBody(body: unknown, mode: 'create' | 'patch'): HolderInput {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw badRequest('BAD_REQUEST', 'Invalid request');
  const b = body as Record<string, unknown>;
  const known = new Set(['fullName', 'externalId', 'email']);
  if (Object.keys(b).some((k) => !known.has(k))) throw badRequest('UNKNOWN_PROPERTY', 'Unknown property');
  const out: HolderInput = {};
  if ('fullName' in b) out.fullName = parseName(b.fullName);
  else if (mode === 'create') throw badRequest('INVALID_FULL_NAME', 'Full name is required');
  if ('externalId' in b) out.externalId = parseExternalId(b.externalId);
  if ('email' in b) out.email = parseEmail(b.email);
  if (mode === 'patch' && Object.keys(out).length === 0) throw badRequest('BAD_REQUEST', 'Nothing to update');
  return out;
}

export interface ListQuery {
  q?: string;
  limit: number;
  offset: number;
}

export function parseListQuery(query: unknown): ListQuery {
  const q = (query ?? {}) as Record<string, unknown>;
  const known = new Set(['q', 'limit', 'offset']);
  if (Object.keys(q).some((k) => !known.has(k))) throw badRequest('UNKNOWN_PROPERTY', 'Unknown query parameter');
  const int = (v: unknown, name: string, def: number, min: number, max: number): number => {
    if (v === undefined) return def;
    if (typeof v !== 'string' || !/^\d{1,9}$/.test(v)) throw badRequest('BAD_REQUEST', `Invalid ${name}`);
    const n = Number(v);
    if (n < min || n > max) throw badRequest('BAD_REQUEST', `Invalid ${name}`);
    return n;
  };
  let search: string | undefined;
  if (q.q !== undefined) {
    if (typeof q.q !== 'string' || q.q.length > MAX_SEARCH) throw badRequest('BAD_REQUEST', 'Invalid search');
    search = q.q.trim() || undefined;
  }
  return {
    ...(search ? { q: search } : {}),
    limit: int(q.limit, 'limit', DEFAULT_LIMIT, 1, MAX_LIMIT),
    offset: int(q.offset, 'offset', 0, 0, 1_000_000),
  };
}

const likeEscape = (s: string): string => s.replace(/[\\%_]/g, (c) => `\\${c}`);

const pgCode = (e: unknown): { code?: string; constraint?: string } =>
  e && typeof e === 'object' ? (e as { code?: string; constraint?: string }) : {};

const duplicateExternalId = () =>
  new AppError(409, 'DUPLICATE_EXTERNAL_ID', 'A holder with this external id already exists');

/** Request-scoped repository: constructed from the session, the institution is never a parameter. */
export class HolderRepository {
  constructor(
    private readonly db: Db,
    private readonly session: TenantSession,
    private readonly ipHash: string | null = null,
  ) {}

  private audit(c: PoolClient, action: string, targetId: string, metadata: Record<string, unknown>) {
    return appendAudit(c, {
      institutionId: this.session.institutionId,
      actorId: this.session.userId,
      action,
      targetType: 'holder',
      targetId,
      metadata,
      ip: this.ipHash,
    });
  }

  /** Early check (before an upload body is read or stored); setPhoto re-checks inside its transaction. */
  async assertActive(): Promise<void> {
    await this.db.withTenant(this.session, assertInstitutionActive);
  }

  async list(q: ListQuery): Promise<{ items: HolderView[]; total: number; limit: number; offset: number }> {
    return this.db.withTenant(this.session, async (c) => {
      const params: unknown[] = [];
      let where = 'WHERE h.institution_id = app_institution_id()';
      if (q.q) {
        params.push(`%${likeEscape(q.q)}%`);
        where += ` AND (h.full_name ILIKE $1 OR h.external_id ILIKE $1 OR h.email ILIKE $1)`;
      }
      const total = await c.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM credential_holders h ${where}`,
        params,
      );
      params.push(q.limit, q.offset);
      const rows = await c.query<Row>(
        `${SELECT} ${where} ORDER BY h.created_at DESC, h.id DESC LIMIT $${params.length - 1} OFFSET $${params.length}`,
        params,
      );
      return { items: rows.rows.map(toView), total: total.rows[0]!.n, limit: q.limit, offset: q.offset };
    });
  }

  async get(id: string): Promise<{ view: HolderView; photoKey: string | null }> {
    if (!isUuid(id)) throw new NotFoundError();
    return this.db.withTenant(this.session, async (c) => {
      const r = await c.query<Row>(`${SELECT} WHERE h.id = $1 AND h.institution_id = app_institution_id()`, [id]);
      const row = r.rows[0];
      if (!row) throw new NotFoundError();
      return { view: toView(row), photoKey: row.photo_key };
    });
  }

  async create(input: HolderInput): Promise<HolderView> {
    const id = randomUUID();
    try {
      return await this.db.withTenant(this.session, async (c) => {
        await c.query(
          `INSERT INTO credential_holders (id, institution_id, full_name, external_id, email, updated_at)
           VALUES ($1, app_institution_id(), $2, $3, $4, now())`,
          [id, input.fullName, input.externalId ?? null, input.email ?? null],
        );
        const r = await c.query<Row>(`${SELECT} WHERE h.id = $1 AND h.institution_id = app_institution_id()`, [id]);
        await this.audit(c, 'holder.created', id, {});
        return toView(r.rows[0]!);
      });
    } catch (e) {
      if (pgCode(e).code === '23505') throw duplicateExternalId();
      throw e;
    }
  }

  async update(id: string, patch: HolderInput): Promise<HolderView> {
    if (!isUuid(id)) throw new NotFoundError();
    const sets: string[] = [];
    const params: unknown[] = [id];
    const add = (col: string, v: unknown) => {
      params.push(v);
      sets.push(`${col} = $${params.length}`);
    };
    if (patch.fullName !== undefined) add('full_name', patch.fullName);
    if (patch.externalId !== undefined) add('external_id', patch.externalId);
    if (patch.email !== undefined) add('email', patch.email);
    try {
      return await this.db.withTenant(this.session, async (c) => {
        const u = await c.query(
          `UPDATE credential_holders SET ${sets.join(', ')}, updated_at = now()
            WHERE id = $1 AND institution_id = app_institution_id()`,
          params,
        );
        if (u.rowCount === 0) throw new NotFoundError();
        await this.audit(c, 'holder.updated', id, { fields: Object.keys(patch) }); // names only, never PII values
        const r = await c.query<Row>(`${SELECT} WHERE h.id = $1 AND h.institution_id = app_institution_id()`, [id]);
        return toView(r.rows[0]!);
      });
    } catch (e) {
      if (pgCode(e).code === '23505') throw duplicateExternalId();
      throw e;
    }
  }

  /**
   * Point the holder at a new photo object. Returns the previous key only when it is safe to delete after commit:
   * an object that a signed credential payload commits to (holder.photoSha256), or that is the same object as the
   * new one, is kept (T-018 review M1, ADR 0016). Keys are content-addressed, so card/verify can find it by hash.
   */
  async setPhoto(
    id: string,
    key: string,
    sha256: string,
  ): Promise<{ view: HolderView; previousKey: string | null }> {
    if (!isUuid(id)) throw new NotFoundError();
    return this.db.withTenant(this.session, async (c) => {
      await assertInstitutionActive(c);
      const cur = await c.query<{ photo_key: string | null; photo_sha256: string | null }>(
        `SELECT photo_key, photo_sha256 FROM credential_holders
          WHERE id = $1 AND institution_id = app_institution_id() FOR UPDATE`,
        [id],
      );
      const prev = cur.rows[0];
      if (!prev) throw new NotFoundError();
      await c.query(
        `UPDATE credential_holders SET photo_key = $2, photo_sha256 = $3, updated_at = now()
          WHERE id = $1 AND institution_id = app_institution_id()`,
        [id, key, sha256],
      );
      let deletable = prev.photo_key !== null && prev.photo_key !== key;
      if (deletable && prev.photo_sha256) {
        const used = await c.query(
          `SELECT 1 FROM credentials
            WHERE holder_id = $1 AND institution_id = app_institution_id()
              AND payload -> 'holder' ->> 'photoSha256' = $2 LIMIT 1`,
          [id, prev.photo_sha256],
        );
        if (used.rowCount) deletable = false;
      }
      await this.audit(c, 'holder.photo_updated', id, { photoSha256: sha256, previousPhotoSha256: prev.photo_sha256 });
      const r = await c.query<Row>(`${SELECT} WHERE h.id = $1 AND h.institution_id = app_institution_id()`, [id]);
      return { view: toView(r.rows[0]!), previousKey: deletable ? prev.photo_key : null };
    });
  }

  /** Delete a holder that has no credentials; returns the photo key to remove after commit. */
  async delete(id: string): Promise<string | null> {
    if (!isUuid(id)) throw new NotFoundError();
    try {
      return await this.db.withTenant(this.session, async (c) => {
        // Lock the holder row first so a concurrent issuance (which needs it to exist) cannot slip in.
        const cur = await c.query<{ photo_key: string | null }>(
          `SELECT photo_key FROM credential_holders
            WHERE id = $1 AND institution_id = app_institution_id() FOR UPDATE`,
          [id],
        );
        if (!cur.rows[0]) throw new NotFoundError();
        const n = await c.query<{ n: number }>(
          `SELECT count(*)::int AS n FROM credentials WHERE holder_id = $1 AND institution_id = app_institution_id()`,
          [id],
        );
        if (n.rows[0]!.n > 0) throw hasCredentials();
        await c.query(`DELETE FROM credential_holders WHERE id = $1 AND institution_id = app_institution_id()`, [id]);
        await this.audit(c, 'holder.deleted', id, {});
        return cur.rows[0].photo_key;
      });
    } catch (e) {
      if (pgCode(e).code === '23503') throw hasCredentials(); // FK RESTRICT is the backstop
      throw e;
    }
  }
}

const hasCredentials = () =>
  new AppError(409, 'HOLDER_HAS_CREDENTIALS', 'This holder has credentials and cannot be deleted');

const tenantScope = (req: FastifyRequest): TenantSession => {
  const s: AuthSession | null = req.session;
  if (!s || s.kind !== 'tenant') throw new AppError(403, 'FORBIDDEN', 'Insufficient role');
  return { kind: 'tenant', userId: s.userId, institutionId: s.institutionId };
};

export interface HolderRoutesOptions {
  db: Db;
  /** Undefined when object storage is not configured: photo upload answers 503, photoUrl is omitted. */
  storage: ObjectStorage | undefined;
  photoMaxBytes: number;
  log: FastifyBaseLogger;
  hashIp?: (ip: string | undefined) => string | undefined;
}

export function registerHolders(app: FastifyInstance, o: HolderRoutesOptions): void {
  const ia = { preHandler: app.requireRole('INSTITUTION_ADMIN') };
  const repo = (req: FastifyRequest) => new HolderRepository(o.db, tenantScope(req), o.hashIp?.(req.ip) ?? null);
  const noStore = (reply: { header: (k: string, v: string) => unknown }) => void reply.header('Cache-Control', 'no-store');

  const withPhotoUrl = async (view: HolderView, key: string | null): Promise<HolderView> => {
    if (!key || !o.storage) return view;
    return { ...view, photoUrl: await o.storage.signedGetUrl(key, PHOTO_URL_TTL_SECONDS) };
  };

  app.get('/holders', ia, async (req, reply) => {
    noStore(reply);
    return repo(req).list(parseListQuery(req.query));
  });

  app.post('/holders', ia, async (req, reply) => {
    noStore(reply);
    const scope = tenantScope(req);
    const input = parseHolderBody(req.body, 'create');
    const view = await repo(req).create(input);
    o.log.info(
      { event: 'holder.created', actorId: scope.userId, institutionId: scope.institutionId, holderId: view.id },
      'holder created',
    );
    return reply.status(201).send(view);
  });

  app.get('/holders/:id', ia, async (req, reply) => {
    noStore(reply);
    const { view, photoKey } = await repo(req).get((req.params as { id: string }).id);
    return withPhotoUrl(view, photoKey);
  });

  app.patch('/holders/:id', ia, async (req, reply) => {
    noStore(reply);
    const scope = tenantScope(req);
    const id = (req.params as { id: string }).id;
    const patch = parseHolderBody(req.body, 'patch');
    const view = await repo(req).update(id, patch);
    o.log.info(
      { event: 'holder.updated', actorId: scope.userId, institutionId: scope.institutionId, holderId: view.id, fields: Object.keys(patch) },
      'holder updated',
    );
    const { photoKey } = await repo(req).get(id);
    return withPhotoUrl(view, photoKey);
  });

  app.delete('/holders/:id', ia, async (req, reply) => {
    noStore(reply);
    const scope = tenantScope(req);
    const id = (req.params as { id: string }).id;
    const photoKey = await repo(req).delete(id);
    if (photoKey && o.storage) {
      await o.storage.delete(photoKey).catch(() => {
        o.log.warn({ event: 'holder.photo_cleanup_failed', institutionId: scope.institutionId }, 'photo not deleted');
      });
    }
    o.log.info(
      { event: 'holder.deleted', actorId: scope.userId, institutionId: scope.institutionId, holderId: id },
      'holder deleted',
    );
    return reply.status(204).send();
  });

  // Multipart is registered only in this encapsulated scope, so no other holder route accepts uploads.
  void app.register(async (sub) => {
    await sub.register(multipart, {
      limits: { fileSize: o.photoMaxBytes, files: 1, fields: 0, parts: 2, headerPairs: 20 },
    });

    sub.post('/holders/:id/photo', ia, async (req, reply) => {
      noStore(reply);
      const scope = tenantScope(req);
      const id = (req.params as { id: string }).id;
      if (!o.storage) throw new AppError(503, 'STORAGE_UNAVAILABLE', 'File storage is not available');
      await repo(req).get(id); // 404 before reading the body when the holder is not ours
      await repo(req).assertActive(); // suspended institution: refuse before reading or storing anything

      const { type, bytes } = await readImageUpload(req, 'Photo');
      // Hash of exactly the bytes that are stored (after stripping), as credential payloads commit to it.
      const sha256 = createHash('sha256').update(bytes).digest('hex');
      // Server-generated, content-addressed key: session institution, holder id (validated uuid), SHA-256 of the bytes.
      const key = `institutions/${scope.institutionId}/holders/${id}/photo/${sha256}.${extensionOf(type)}`;
      try {
        await o.storage.put(key, bytes, type);
      } catch (e) {
        if (!(e instanceof StorageError)) throw e;
        o.log.error({ event: 'holder.photo_store_failed', institutionId: scope.institutionId }, 'photo store failed');
        throw new AppError(503, 'STORAGE_UNAVAILABLE', 'File storage is not available');
      }

      // If this fails the new object is left in place: the key is content-addressed, so it may be the very object
      // the holder or a signed credential already uses (ADR 0016).
      const result = await repo(req).setPhoto(id, key, sha256);
      if (result.previousKey) {
        await o.storage.delete(result.previousKey).catch(() => {
          o.log.warn({ event: 'holder.photo_cleanup_failed', institutionId: scope.institutionId }, 'old photo not deleted');
        });
      }
      o.log.info(
        { event: 'holder.photo_updated', actorId: scope.userId, institutionId: scope.institutionId, holderId: id },
        'holder photo updated',
      );
      return withPhotoUrl(result.view, key);
    });
  });
}
