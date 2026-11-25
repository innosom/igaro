// Own-institution profile (T-016): branding, public-field settings and the logo. Institution Admin only.
// The institution id comes from the authenticated session, never from the request. Every query runs in
// Db.withTenant (RLS sets app.institution_id) and also filters on app_institution_id().
import { randomUUID } from 'node:crypto';
import multipart from '@fastify/multipart';
import type { FastifyBaseLogger, FastifyInstance, FastifyRequest } from 'fastify';
import type { AuthSession } from './auth.js';
import type { Db, TenantSession } from './db.js';
import { AppError, NotFoundError } from './errors.js';
import { extensionOf, sniffImage, stripMetadata } from './image.js';
import { StorageError, type ObjectStorage } from './storage.js';

/**
 * Optional holder fields the public verification page may show. Name and status always appear and are
 * not configurable (white paper section on verification). ADR 0008.
 */
export const PUBLIC_FIELDS = ['photo', 'idNumber', 'attributes'] as const;
export type PublicField = (typeof PUBLIC_FIELDS)[number];

export const DEFAULT_LOGO_MAX_BYTES = 1024 * 1024;
const MAX_CARD_TITLE = 100;
const COLOR_RE = /^#[0-9a-fA-F]{6}$/;

export interface InstitutionProfile {
  id: string;
  name: string;
  slug: string;
  status: 'ACTIVE' | 'SUSPENDED';
  cardTitle: string | null;
  primaryColor: string;
  secondaryColor: string;
  publicFields: PublicField[];
  /** True when a logo is stored. The storage key and any URL are never returned (private bucket). */
  hasLogo: boolean;
  updatedAt: string;
}

interface Row {
  id: string;
  name: string;
  slug: string;
  status: 'ACTIVE' | 'SUSPENDED';
  card_title: string | null;
  primary_color: string;
  secondary_color: string;
  public_fields: unknown;
  logo_key: string | null;
  updated_at: Date;
}

const COLS = `id, name, slug, status, card_title, primary_color, secondary_color, public_fields,
  logo_key, updated_at`;

const toProfile = (r: Row): InstitutionProfile => ({
  id: r.id,
  name: r.name,
  slug: r.slug,
  status: r.status,
  cardTitle: r.card_title,
  primaryColor: r.primary_color,
  secondaryColor: r.secondary_color,
  publicFields: (Array.isArray(r.public_fields) ? r.public_fields : []).filter(
    (f): f is PublicField => (PUBLIC_FIELDS as readonly unknown[]).includes(f),
  ),
  hasLogo: r.logo_key !== null,
  updatedAt: r.updated_at.toISOString(),
});

export interface ProfilePatch {
  cardTitle?: string | null;
  primaryColor?: string;
  secondaryColor?: string;
  publicFields?: PublicField[];
}

const badRequest = (code: string, message: string) => new AppError(400, code, message);

/** Validate a PATCH body. Unknown properties are rejected; nothing from the body is echoed back. */
export function parseProfilePatch(body: unknown): ProfilePatch {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw badRequest('BAD_REQUEST', 'Invalid request');
  }
  const b = body as Record<string, unknown>;
  const known = new Set(['cardTitle', 'primaryColor', 'secondaryColor', 'publicFields']);
  if (Object.keys(b).some((k) => !known.has(k))) {
    throw badRequest('UNKNOWN_PROPERTY', 'Unknown property');
  }
  const out: ProfilePatch = {};
  if ('cardTitle' in b) {
    const v = b.cardTitle;
    if (v === null) out.cardTitle = null;
    else if (typeof v === 'string' && v.trim().length >= 1 && v.trim().length <= MAX_CARD_TITLE) {
      // eslint-disable-next-line no-control-regex
      if (/[\u0000-\u001f\u007f]/.test(v)) throw badRequest('INVALID_CARD_TITLE', 'Invalid card title');
      out.cardTitle = v.trim();
    } else throw badRequest('INVALID_CARD_TITLE', 'Card title must be 1-100 characters or null');
  }
  for (const k of ['primaryColor', 'secondaryColor'] as const) {
    if (k in b) {
      const v = b[k];
      if (typeof v !== 'string' || !COLOR_RE.test(v)) {
        throw badRequest('INVALID_COLOR', 'Colours must be #rrggbb');
      }
      out[k] = v.toLowerCase();
    }
  }
  if ('publicFields' in b) {
    const v = b.publicFields;
    if (!Array.isArray(v) || v.length > 50) throw badRequest('INVALID_PUBLIC_FIELDS', 'Invalid publicFields');
    const seen = new Set<PublicField>();
    for (const f of v) {
      if (typeof f !== 'string' || !(PUBLIC_FIELDS as readonly string[]).includes(f)) {
        throw badRequest('INVALID_PUBLIC_FIELDS', 'Unknown public field');
      }
      seen.add(f as PublicField);
    }
    out.publicFields = PUBLIC_FIELDS.filter((f) => seen.has(f)); // deduped, canonical order
  }
  if (Object.keys(out).length === 0) throw badRequest('BAD_REQUEST', 'Nothing to update');
  return out;
}

/** Request-scoped repository: constructed from the session, the institution is never a parameter. */
export class InstitutionProfileRepository {
  constructor(
    private readonly db: Db,
    private readonly session: TenantSession,
  ) {}

  async get(): Promise<InstitutionProfile> {
    return this.db.withTenant(this.session, async (c) => {
      const r = await c.query<Row>(`SELECT ${COLS} FROM institutions WHERE id = app_institution_id()`);
      const row = r.rows[0];
      if (!row) throw new NotFoundError();
      return toProfile(row);
    });
  }

  async update(patch: ProfilePatch): Promise<InstitutionProfile> {
    const sets: string[] = [];
    const params: unknown[] = [];
    const add = (col: string, v: unknown) => {
      params.push(v);
      sets.push(`${col} = $${params.length}`);
    };
    if (patch.cardTitle !== undefined) add('card_title', patch.cardTitle);
    if (patch.primaryColor !== undefined) add('primary_color', patch.primaryColor);
    if (patch.secondaryColor !== undefined) add('secondary_color', patch.secondaryColor);
    if (patch.publicFields !== undefined) add('public_fields', JSON.stringify(patch.publicFields));
    return this.db.withTenant(this.session, async (c) => {
      const r = await c.query<Row>(
        `UPDATE institutions SET ${sets.join(', ')}, updated_at = now()
          WHERE id = app_institution_id() RETURNING ${COLS}`,
        params,
      );
      const row = r.rows[0];
      if (!row) throw new NotFoundError();
      return toProfile(row);
    });
  }

  /** Point the institution at a new logo object; returns the previous key (to delete after commit). */
  async setLogoKey(key: string): Promise<{ profile: InstitutionProfile; previousKey: string | null }> {
    return this.db.withTenant(this.session, async (c) => {
      const cur = await c.query<{ logo_key: string | null }>(
        `SELECT logo_key FROM institutions WHERE id = app_institution_id() FOR UPDATE`,
      );
      if (!cur.rows[0]) throw new NotFoundError();
      const r = await c.query<Row>(
        `UPDATE institutions SET logo_key = $1, updated_at = now()
          WHERE id = app_institution_id() RETURNING ${COLS}`,
        [key],
      );
      return { profile: toProfile(r.rows[0]!), previousKey: cur.rows[0].logo_key };
    });
  }
}

const tenantScope = (req: FastifyRequest): TenantSession => {
  const s: AuthSession | null = req.session;
  if (!s || s.kind !== 'tenant') throw new AppError(403, 'FORBIDDEN', 'Insufficient role');
  return { kind: 'tenant', userId: s.userId, institutionId: s.institutionId };
};

export interface ProfileRoutesOptions {
  db: Db;
  /** Undefined when object storage is not configured: logo upload answers 503. */
  storage: ObjectStorage | undefined;
  logoMaxBytes: number;
  log: FastifyBaseLogger;
}

export function registerInstitutionProfile(app: FastifyInstance, o: ProfileRoutesOptions): void {
  const ia = { preHandler: app.requireRole('INSTITUTION_ADMIN') };
  const repo = (req: FastifyRequest) => new InstitutionProfileRepository(o.db, tenantScope(req));

  app.get('/institution', ia, async (req, reply) => {
    void reply.header('Cache-Control', 'no-store');
    return repo(req).get();
  });

  app.patch('/institution', ia, async (req, reply) => {
    void reply.header('Cache-Control', 'no-store');
    const patch = parseProfilePatch(req.body);
    const scope = tenantScope(req);
    const out = await repo(req).update(patch);
    // TODO(T-024): audit_logs entry in the same transaction. Until then: field names only, no values.
    o.log.info(
      { event: 'institution.updated', actorId: scope.userId, institutionId: scope.institutionId, fields: Object.keys(patch) },
      'institution profile updated',
    );
    return out;
  });

  // Multipart is registered only in this encapsulated scope, so no other route accepts uploads.
  void app.register(async (sub) => {
    await sub.register(multipart, {
      limits: { fileSize: o.logoMaxBytes, files: 1, fields: 0, parts: 2, headerPairs: 20 },
    });

    sub.post('/institution/logo', ia, async (req, reply) => {
      void reply.header('Cache-Control', 'no-store');
      const scope = tenantScope(req);
      if (!o.storage) throw new AppError(503, 'STORAGE_UNAVAILABLE', 'File storage is not available');
      if (!req.isMultipart()) throw new AppError(415, 'UNSUPPORTED_MEDIA_TYPE', 'Expected multipart/form-data');

      let raw: Buffer;
      try {
        const part = await req.file();
        if (!part || part.fieldname !== 'file') throw badRequest('BAD_REQUEST', 'Expected one file field named "file"');
        raw = await part.toBuffer();
        if (part.file.truncated) throw new AppError(413, 'PAYLOAD_TOO_LARGE', 'Logo is too large');
      } catch (e) {
        if (e instanceof AppError) throw e;
        const code = (e as { code?: string }).code;
        if (code === 'FST_REQ_FILE_TOO_LARGE') {
          throw new AppError(413, 'PAYLOAD_TOO_LARGE', 'Logo is too large');
        }
        throw badRequest('BAD_REQUEST', 'Invalid upload');
      }
      if (raw.length === 0) throw badRequest('BAD_REQUEST', 'Empty file');

      // The type comes from the bytes, never from the client's content-type or file name.
      const type = sniffImage(raw);
      if (!type) throw new AppError(415, 'UNSUPPORTED_IMAGE_TYPE', 'Logo must be a PNG or JPEG image');
      const clean = stripMetadata(raw, type);
      if (!clean) throw badRequest('INVALID_IMAGE', 'The image file is damaged');

      // Server-generated key; the only variable parts are the session's institution id and a random UUID.
      const key = `institutions/${scope.institutionId}/logo/${randomUUID()}.${extensionOf(type)}`;
      try {
        await o.storage.put(key, clean, type);
      } catch (e) {
        if (!(e instanceof StorageError)) throw e;
        o.log.error({ event: 'logo.store_failed', institutionId: scope.institutionId }, 'logo store failed');
        throw new AppError(503, 'STORAGE_UNAVAILABLE', 'File storage is not available');
      }

      let result: Awaited<ReturnType<InstitutionProfileRepository['setLogoKey']>>;
      try {
        result = await repo(req).setLogoKey(key);
      } catch (e) {
        await o.storage.delete(key).catch(() => undefined);
        throw e;
      }
      if (result.previousKey) {
        await o.storage.delete(result.previousKey).catch(() => {
          o.log.warn({ event: 'logo.cleanup_failed', institutionId: scope.institutionId }, 'old logo not deleted');
        });
      }
      o.log.info(
        { event: 'institution.logo_updated', actorId: scope.userId, institutionId: scope.institutionId },
        'institution logo updated',
      );
      return result.profile;
    });
  });
}
