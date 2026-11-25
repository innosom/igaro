// Read side for credentials, dashboard and audit (T-027, ADR 0018). The institution comes from the session only;
// every query runs in Db.withTenant (RLS) and also filters on app_institution_id(). Foreign, unknown and malformed
// ids are all the same 404. Responses never carry the verification token, the holder token (hash) or the salt: the
// signed payload is therefore not returned whole, only its non-secret parts (attributes, dataHash, signature, kid).
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { AuthSession } from './auth.js';
import { verifyAuditChain } from './audit.js';
import { BAD_TEXT_RE, badRequest } from './credentials.js';
import { isUuid, type Db, type TenantSession } from './db.js';
import { AppError, NotFoundError } from './errors.js';

export const STATUS_FILTERS = ['DRAFT', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'SUPERSEDED', 'EXPIRED'] as const;
export type StatusFilter = (typeof STATUS_FILTERS)[number];
const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;
const MAX_SEARCH = 100;
const TYPE_CODE_RE = /^[A-Z][A-Z0-9_]{1,39}$/;
const CURSOR_RE = /^[A-Za-z0-9_-]{1,120}$/;

/** Effective status. EXPIRED is computed (invariant 4) and only ever replaces ACTIVE (invariant 7 order). */
const EFFECTIVE_STATUS = `(CASE WHEN c.status = 'ACTIVE' AND c.expires_at IS NOT NULL AND c.expires_at <= now()
                                 THEN 'EXPIRED' ELSE c.status::text END)`;

const likeEscape = (s: string): string => s.replace(/[\\%_]/g, (c) => `\\${c}`);
const b64 = (s: string): string => Buffer.from(s, 'utf8').toString('base64url');
const unb64 = (s: string): string => Buffer.from(s, 'base64url').toString('utf8');

function rejectUnknown(q: Record<string, unknown>, known: string[]): void {
  if (Object.keys(q).some((k) => !known.includes(k))) throw badRequest('UNKNOWN_PROPERTY', 'Unknown query parameter');
}
function parseLimit(v: unknown): number {
  if (v === undefined) return DEFAULT_LIMIT;
  if (typeof v !== 'string' || !/^\d{1,9}$/.test(v)) throw badRequest('INVALID_LIMIT', 'Invalid limit');
  const n = Number(v);
  if (n < 1 || n > MAX_LIMIT) throw badRequest('INVALID_LIMIT', `limit must be 1-${MAX_LIMIT}`);
  return n;
}
function parseCursorParam(v: unknown): string | undefined {
  if (v === undefined) return undefined;
  if (typeof v !== 'string' || !CURSOR_RE.test(v)) throw badRequest('INVALID_CURSOR', 'Invalid cursor');
  return v;
}

export interface CredentialListQuery {
  status?: StatusFilter;
  type?: string;
  q?: string;
  limit: number;
  cursor?: { createdAt: string; id: string };
}

export function parseCredentialListQuery(query: unknown): CredentialListQuery {
  const q = (query ?? {}) as Record<string, unknown>;
  rejectUnknown(q, ['status', 'type', 'q', 'limit', 'cursor']);
  const out: CredentialListQuery = { limit: parseLimit(q.limit) };
  if (q.status !== undefined) {
    if (typeof q.status !== 'string' || !(STATUS_FILTERS as readonly string[]).includes(q.status)) {
      throw badRequest('INVALID_STATUS', 'Invalid status');
    }
    out.status = q.status as StatusFilter;
  }
  if (q.type !== undefined) {
    if (typeof q.type !== 'string' || !TYPE_CODE_RE.test(q.type)) throw badRequest('INVALID_TYPE', 'Invalid type');
    out.type = q.type;
  }
  if (q.q !== undefined) {
    if (typeof q.q !== 'string' || q.q.length > MAX_SEARCH || BAD_TEXT_RE.test(q.q)) throw badRequest('INVALID_SEARCH', 'Invalid search');
    const t = q.q.normalize('NFC').trim();
    if (t) out.q = t;
  }
  const cur = parseCursorParam(q.cursor);
  if (cur) {
    const [createdAt, id] = unb64(cur).split('|');
    if (!createdAt || !id || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}$/.test(createdAt) || !isUuid(id)) {
      throw badRequest('INVALID_CURSOR', 'Invalid cursor');
    }
    out.cursor = { createdAt, id };
  }
  return out;
}

export interface AuditListQuery {
  limit: number;
  /** Return entries with seq below this. */
  before?: string;
}

export function parseAuditListQuery(query: unknown): AuditListQuery {
  const q = (query ?? {}) as Record<string, unknown>;
  rejectUnknown(q, ['limit', 'cursor']);
  const out: AuditListQuery = { limit: parseLimit(q.limit) };
  const cur = parseCursorParam(q.cursor);
  if (cur) {
    const s = unb64(cur);
    if (!/^[1-9]\d{0,17}$/.test(s)) throw badRequest('INVALID_CURSOR', 'Invalid cursor');
    out.before = s;
  }
  return out;
}

export interface CredentialSummary {
  id: string;
  credentialNumber: string;
  status: string;
  holder: { id: string; fullName: string };
  type: { code: string; name: string };
  issuedAt: string | null;
  expiresAt: string | null;
  supersededBy: string | null;
  createdAt: string;
}
export interface CredentialDetail extends CredentialSummary {
  /** Stored status; differs from `status` only when the credential is computed EXPIRED. */
  storedStatus: string;
  attributes: Record<string, string>;
  dataHash: string;
  signature: string;
  issuerKeyId: string;
  anchorStatus: string;
  events: { id: string; type: string; payload: Record<string, unknown>; createdAt: string }[];
}

interface Row {
  id: string;
  credential_number: string;
  status: string;
  stored_status: string;
  holder_id: string;
  holder_name: string;
  type_code: string;
  type_name: string;
  issued_at: Date | null;
  expires_at: Date | null;
  superseded_by: string | null;
  created_at: Date;
  created_cursor: string;
}
const iso = (d: Date | null): string | null => (d ? d.toISOString() : null);
const toSummary = (r: Row): CredentialSummary => ({
  id: r.id,
  credentialNumber: r.credential_number,
  status: r.status,
  holder: { id: r.holder_id, fullName: r.holder_name },
  type: { code: r.type_code, name: r.type_name },
  issuedAt: iso(r.issued_at),
  expiresAt: iso(r.expires_at),
  supersededBy: r.superseded_by,
  createdAt: r.created_at.toISOString(),
});

const SELECT_SUMMARY = `
  SELECT c.id, c.credential_number, ${EFFECTIVE_STATUS} AS status, c.status::text AS stored_status,
         c.holder_id, h.full_name AS holder_name, t.code AS type_code, t.name AS type_name,
         c.issued_at, c.expires_at, c.superseded_by, c.created_at,
         to_char(c.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US') AS created_cursor
    FROM credentials c
    JOIN credential_holders h ON h.id = c.holder_id AND h.institution_id = c.institution_id
    JOIN credential_types t ON t.id = c.type_id AND t.institution_id = c.institution_id`;

export class CredentialQueryService {
  constructor(private readonly db: Db) {}

  async list(s: TenantSession, q: CredentialListQuery): Promise<{ items: CredentialSummary[]; nextCursor: string | null }> {
    const where = ['c.institution_id = app_institution_id()'];
    const params: unknown[] = [];
    const p = (v: unknown): string => {
      params.push(v);
      return `$${params.length}`;
    };
    if (q.status) where.push(`${EFFECTIVE_STATUS} = ${p(q.status)}`);
    if (q.type) where.push(`t.code = ${p(q.type)}`);
    if (q.q) {
      const like = p(`%${likeEscape(q.q)}%`);
      where.push(`(c.credential_number ILIKE ${like} ESCAPE '\\' OR h.full_name ILIKE ${like} ESCAPE '\\')`);
    }
    if (q.cursor) where.push(`(c.created_at, c.id) < (${p(q.cursor.createdAt)}::timestamp AT TIME ZONE 'UTC', ${p(q.cursor.id)}::uuid)`);
    const limit = p(q.limit + 1);
    return this.db.withTenant(s, async (c) => {
      const r = await c.query<Row>(
        `${SELECT_SUMMARY} WHERE ${where.join(' AND ')} ORDER BY c.created_at DESC, c.id DESC LIMIT ${limit}`,
        params,
      );
      const page = r.rows.slice(0, q.limit);
      const last = page[page.length - 1];
      const nextCursor = r.rows.length > q.limit && last ? b64(`${last.created_cursor}|${last.id}`) : null;
      return { items: page.map(toSummary), nextCursor };
    });
  }

  async get(s: TenantSession, id: string): Promise<CredentialDetail> {
    if (!isUuid(id)) throw new NotFoundError();
    return this.db.withTenant(s, async (c) => {
      const r = await c.query<Row & { payload: { attributes?: Record<string, string> }; data_hash: string; signature: string; issuer_kid: string; anchor_status: string }>(
        `SELECT x.*, c.payload, c.data_hash, c.signature, c.issuer_kid, c.anchor_status::text AS anchor_status
           FROM (${SELECT_SUMMARY} WHERE c.id = $1 AND c.institution_id = app_institution_id()) x
           JOIN credentials c ON c.id = x.id`,
        [id],
      );
      const row = r.rows[0];
      if (!row) throw new NotFoundError();
      const ev = await c.query<{ id: string; type: string; payload: Record<string, unknown>; created_at: Date }>(
        `SELECT id, type::text AS type, payload, created_at FROM credential_events
          WHERE credential_id = $1 AND institution_id = app_institution_id() ORDER BY seq, created_at`,
        [id],
      );
      return {
        ...toSummary(row),
        storedStatus: row.stored_status,
        attributes: { ...(row.payload.attributes ?? {}) },
        dataHash: row.data_hash,
        signature: row.signature,
        issuerKeyId: row.issuer_kid,
        anchorStatus: row.anchor_status,
        events: ev.rows.map((e) => ({ id: e.id, type: e.type, payload: e.payload, createdAt: e.created_at.toISOString() })),
      };
    });
  }

  async stats(s: TenantSession): Promise<{ total: number; byStatus: Record<StatusFilter, number> }> {
    return this.db.withTenant(s, async (c) => {
      const r = await c.query<{ status: StatusFilter; n: number }>(
        `SELECT ${EFFECTIVE_STATUS} AS status, count(*)::int AS n FROM credentials c
          WHERE c.institution_id = app_institution_id() GROUP BY 1`,
      );
      const byStatus = Object.fromEntries(STATUS_FILTERS.map((k) => [k, 0])) as Record<StatusFilter, number>;
      let total = 0;
      for (const x of r.rows) {
        byStatus[x.status] = x.n;
        total += x.n;
      }
      return { total, byStatus };
    });
  }

  async auditList(s: TenantSession, q: AuditListQuery) {
    return this.db.withTenant(s, async (c) => {
      const params: unknown[] = [];
      let cursorSql = '';
      if (q.before) {
        params.push(q.before);
        cursorSql = `AND a.seq < $1::bigint`;
      }
      params.push(q.limit + 1);
      const r = await c.query<{
        id: string; seq: string; actor_id: string | null; action: string; target_type: string | null;
        target_id: string | null; metadata: Record<string, unknown>; created_at: Date; prev_hash: string; entry_hash: string;
      }>(
        `SELECT a.id, a.seq::text AS seq, a.actor_id, a.action, a.target_type, a.target_id, a.metadata, a.created_at,
                a.prev_hash, a.entry_hash
           FROM audit_logs a WHERE a.institution_id = app_institution_id() ${cursorSql}
          ORDER BY a.seq DESC LIMIT $${params.length}`,
        params,
      );
      const page = r.rows.slice(0, q.limit);
      const last = page[page.length - 1];
      return {
        items: page.map((a) => ({
          id: a.id, seq: a.seq, actorId: a.actor_id, action: a.action, targetType: a.target_type, targetId: a.target_id,
          metadata: a.metadata, createdAt: a.created_at.toISOString(), prevHash: a.prev_hash, entryHash: a.entry_hash,
        })),
        nextCursor: r.rows.length > q.limit && last ? b64(last.seq) : null,
      };
    });
  }

  /** Recompute the whole chain, then compare it with the signed daily heads (if any exist). */
  async verifyChain(s: TenantSession) {
    return this.db.withTenant(s, async (c) => {
      const chain = await verifyAuditChain(c, s.institutionId);
      const heads = (
        await c.query<{ day: string; head_hash: string }>(
          `SELECT day::text AS day, head_hash FROM audit_head_hashes WHERE institution_id = app_institution_id() ORDER BY day`,
        )
      ).rows;
      // A signed head must still be an entry hash of the chain. A rewritten or recomputed chain loses it.
      const found = new Set<string>();
      if (heads.length > 0) {
        const f = await c.query<{ entry_hash: string }>(
          `SELECT entry_hash FROM audit_logs WHERE institution_id = app_institution_id() AND entry_hash = ANY($1::text[])`,
          [heads.map((h) => h.head_hash)],
        );
        for (const x of f.rows) found.add(x.entry_hash);
      }
      const mismatchedDays = heads.filter((h) => !found.has(h.head_hash)).map((h) => h.day);
      const headsRecorded = heads.length > 0 && mismatchedDays.length === 0;
      return {
        valid: chain.ok && mismatchedDays.length === 0,
        entries: chain.count,
        ...(chain.ok ? { head: chain.head } : { brokenAtSeq: chain.brokenAtSeq, reason: chain.reason }),
        headsRecorded,
        signedHeads: { checked: heads.length, matched: heads.length - mismatchedDays.length, mismatchedDays },
      };
    });
  }
}

const tenantScope = (req: FastifyRequest): TenantSession => {
  const s: AuthSession | null = req.session;
  if (!s || s.kind !== 'tenant') throw new AppError(403, 'FORBIDDEN', 'Insufficient role');
  return { kind: 'tenant', userId: s.userId, institutionId: s.institutionId };
};

export function registerCredentialQueries(app: FastifyInstance, svc: CredentialQueryService): void {
  const ia = { preHandler: app.requireRole('INSTITUTION_ADMIN') };
  app.get('/credentials', ia, async (req, reply) => {
    void reply.header('Cache-Control', 'no-store');
    return svc.list(tenantScope(req), parseCredentialListQuery(req.query));
  });
  app.get<{ Params: { id: string } }>('/credentials/:id', ia, async (req, reply) => {
    void reply.header('Cache-Control', 'no-store');
    return svc.get(tenantScope(req), req.params.id);
  });
  app.get('/dashboard/stats', ia, async (req, reply) => {
    void reply.header('Cache-Control', 'no-store');
    return svc.stats(tenantScope(req));
  });
  app.get('/audit-logs', ia, async (req, reply) => {
    void reply.header('Cache-Control', 'no-store');
    return svc.auditList(tenantScope(req), parseAuditListQuery(req.query));
  });
  app.get('/audit-logs/verify-chain', ia, async (req, reply) => {
    void reply.header('Cache-Control', 'no-store');
    return svc.verifyChain(tenantScope(req));
  });
}
