// Credential types (T-019): per-institution configuration of what a credential contains. Institution Admin only.
// The institution id comes from the session, never the request. Queries run in Db.withTenant (RLS) and also filter on
// app_institution_id(). Another tenant's type id is indistinguishable from an unknown one: 404.
// `code` and `kind` are immutable (the DB grants UPDATE only on name, attribute_schema, validity_days). Changing the
// attribute list never touches already signed credentials: their payload carries its own attributes.
import { randomUUID } from 'node:crypto';
import type { FastifyBaseLogger, FastifyInstance, FastifyRequest } from 'fastify';
import type { AuthSession } from './auth.js';
import { isUuid, type Db, type TenantSession } from './db.js';
import { AppError, NotFoundError } from './errors.js';

export type CredentialKind = 'ID_CARD' | 'CERTIFICATE';
export type AttributeType = 'string' | 'date' | 'number';

export interface AttributeDef {
  key: string;
  label: string;
  type: AttributeType;
  required: boolean;
}

export interface CredentialTypeView {
  id: string;
  code: string;
  name: string;
  kind: CredentialKind;
  attributes: AttributeDef[];
  defaultValidityDays: number | null;
  credentialCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface TypeTemplate {
  code: string;
  name: string;
  kind: CredentialKind;
  attributes: AttributeDef[];
  defaultValidityDays: number | null;
}

/** Built-in templates (same shape as the seed data). Using one creates an ordinary, editable type. */
export const TYPE_TEMPLATES: readonly TypeTemplate[] = [
  {
    code: 'STUDENT_ID',
    name: 'Student/Staff ID Card',
    kind: 'ID_CARD',
    defaultValidityDays: 365,
    attributes: [
      { key: 'program', label: 'Programme', type: 'string', required: true },
      { key: 'faculty', label: 'Faculty', type: 'string', required: false },
      { key: 'yearOfStudy', label: 'Year of study', type: 'number', required: false },
    ],
  },
  {
    code: 'CERTIFICATE',
    name: 'Certificate',
    kind: 'CERTIFICATE',
    defaultValidityDays: null,
    attributes: [
      { key: 'title', label: 'Certificate title', type: 'string', required: true },
      { key: 'program', label: 'Programme', type: 'string', required: true },
      { key: 'grade', label: 'Grade or classification', type: 'string', required: false },
      { key: 'awardDate', label: 'Award date', type: 'date', required: true },
    ],
  },
];

const MAX_ATTRIBUTES = 30;
const MAX_NAME = 100;
const MAX_LABEL = 100;
const MAX_VALIDITY_DAYS = 36_500;
const CODE_RE = /^[A-Z][A-Z0-9_]{1,39}$/;
const KEY_RE = /^[a-z][A-Za-z0-9]{0,49}$/;
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f]|\p{Cf}/u;
// Names that exist on Object.prototype: refused as attribute keys so later plain-object handling cannot be fooled.
const RESERVED_KEYS = new Set(['constructor', 'hasOwnProperty', 'isPrototypeOf', 'propertyIsEnumerable', 'toString', 'toLocaleString', 'valueOf']);

const badRequest = (code: string, message: string) => new AppError(400, code, message);

interface Row {
  id: string;
  code: string;
  name: string;
  kind: CredentialKind;
  attribute_schema: unknown;
  validity_days: number | null;
  credential_count: number;
  created_at: Date;
  updated_at: Date;
}

const SELECT = `SELECT t.id, t.code, t.name, t.kind, t.attribute_schema, t.validity_days,
    (SELECT count(*)::int FROM credentials c
      WHERE c.type_id = t.id AND c.institution_id = app_institution_id()) AS credential_count,
    t.created_at, t.updated_at
  FROM credential_types t`;

const toView = (r: Row): CredentialTypeView => ({
  id: r.id,
  code: r.code,
  name: r.name,
  kind: r.kind,
  attributes: Array.isArray(r.attribute_schema) ? (r.attribute_schema as AttributeDef[]) : [],
  defaultValidityDays: r.validity_days,
  credentialCount: r.credential_count,
  createdAt: r.created_at.toISOString(),
  updatedAt: r.updated_at.toISOString(),
});

function parseName(v: unknown): string {
  if (typeof v !== 'string') throw badRequest('INVALID_NAME', 'Name is required');
  const t = v.trim();
  if (t.length < 1 || t.length > MAX_NAME || CONTROL_RE.test(t)) throw badRequest('INVALID_NAME', 'Name must be 1-100 characters');
  return t;
}

function parseValidity(v: unknown): number | null {
  if (v === null) return null;
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 1 || v > MAX_VALIDITY_DAYS) {
    throw badRequest('INVALID_VALIDITY', 'defaultValidityDays must be an integer from 1 to 36500, or null');
  }
  return v;
}

export function parseAttributes(v: unknown): AttributeDef[] {
  if (!Array.isArray(v) || v.length > MAX_ATTRIBUTES) {
    throw badRequest('INVALID_ATTRIBUTES', `attributes must be a list of at most ${MAX_ATTRIBUTES} items`);
  }
  const seen = new Set<string>();
  return v.map((raw) => {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw badRequest('INVALID_ATTRIBUTES', 'Invalid attribute');
    const a = raw as Record<string, unknown>;
    if (Object.keys(a).some((k) => !['key', 'label', 'type', 'required'].includes(k))) {
      throw badRequest('INVALID_ATTRIBUTES', 'Unknown attribute property');
    }
    if (typeof a.key !== 'string' || !KEY_RE.test(a.key)) {
      throw badRequest('INVALID_ATTRIBUTES', 'Attribute key must be camelCase letters and digits, up to 50 characters');
    }
    if (RESERVED_KEYS.has(a.key)) throw badRequest('INVALID_ATTRIBUTES', 'Attribute key is reserved');
    if (seen.has(a.key)) throw badRequest('INVALID_ATTRIBUTES', 'Duplicate attribute key');
    seen.add(a.key);
    if (typeof a.label !== 'string' || a.label.trim().length < 1 || a.label.trim().length > MAX_LABEL || CONTROL_RE.test(a.label)) {
      throw badRequest('INVALID_ATTRIBUTES', 'Attribute label must be 1-100 characters');
    }
    if (a.type !== 'string' && a.type !== 'date' && a.type !== 'number') {
      throw badRequest('INVALID_ATTRIBUTES', 'Attribute type must be string, date or number');
    }
    if (typeof a.required !== 'boolean') throw badRequest('INVALID_ATTRIBUTES', 'Attribute required must be true or false');
    return { key: a.key, label: a.label.trim(), type: a.type, required: a.required };
  });
}

export interface TypeInput {
  code?: string;
  name?: string;
  kind?: CredentialKind;
  attributes?: AttributeDef[];
  defaultValidityDays?: number | null;
}

/** Validate a create/patch body. Unknown properties are rejected. Create accepts `template` to start from a built-in. */
export function parseTypeBody(body: unknown, mode: 'create' | 'patch'): TypeInput {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw badRequest('BAD_REQUEST', 'Invalid request');
  const b = body as Record<string, unknown>;
  const known = new Set(['name', 'attributes', 'defaultValidityDays', ...(mode === 'create' ? ['code', 'kind', 'template'] : [])]);
  if (Object.keys(b).some((k) => !known.has(k))) throw badRequest('UNKNOWN_PROPERTY', 'Unknown property');
  const out: TypeInput = {};

  if (mode === 'create') {
    let base: TypeTemplate | undefined;
    if ('template' in b) {
      base = TYPE_TEMPLATES.find((t) => t.code === b.template);
      if (!base) throw badRequest('UNKNOWN_TEMPLATE', 'Unknown template');
    }
    const code = 'code' in b ? b.code : base?.code;
    if (typeof code !== 'string' || !CODE_RE.test(code)) {
      throw badRequest('INVALID_CODE', 'Code must be 2-40 characters: capital letters, digits and underscores, starting with a letter');
    }
    out.code = code;
    const kind = 'kind' in b ? b.kind : base?.kind;
    if (kind !== 'ID_CARD' && kind !== 'CERTIFICATE') throw badRequest('INVALID_KIND', 'kind must be ID_CARD or CERTIFICATE');
    out.kind = kind;
    out.name = parseName('name' in b ? b.name : base?.name);
    out.attributes = parseAttributes('attributes' in b ? b.attributes : (base?.attributes ?? []));
    out.defaultValidityDays = parseValidity('defaultValidityDays' in b ? b.defaultValidityDays : (base?.defaultValidityDays ?? null));
    return out;
  }
  if ('name' in b) out.name = parseName(b.name);
  if ('attributes' in b) out.attributes = parseAttributes(b.attributes);
  if ('defaultValidityDays' in b) out.defaultValidityDays = parseValidity(b.defaultValidityDays);
  if (Object.keys(out).length === 0) throw badRequest('BAD_REQUEST', 'Nothing to update');
  return out;
}

const pgCode = (e: unknown): { code?: string } => (e && typeof e === 'object' ? (e as { code?: string }) : {});
const duplicateCode = () => new AppError(409, 'DUPLICATE_TYPE_CODE', 'A credential type with this code already exists');
const inUse = () => new AppError(409, 'TYPE_HAS_CREDENTIALS', 'This credential type has credentials and cannot be deleted');

/** Request-scoped repository: constructed from the session, the institution is never a parameter. */
export class CredentialTypeRepository {
  constructor(
    private readonly db: Db,
    private readonly session: TenantSession,
  ) {}

  async list(): Promise<CredentialTypeView[]> {
    return this.db.withTenant(this.session, async (c) => {
      const r = await c.query<Row>(`${SELECT} WHERE t.institution_id = app_institution_id() ORDER BY t.code`);
      return r.rows.map(toView);
    });
  }

  async get(id: string): Promise<CredentialTypeView> {
    if (!isUuid(id)) throw new NotFoundError();
    return this.db.withTenant(this.session, async (c) => {
      const r = await c.query<Row>(`${SELECT} WHERE t.id = $1 AND t.institution_id = app_institution_id()`, [id]);
      if (!r.rows[0]) throw new NotFoundError();
      return toView(r.rows[0]);
    });
  }

  async create(input: Required<TypeInput>): Promise<CredentialTypeView> {
    const id = randomUUID();
    try {
      return await this.db.withTenant(this.session, async (c) => {
        await c.query(
          `INSERT INTO credential_types (id, institution_id, code, name, kind, attribute_schema, validity_days, updated_at)
           VALUES ($1, app_institution_id(), $2, $3, $4::text::credential_kind, $5::jsonb, $6, now())`,
          [id, input.code, input.name, input.kind, JSON.stringify(input.attributes), input.defaultValidityDays],
        );
        const r = await c.query<Row>(`${SELECT} WHERE t.id = $1 AND t.institution_id = app_institution_id()`, [id]);
        return toView(r.rows[0]!);
      });
    } catch (e) {
      if (pgCode(e).code === '23505') throw duplicateCode();
      throw e;
    }
  }

  async update(id: string, patch: TypeInput): Promise<CredentialTypeView> {
    if (!isUuid(id)) throw new NotFoundError();
    const sets: string[] = [];
    const params: unknown[] = [id];
    const add = (col: string, v: unknown, cast = '') => {
      params.push(v);
      sets.push(`${col} = $${params.length}${cast}`);
    };
    if (patch.name !== undefined) add('name', patch.name);
    if (patch.attributes !== undefined) add('attribute_schema', JSON.stringify(patch.attributes), '::jsonb');
    if (patch.defaultValidityDays !== undefined) add('validity_days', patch.defaultValidityDays);
    return this.db.withTenant(this.session, async (c) => {
      const u = await c.query(
        `UPDATE credential_types SET ${sets.join(', ')}, updated_at = now()
          WHERE id = $1 AND institution_id = app_institution_id()`,
        params,
      );
      if (u.rowCount === 0) throw new NotFoundError();
      const r = await c.query<Row>(`${SELECT} WHERE t.id = $1 AND t.institution_id = app_institution_id()`, [id]);
      return toView(r.rows[0]!);
    });
  }

  async delete(id: string): Promise<void> {
    if (!isUuid(id)) throw new NotFoundError();
    try {
      await this.db.withTenant(this.session, async (c) => {
        const cur = await c.query(
          `SELECT 1 FROM credential_types WHERE id = $1 AND institution_id = app_institution_id() FOR UPDATE`,
          [id],
        );
        if (cur.rowCount === 0) throw new NotFoundError();
        const n = await c.query<{ n: number }>(
          `SELECT count(*)::int AS n FROM credentials WHERE type_id = $1 AND institution_id = app_institution_id()`,
          [id],
        );
        if (n.rows[0]!.n > 0) throw inUse();
        await c.query(`DELETE FROM credential_types WHERE id = $1 AND institution_id = app_institution_id()`, [id]);
      });
    } catch (e) {
      if (pgCode(e).code === '23503') throw inUse(); // FK RESTRICT is the backstop
      throw e;
    }
  }
}

const tenantScope = (req: FastifyRequest): TenantSession => {
  const s: AuthSession | null = req.session;
  if (!s || s.kind !== 'tenant') throw new AppError(403, 'FORBIDDEN', 'Insufficient role');
  return { kind: 'tenant', userId: s.userId, institutionId: s.institutionId };
};

export function registerCredentialTypes(app: FastifyInstance, o: { db: Db; log: FastifyBaseLogger }): void {
  const ia = { preHandler: app.requireRole('INSTITUTION_ADMIN') };
  const repo = (req: FastifyRequest) => new CredentialTypeRepository(o.db, tenantScope(req));
  const noStore = (reply: { header: (k: string, v: string) => unknown }) => void reply.header('Cache-Control', 'no-store');
  // TODO(T-024): audit entries for create/update/delete in the same transaction.
  const logEvent = (req: FastifyRequest, event: string, typeId: string, extra: object = {}) => {
    const s = tenantScope(req);
    o.log.info({ event, actorId: s.userId, institutionId: s.institutionId, credentialTypeId: typeId, ...extra }, event);
  };

  app.get('/credential-types', ia, async (req, reply) => {
    noStore(reply);
    return { items: await repo(req).list() };
  });

  app.get('/credential-types/templates', ia, async (_req, reply) => {
    noStore(reply);
    return { items: TYPE_TEMPLATES };
  });

  app.post('/credential-types', ia, async (req, reply) => {
    noStore(reply);
    const input = parseTypeBody(req.body, 'create') as Required<TypeInput>;
    const view = await repo(req).create(input);
    logEvent(req, 'credential_type.created', view.id, { code: view.code });
    return reply.status(201).send(view);
  });

  app.get('/credential-types/:id', ia, async (req, reply) => {
    noStore(reply);
    return repo(req).get((req.params as { id: string }).id);
  });

  app.patch('/credential-types/:id', ia, async (req, reply) => {
    noStore(reply);
    const patch = parseTypeBody(req.body, 'patch');
    const view = await repo(req).update((req.params as { id: string }).id, patch);
    logEvent(req, 'credential_type.updated', view.id, { fields: Object.keys(patch) });
    return view;
  });

  app.delete('/credential-types/:id', ia, async (req, reply) => {
    noStore(reply);
    const id = (req.params as { id: string }).id;
    await repo(req).delete(id);
    logEvent(req, 'credential_type.deleted', id);
    return reply.status(204).send();
  });
}
