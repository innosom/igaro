// Credential issuance (T-025). One DB transaction: validate -> ids and tokens -> payload with fresh salt and photo
// hash -> hash and sign with the institution's ACTIVE key -> ACTIVE credential + ISSUED event (outbox) + audit entry.
// The institution comes from the session only. Every query runs in Db.withTenant (RLS) and also filters on
// app_institution_id(). Another tenant's holder or type is indistinguishable from an unknown one: 404.
//
// Hashing, canonicalisation and signing come from @igaro/core (never reimplemented here). The private key is
// unwrapped with the master key only inside the signing step and is never stored, returned or logged.
// Tokens: the 128-bit verification token is stored in clear (QR/card need it); the holder token is stored only as
// SHA-256 (ADR 0002) and its plaintext appears once, in the 201 response (the delivery job gets it later, T-040).
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { FastifyBaseLogger, FastifyInstance, FastifyRequest } from 'fastify';
import type { PoolClient } from 'pg';
import {
  CREDENTIAL_SCHEMA_VERSION,
  generateSalt,
  signCredential,
  unwrapPrivateKey,
  verifyDataHashSignature,
  type CredentialPayloadV1,
} from '@igaro/core';
import { appendAudit } from './audit.js';
import type { AuthSession } from './auth.js';
import { isUuid, type Db, type TenantSession } from './db.js';
import { AppError, NotFoundError } from './errors.js';
import { parseAttributes, type AttributeDef } from './credential-types.js';

const MAX_VALUE = 500;
const MAX_ATTR_KEYS = 30;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const NUMBER_RE = /^-?(?:0|[1-9]\d{0,14})(?:\.\d{1,10})?$/;
// C0/C1 controls, bidi and other format characters, lone surrogates (JSONB and I-JSON cannot hold them).
// eslint-disable-next-line no-control-regex
const BAD_TEXT_RE = /[\u0000-\u001f\u007f-\u009f]|\p{Cf}|[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/u;

const badRequest = (code: string, message: string) => new AppError(400, code, message);

export interface IssueInput {
  holderId: string;
  credentialTypeCode: string;
  attributes: Record<string, unknown>;
  /** undefined = use the type's default validity; null = no expiry; string = strict ISO UTC, seconds. */
  expiresAt?: string | null;
}

/** Validate the request body shape. Unknown properties are rejected; nothing from the body is echoed back. */
export function parseIssueBody(body: unknown): IssueInput {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw badRequest('BAD_REQUEST', 'Invalid request');
  const b = body as Record<string, unknown>;
  const known = new Set(['holderId', 'credentialTypeCode', 'attributes', 'expiresAt']);
  if (Object.keys(b).some((k) => !known.has(k))) throw badRequest('UNKNOWN_PROPERTY', 'Unknown property');
  if (typeof b.holderId !== 'string') throw badRequest('INVALID_HOLDER_ID', 'holderId is required');
  if (typeof b.credentialTypeCode !== 'string' || b.credentialTypeCode.length > 40) {
    throw badRequest('INVALID_TYPE_CODE', 'credentialTypeCode is required');
  }
  const attrs = b.attributes ?? {};
  if (!attrs || typeof attrs !== 'object' || Array.isArray(attrs)) {
    throw badRequest('INVALID_ATTRIBUTES', 'attributes must be an object');
  }
  if (Object.keys(attrs).length > MAX_ATTR_KEYS) throw badRequest('INVALID_ATTRIBUTES', 'Too many attributes');
  const out: IssueInput = {
    holderId: b.holderId,
    credentialTypeCode: b.credentialTypeCode,
    attributes: attrs as Record<string, unknown>,
  };
  if ('expiresAt' in b) {
    if (b.expiresAt !== null && !isIsoSeconds(b.expiresAt)) {
      throw badRequest('INVALID_EXPIRES_AT', 'expiresAt must be null or a UTC timestamp like 2027-01-31T00:00:00Z');
    }
    out.expiresAt = b.expiresAt as string | null;
  }
  return out;
}

function isIsoSeconds(v: unknown): v is string {
  if (typeof v !== 'string' || !ISO_RE.test(v)) return false;
  const t = Date.parse(v);
  return !Number.isNaN(t) && new Date(t).toISOString().slice(0, 19) + 'Z' === v;
}

const toIsoSeconds = (d: Date): string => d.toISOString().slice(0, 19) + 'Z';

/** NFC-normalise and check free text (ADR 0013: core does no normalisation, so issuance must). */
function cleanText(v: string, what: string): string {
  const t = v.normalize('NFC').trim();
  if (t.length < 1 || t.length > MAX_VALUE || BAD_TEXT_RE.test(t)) {
    throw badRequest('INVALID_ATTRIBUTE_VALUE', `${what} must be 1-${MAX_VALUE} characters without control or formatting characters`);
  }
  return t;
}

/**
 * Validate supplied attributes against the type's stored schema and return the string map that is signed.
 * The stored schema is re-validated with parseAttributes (T-019 follow-up L2) and own-property checks are used
 * everywhere (L4). Optional attributes left out are omitted from the payload.
 */
export function buildAttributes(schemaJson: unknown, supplied: Record<string, unknown>): Record<string, string> {
  let schema: AttributeDef[];
  try {
    schema = parseAttributes(schemaJson);
  } catch {
    throw new AppError(409, 'TYPE_SCHEMA_INVALID', 'This credential type has an invalid attribute list');
  }
  const known = new Set(schema.map((a) => a.key));
  for (const k of Object.keys(supplied)) {
    if (!known.has(k)) throw badRequest('UNKNOWN_ATTRIBUTE', 'Unknown attribute');
  }
  const out: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const def of schema) {
    const present = Object.hasOwn(supplied, def.key) && supplied[def.key] !== undefined && supplied[def.key] !== null;
    if (!present) {
      if (def.required) throw badRequest('MISSING_ATTRIBUTE', `Attribute ${def.key} is required`);
      continue;
    }
    const raw = supplied[def.key];
    if (def.type === 'string') {
      if (typeof raw !== 'string') throw badRequest('INVALID_ATTRIBUTE_VALUE', `Attribute ${def.key} must be text`);
      out[def.key] = cleanText(raw, `Attribute ${def.key}`);
    } else if (def.type === 'date') {
      if (typeof raw !== 'string' || !DATE_RE.test(raw) || new Date(`${raw}T00:00:00Z`).toISOString().slice(0, 10) !== raw) {
        throw badRequest('INVALID_ATTRIBUTE_VALUE', `Attribute ${def.key} must be a date like 2026-01-31`);
      }
      out[def.key] = raw;
    } else {
      const s = typeof raw === 'number' && Number.isFinite(raw) ? String(raw) : typeof raw === 'string' ? raw.trim() : '';
      if (!NUMBER_RE.test(s)) throw badRequest('INVALID_ATTRIBUTE_VALUE', `Attribute ${def.key} must be a number`);
      out[def.key] = s;
    }
  }
  return { ...out };
}

export interface IssuedCredential {
  id: string;
  credentialNumber: string;
  status: 'ACTIVE';
  holderId: string;
  credentialTypeCode: string;
  issuedAt: string;
  expiresAt: string | null;
  issuerKeyId: string;
  dataHash: string;
  signature: string;
  payload: CredentialPayloadV1;
  verificationToken: string;
  /** Plaintext holder token: returned this once; only its SHA-256 is stored (ADR 0002). */
  holderToken: string;
  anchorStatus: 'NOT_ANCHORED';
}

export interface IssueContext {
  /** From the session, never from the request. */
  institutionId: string;
  actorId: string | null;
  masterKey: Buffer | undefined;
  /** Already hashed (hashIp). */
  ipHash?: string | undefined;
  now?: Date;
}

const sha256Hex = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex');
const newToken = (): string => randomBytes(16).toString('base64url'); // 128 bits

/** Next per-institution human number, e.g. 2026-000001. Caller holds the numbering lock. */
async function nextCredentialNumber(c: PoolClient, institutionId: string, year: number): Promise<string> {
  await c.query(`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, [`igaro.credno:${institutionId}`]);
  const r = await c.query<{ n: string }>(
    `SELECT COALESCE(max(substring(credential_number FROM '-([0-9]+)$')::bigint), 0)::text AS n
       FROM credentials WHERE institution_id = app_institution_id()`,
  );
  const next = BigInt(r.rows[0]!.n) + 1n;
  return `${year}-${next.toString().padStart(6, '0')}`;
}

/**
 * The single issuance code path. Runs inside the caller's tenant transaction (Db.withTenant) so everything commits or
 * rolls back together. The batch/CSV import (T-043/T-044) calls this same function per row via the API.
 */
export async function issueInTransaction(c: PoolClient, ctx: IssueContext, input: IssueInput): Promise<IssuedCredential> {
  if (!isUuid(input.holderId)) throw new NotFoundError();
  const now = ctx.now ?? new Date();
  const issuedAt = toIsoSeconds(now);

  const inst = await c.query<{ status: string }>(`SELECT status FROM institutions WHERE id = app_institution_id()`);
  if (!inst.rows[0]) throw new NotFoundError();
  if (inst.rows[0].status !== 'ACTIVE') throw new AppError(409, 'INSTITUTION_SUSPENDED', 'This institution cannot issue credentials');

  // FOR SHARE: a concurrent photo change (FOR UPDATE) or key rotation waits until this issuance commits.
  const holder = (
    await c.query<{ id: string; full_name: string; external_id: string | null; photo_sha256: string | null }>(
      `SELECT id, full_name, external_id, photo_sha256 FROM credential_holders
        WHERE id = $1 AND institution_id = app_institution_id() FOR SHARE`,
      [input.holderId],
    )
  ).rows[0];
  if (!holder) throw new NotFoundError();
  const type = (
    await c.query<{ id: string; code: string; attribute_schema: unknown; validity_days: number | null }>(
      `SELECT id, code, attribute_schema, validity_days FROM credential_types
        WHERE code = $1 AND institution_id = app_institution_id() FOR SHARE`,
      [input.credentialTypeCode],
    )
  ).rows[0];
  if (!type) throw new NotFoundError();

  const attributes = buildAttributes(type.attribute_schema, input.attributes);

  if (!holder.photo_sha256 || !SHA256_HEX.test(holder.photo_sha256)) {
    throw new AppError(409, 'HOLDER_PHOTO_REQUIRED', 'The holder needs a photo before a credential can be issued');
  }

  let expiresAt: string | null;
  if (input.expiresAt === undefined) {
    expiresAt = type.validity_days ? toIsoSeconds(new Date(now.getTime() + type.validity_days * 86_400_000)) : null;
  } else {
    expiresAt = input.expiresAt;
  }
  if (expiresAt !== null && Date.parse(expiresAt) <= Date.parse(issuedAt)) {
    throw badRequest('INVALID_EXPIRES_AT', 'expiresAt must be in the future');
  }

  const key = (
    await c.query<{ kid: string; public_key: string; encrypted_private_key: string }>(
      `SELECT kid, public_key, encrypted_private_key FROM institution_keys
        WHERE institution_id = app_institution_id() AND status = 'ACTIVE' FOR SHARE`,
    )
  ).rows[0];
  if (!key) throw new AppError(409, 'NO_ACTIVE_KEY', 'The institution has no active signing key');
  if (!ctx.masterKey) throw new AppError(503, 'KEY_CUSTODY_UNAVAILABLE', 'Credentials cannot be signed right now');

  const id = randomUUID();
  const credentialNumber = await nextCredentialNumber(c, ctx.institutionId, now.getUTCFullYear());
  const verificationToken = newToken();
  const holderToken = newToken();

  const payload: CredentialPayloadV1 = {
    schemaVersion: CREDENTIAL_SCHEMA_VERSION,
    credentialId: id,
    credentialNumber,
    institutionId: ctx.institutionId,
    issuerKeyId: key.kid,
    credentialType: type.code,
    holder: {
      fullName: holder.full_name.normalize('NFC'),
      externalId: holder.external_id === null ? null : holder.external_id.normalize('NFC'),
      photoSha256: holder.photo_sha256,
    },
    attributes,
    issuedAt,
    expiresAt,
    salt: generateSalt(),
  };

  // Unwrap only now; the KeyObject goes out of scope right after signing. Errors carry no key material.
  let dataHash: string;
  let signature: string;
  try {
    const priv = unwrapPrivateKey(key.encrypted_private_key, ctx.masterKey, key.kid);
    ({ dataHash, signature } = signCredential(payload, priv));
    if (!verifyDataHashSignature(dataHash, signature, key.public_key)) throw new Error('self-check failed');
  } catch {
    throw new AppError(500, 'SIGNING_FAILED', 'Could not sign the credential');
  }

  await c.query(
    `INSERT INTO credentials
       (id, institution_id, holder_id, type_id, credential_number, status, payload, data_hash, issuer_kid, signature,
        issued_at, expires_at, verification_token, holder_token_hash, updated_at)
     VALUES ($1, app_institution_id(), $2, $3, $4, 'ACTIVE', $5::jsonb, $6, $7, $8, $9::timestamptz, $10::timestamptz, $11, $12, now())`,
    [id, holder.id, type.id, credentialNumber, JSON.stringify(payload), dataHash, key.kid, signature, issuedAt, expiresAt, verificationToken, sha256Hex(holderToken)],
  );
  // Outbox row (Phase 1 anchoring); anchor_status stays NOT_ANCHORED. Payload carries no tokens or salt.
  await c.query(
    `INSERT INTO credential_events (id, institution_id, credential_id, type, payload)
     VALUES ($1, app_institution_id(), $2, 'ISSUED', $3::jsonb)`,
    [randomUUID(), id, JSON.stringify({ credentialNumber, dataHash, kid: key.kid })],
  );
  await appendAudit(c, {
    institutionId: ctx.institutionId,
    actorId: ctx.actorId,
    action: 'credential.issued',
    targetType: 'credential',
    targetId: id,
    metadata: { credentialNumber, credentialType: type.code, holderId: holder.id, kid: key.kid, dataHash },
    ip: ctx.ipHash ?? null,
  });

  return {
    id,
    credentialNumber,
    status: 'ACTIVE',
    holderId: holder.id,
    credentialTypeCode: type.code,
    issuedAt,
    expiresAt,
    issuerKeyId: key.kid,
    dataHash,
    signature,
    payload,
    verificationToken,
    holderToken,
    anchorStatus: 'NOT_ANCHORED',
  };
}

export class CredentialService {
  constructor(
    private readonly db: Db,
    private readonly opts: { masterKey: Buffer | undefined; hashIp?: (ip: string | undefined) => string | undefined },
  ) {}

  /** Request-scoped: the institution is taken from the session object only. */
  async issue(session: TenantSession, input: IssueInput, ip?: string): Promise<IssuedCredential> {
    return this.db.withTenant(session, (c) =>
      issueInTransaction(
        c,
        { institutionId: session.institutionId, actorId: session.userId, masterKey: this.opts.masterKey, ipHash: this.opts.hashIp?.(ip) },
        input,
      ),
    );
  }
}

const tenantScope = (req: FastifyRequest): TenantSession => {
  const s: AuthSession | null = req.session;
  if (!s || s.kind !== 'tenant') throw new AppError(403, 'FORBIDDEN', 'Insufficient role');
  return { kind: 'tenant', userId: s.userId, institutionId: s.institutionId };
};

export function registerCredentials(app: FastifyInstance, svc: CredentialService, log: FastifyBaseLogger): void {
  const ia = { preHandler: app.requireRole('INSTITUTION_ADMIN') };

  app.post('/credentials', ia, async (req, reply) => {
    void reply.header('Cache-Control', 'no-store');
    const scope = tenantScope(req);
    const input = parseIssueBody(req.body);
    const out = await svc.issue(scope, input, req.ip);
    // Ids only: never tokens, salt or payload.
    log.info(
      { event: 'credential.issued', actorId: scope.userId, institutionId: scope.institutionId, credentialId: out.id },
      'credential issued',
    );
    return reply.status(201).send(out);
  });
}
