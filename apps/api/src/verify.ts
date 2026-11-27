// Public verification (T-032, ADR 0022): GET /verify/:token and GET /verify/:token/credential.json.
// No session. The credential is found through the narrow `app.verification_token` RLS lookup (init migration PART 4); the scope is
// then set from the row found so the key, institution, holder and type can be read. The result comes from core.verifyCredential
// (invariant 7: integrity before status). Never returned: `reason`, salt (except inside credential.json, which must carry the
// signed payload), internal ids, holder token, credential number lookups. Every check is written to verification_logs with a
// keyed IP hash (ADR 0003) and never the raw IP or the token.
import { createHash } from 'node:crypto';
import type { FastifyBaseLogger, FastifyInstance, FastifyRequest } from 'fastify';
import type pg from 'pg';
import { verifyCredential, type CredentialPayloadV1, type CredentialStatus, type VerificationOutcome } from '@igaro/core';
import type { Db } from './db.js';
import { DEFAULT_VERIFY_LIMIT } from './config.js';
import { AppError, NotFoundError, RateLimitedError } from './errors.js';
import { PgRateLimiter } from './rate-limit.js';
import type { ObjectStorage } from './storage.js';

export interface VerifyRateLimit {
  /** Requests per client IP (hashed) per window. */
  ipMax: number;
  /** Requests per verification token per window, across all IPs. */
  tokenMax: number;
  windowSeconds: number;
}

/** Lifetime of the signed photo URL in the verify response. */
export const VERIFY_PHOTO_URL_SECONDS = 300;
const TOKEN_RE = /^[A-Za-z0-9_-]{22}$/; // 16 random bytes as base64url
const MAX_UA = 200;
const SHA256_RE = /^[0-9a-f]{64}$/;
const PUBLIC_FIELD_NAMES = ['photo', 'idNumber', 'attributes'];

interface Loaded {
  cred: {
    id: string;
    institution_id: string;
    status: string;
    payload: unknown;
    data_hash: string;
    signature: string;
    issuer_kid: string;
    issued_at: Date | null;
    expires_at: Date | null;
    anchor_status: string;
    superseded_by: string | null;
  };
  key: { kid: string; institution_id: string; public_key: string; status: 'ACTIVE' | 'RETIRED' | 'COMPROMISED' } | null;
  inst: {
    name: string;
    slug: string;
    status: string;
    card_title: string | null;
    primary_color: string;
    secondary_color: string;
    public_fields: unknown;
  };
  holder: { id: string; photo_key: string | null; photo_sha256: string | null } | null;
  type: { code: string; name: string; kind: string } | null;
  nextToken: string | null;
}

export interface VerifyContext {
  db: Db;
  storage?: ObjectStorage | undefined;
  log: FastifyBaseLogger;
  hashIp: (ip: string | undefined) => string | undefined;
  rateLimit?: VerifyRateLimit | undefined;
  now?: () => Date;
}

/** Only a well-formed token is handed to Postgres; anything else is a lookup miss. */
const lookupSettings = (token: string): { 'app.verification_token'?: string } =>
  TOKEN_RE.test(token) ? { 'app.verification_token': token } : {};

async function load(c: pg.PoolClient, token: string): Promise<Loaded | null> {
  if (!TOKEN_RE.test(token)) return null;
  const cr = await c.query<Loaded['cred']>(
    `SELECT id, institution_id, status::text AS status, payload, data_hash, signature, issuer_kid, issued_at, expires_at,
            anchor_status::text AS anchor_status, superseded_by
       FROM credentials WHERE verification_token = $1`,
    [token],
  );
  const cred = cr.rows[0];
  // Unknown and DRAFT take the same path: no further queries (ADR 0022).
  if (!cred || cred.status === 'DRAFT') return null;
  // Scope from the row we matched, never from the request (same pattern as the session lookup).
  await c.query(`SELECT set_config('app.institution_id', $1, true)`, [cred.institution_id]);
  const inst = (
    await c.query<Loaded['inst']>(
      `SELECT name, slug, status::text AS status, card_title, primary_color, secondary_color, public_fields
         FROM institutions WHERE id = $1`,
      [cred.institution_id],
    )
  ).rows[0];
  if (!inst) return null;
  const key = (
    await c.query<NonNullable<Loaded['key']>>(
      `SELECT kid, institution_id, public_key, status::text AS status FROM institution_keys WHERE institution_id = $1 AND kid = $2`,
      [cred.institution_id, cred.issuer_kid],
    )
  ).rows[0];
  const holder = (
    await c.query<NonNullable<Loaded['holder']>>(
      `SELECT h.id, h.photo_key, h.photo_sha256 FROM credential_holders h JOIN credentials c ON c.holder_id = h.id AND c.institution_id = h.institution_id WHERE c.id = $1`,
      [cred.id],
    )
  ).rows[0];
  const type = (
    await c.query<NonNullable<Loaded['type']>>(
      `SELECT t.code, t.name, t.kind::text AS kind FROM credential_types t JOIN credentials c ON c.type_id = t.id AND c.institution_id = t.institution_id WHERE c.id = $1`,
      [cred.id],
    )
  ).rows[0];
  let nextToken: string | null = null;
  if (cred.superseded_by) {
    nextToken =
      (
        await c.query<{ verification_token: string }>(
          `SELECT verification_token FROM credentials WHERE id = $1 AND institution_id = $2`,
          [cred.superseded_by, cred.institution_id],
        )
      ).rows[0]?.verification_token ?? null;
  }
  return { cred, key: key ?? null, inst, holder: holder ?? null, type: type ?? null, nextToken };
}

export class VerifyService {
  private readonly ipLimiter: PgRateLimiter;
  private readonly tokenLimiter: PgRateLimiter;

  constructor(private readonly ctx: VerifyContext) {
    const rl = ctx.rateLimit ?? DEFAULT_VERIFY_LIMIT;
    this.ipLimiter = new PgRateLimiter({ db: ctx.db, family: 'verify-ip', max: rl.ipMax, windowSeconds: rl.windowSeconds, onError: 'open' });
    this.tokenLimiter = new PgRateLimiter({ db: ctx.db, family: 'verify-token', max: rl.tokenMax, windowSeconds: rl.windowSeconds, onError: 'open' });
  }

  /** Per-IP limit, counted on every request. */
  async enforceLimits(req: FastifyRequest): Promise<void> {
    const ipWait = await this.ipLimiter.consume(this.ctx.hashIp(req.ip) ?? 'unknown');
    if (ipWait > 0) throw new RateLimitedError(ipWait);
  }

  /**
   * Per-token limit, counted only for NOT_FOUND and failed lookups (ADR 0022): successful checks of a real credential never
   * count, so a QR holder cannot lock a genuine credential out by hammering it; per-IP limits bound that traffic instead.
   * Keyed by the token's hash, so no token sits in memory tables.
   */
  private async noteMiss(token: string): Promise<void> {
    const wait = await this.tokenLimiter.consume(createHash('sha256').update(token).digest('hex'));
    if (wait > 0) throw new RateLimitedError(wait);
  }

  async verify(token: string, req: FastifyRequest): Promise<Record<string, unknown>> {
    const ipHash = this.ctx.hashIp(req.ip) ?? null;
    const ua = typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'].slice(0, MAX_UA) : null;
    const now = this.ctx.now?.() ?? new Date();

    const { loaded, outcome } = await this.ctx.db.withLookup(lookupSettings(token), async (c) => {
      const loaded = await load(c, token);
      const outcome = verifyCredential({
        record: loaded && {
          id: loaded.cred.id,
          institutionId: loaded.cred.institution_id,
          status: loaded.cred.status as CredentialStatus,
          payload: loaded.cred.payload,
          dataHash: loaded.cred.data_hash,
          signature: loaded.cred.signature,
          supersededByCredentialId: loaded.cred.superseded_by,
        },
        key: loaded?.key && {
          kid: loaded.key.kid,
          institutionId: loaded.key.institution_id,
          publicKey: loaded.key.public_key,
          status: loaded.key.status,
        },
        institutionSuspended: loaded?.inst.status === 'SUSPENDED',
        now,
      });
      // Unknown token and DRAFT are logged identically, with no credential link.
      const known = loaded && outcome.result !== 'NOT_FOUND';
      const logResult = outcome.reason === 'KEY_COMPROMISED' ? 'KEY_COMPROMISED' : outcome.result;
      await c.query(
        `INSERT INTO verification_logs (id, institution_id, credential_id, result, ip_hash, user_agent)
         VALUES (gen_random_uuid(), $1, $2, $3::verification_result, $4, $5)`,
        [known ? loaded.cred.institution_id : null, known ? loaded.cred.id : null, logResult, ipHash, ua],
      );
      return { loaded, outcome };
    });

    if (outcome.result === 'NOT_FOUND' || outcome.result === 'VERIFICATION_FAILED') await this.noteMiss(token);

    if (outcome.alertOps && loaded) {
      // Ops alert (ADR 0022): structured error line, internal ids only, no token, salt, payload or IP.
      this.ctx.log.error(
        {
          event: 'VERIFICATION_INTEGRITY_FAILURE',
          alert: 'ops',
          reason: outcome.reason,
          institutionId: loaded.cred.institution_id,
          credentialId: loaded.cred.id,
          ipHash,
        },
        'verification integrity failure',
      );
    }
    return this.present(loaded, outcome);
  }

  private async present(loaded: Loaded | null, outcome: VerificationOutcome): Promise<Record<string, unknown>> {
    const blank = {
      result: outcome.result,
      institution: null,
      holder: null,
      type: null,
      status: null,
      issuedAt: null,
      expiresAt: null,
      supersededBy: null,
      proof: null,
    };
    // NOT_FOUND and failures reveal nothing from the (possibly altered) row.
    if (!loaded || outcome.result === 'NOT_FOUND' || outcome.result === 'VERIFICATION_FAILED') return blank;

    const payload = loaded.cred.payload as CredentialPayloadV1; // authentic: integrity passed
    const fields = (Array.isArray(loaded.inst.public_fields) ? loaded.inst.public_fields : []).filter(
      (f): f is string => typeof f === 'string' && PUBLIC_FIELD_NAMES.includes(f),
    );
    const holder: Record<string, unknown> = { fullName: payload.holder.fullName };
    if (fields.includes('idNumber')) holder.idNumber = payload.holder.externalId;
    if (fields.includes('attributes')) holder.attributes = payload.attributes;
    if (fields.includes('photo')) {
      holder.photoUrl = null;
      const h = loaded.holder;
      const signedSha = payload.holder.photoSha256;
      // The object key is rebuilt from the SIGNED photoSha256 (keys are content-addressed, see holders.ts), never taken
      // from the unsigned photo_key column, so a swapped column cannot point a VERIFIED result at another image. Only the
      // extension is read from the column, and only from an allow-list. The web layer re-hashes the fetched bytes.
      const ext = h?.photo_key ? /\.(png|jpg)$/.exec(h.photo_key)?.[1] : undefined;
      if (this.ctx.storage && h && ext && typeof signedSha === 'string' && SHA256_RE.test(signedSha) && h.photo_sha256 === signedSha) {
        try {
          const key = `institutions/${loaded.cred.institution_id}/holders/${h.id}/photo/${signedSha}.${ext}`;
          holder.photoUrl = await this.ctx.storage.signedGetUrl(key, VERIFY_PHOTO_URL_SECONDS);
          holder.photoSha256 = signedSha;
        } catch {
          holder.photoUrl = null;
        }
      }
    }
    return {
      result: outcome.result,
      ...(outcome.result === 'VALID_WITH_WARNING' ? { warning: 'INSTITUTION_SUSPENDED' } : {}),
      institution: {
        name: loaded.inst.name,
        slug: loaded.inst.slug,
        cardTitle: loaded.inst.card_title,
        primaryColor: loaded.inst.primary_color,
        secondaryColor: loaded.inst.secondary_color,
      },
      holder,
      // The label is the SIGNED type code (ADR 0036): credential_types.name is editable and unsigned, so it is never shown as verified.
      type: { code: payload.credentialType, name: payload.credentialType, kind: loaded.type?.kind ?? 'UNKNOWN' },
      // EXPIRED comes from core's outcome (signed expiry), never from the unsigned column.
      status: outcome.result === 'EXPIRED' ? 'EXPIRED' : loaded.cred.status,
      issuedAt: payload.issuedAt,
      expiresAt: payload.expiresAt,
      supersededBy: outcome.result === 'SUPERSEDED' ? loaded.nextToken : null,
      proof: { signedBy: loaded.inst.name, kid: payload.issuerKeyId, anchorStatus: loaded.cred.anchor_status },
    };
  }

  /** The signed document for tools/verify-cli. Served as stored (the CLI detects tampering); no status or private data. */
  async credentialJson(token: string): Promise<Record<string, unknown>> {
    const found = await this.ctx.db.withLookup(lookupSettings(token), async (c) => {
      if (!TOKEN_RE.test(token)) return null;
      const cr = await c.query<{ payload: unknown; data_hash: string; signature: string; issuer_kid: string; status: string; institution_id: string }>(
        `SELECT payload, data_hash, signature, issuer_kid, status::text AS status, institution_id
           FROM credentials WHERE verification_token = $1`,
        [token],
      );
      const row = cr.rows[0];
      if (!row || row.status === 'DRAFT') return null;
      await c.query(`SELECT set_config('app.institution_id', $1, true)`, [row.institution_id]);
      const slug = (await c.query<{ slug: string }>(`SELECT slug FROM institutions WHERE id = $1`, [row.institution_id])).rows[0]?.slug;
      return slug ? { row, slug } : null;
    });
    if (!found) {
      await this.noteMiss(token);
      throw new NotFoundError();
    }
    return {
      payload: found.row.payload,
      dataHash: found.row.data_hash,
      signature: found.row.signature,
      kid: found.row.issuer_kid,
      publicKeysUrl: `/i/${found.slug}/keys.json`,
    };
  }
}

export function registerVerify(app: FastifyInstance, svc: VerifyService): void {
  const tokenParam = (req: FastifyRequest): string => {
    const t = (req.params as { verificationToken?: unknown }).verificationToken;
    // Over-long values are just another unknown token (Fastify's maxParamLength is raised in app.ts).
    if (typeof t !== 'string' || t.length === 0) throw new AppError(400, 'BAD_REQUEST', 'Invalid request');
    return t;
  };
  app.get('/verify/:verificationToken', async (req, reply) => {
    const token = tokenParam(req);
    await svc.enforceLimits(req);
    void reply.header('Cache-Control', 'no-store');
    return svc.verify(token, req);
  });
  app.get('/verify/:verificationToken/credential.json', async (req, reply) => {
    const token = tokenParam(req);
    await svc.enforceLimits(req);
    void reply.header('Cache-Control', 'no-store');
    return svc.credentialJson(token);
  });
}
