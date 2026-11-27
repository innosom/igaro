// Public lookups (T-033, ADR 0023): GET /i/:slug/keys.json (site root, not under /api/v1) and GET /api/v1/holder/:holderToken.
// No session, no migration: both use narrow lookup policies from the init migration (app.institution_slug, app.holder_token_hash).
// Never returned: private key material, internal ids, credential numbers, salt, holder token. Never logged: tokens.
import { createHash } from 'node:crypto';
import type { FastifyBaseLogger, FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { verifyCredentialIntegrity } from '@igaro/core';
import { cardStorageKeys } from '@igaro/worker/producer';
import { CARD_RETRY_AFTER_SECONDS, CARD_URL_SECONDS } from './card-endpoints.js';
import { DEFAULT_VERIFY_LIMIT } from './config.js';
import type { Db } from './db.js';
import { AppError, NotFoundError, RateLimitedError } from './errors.js';
import type { ObjectStorage } from './storage.js';
import { PgRateLimiter } from './rate-limit.js';
import type { VerifyRateLimit } from './verify.js';

const SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{1,38}[a-z0-9])$/;
const TOKEN_RE = /^[A-Za-z0-9_-]{22}$/; // 128-bit token, base64url
const sha256Hex = (s: string): string => createHash('sha256').update(s).digest('hex');

export interface PublicLookupContext {
  db: Db;
  hashIp: (ip: string | undefined) => string | undefined;
  rateLimit?: VerifyRateLimit | undefined;
  storage?: ObjectStorage | undefined;
  log?: FastifyBaseLogger | undefined;
}

export class PublicLookupService {
  private readonly keysIp: PgRateLimiter;
  private readonly holderIp: PgRateLimiter;
  private readonly holderMiss: PgRateLimiter;

  constructor(private readonly ctx: PublicLookupContext) {
    const rl = ctx.rateLimit ?? DEFAULT_VERIFY_LIMIT;
    const mk = (family: string, max: number) => new PgRateLimiter({ db: ctx.db, family, max, windowSeconds: rl.windowSeconds, onError: 'open' });
    this.keysIp = mk('keys-ip', rl.ipMax);
    this.holderIp = mk('holder-ip', rl.ipMax);
    this.holderMiss = mk('holder-miss', rl.tokenMax);
  }

  private async limit(l: PgRateLimiter, req: FastifyRequest): Promise<void> {
    const wait = await l.consume(this.ctx.hashIp(req.ip) ?? 'unknown');
    if (wait > 0) throw new RateLimitedError(wait);
  }

  async keys(slug: string, req: FastifyRequest): Promise<{ keys: Record<string, unknown>[] }> {
    await this.limit(this.keysIp, req);
    if (!SLUG_RE.test(slug)) throw new NotFoundError();
    const rows = await this.ctx.db.withLookup({ 'app.institution_slug': slug }, async (c) => {
      const inst = (await c.query<{ id: string }>(`SELECT id FROM institutions WHERE slug = $1`, [slug])).rows[0];
      if (!inst) return null;
      await c.query(`SELECT set_config('app.institution_id', $1, true)`, [inst.id]);
      // Explicit column list: the encrypted private key is never selected.
      return (
        await c.query<{ kid: string; algorithm: string; public_key: string; status: string; created_at: Date; retired_at: Date | null }>(
          `SELECT kid, algorithm, public_key, status::text AS status, created_at, retired_at
             FROM institution_keys WHERE institution_id = $1 ORDER BY created_at, kid`,
          [inst.id],
        )
      ).rows;
    });
    if (!rows) throw new NotFoundError();
    return {
      keys: rows.map((k) => ({
        kid: k.kid,
        alg: 'Ed25519',
        publicKey: k.public_key,
        status: k.status,
        createdAt: k.created_at.toISOString(),
        retiredAt: k.retired_at ? k.retired_at.toISOString() : null,
      })),
    };
  }

  async holderView(token: string, req: FastifyRequest): Promise<Record<string, unknown>> {
    await this.limit(this.holderIp, req);
    const miss = async (): Promise<never> => {
      const wait = await this.holderMiss.consume(sha256Hex(token));
      if (wait > 0) throw new RateLimitedError(wait);
      throw new NotFoundError();
    };
    if (!TOKEN_RE.test(token)) return await miss();
    const hash = sha256Hex(token);
    const found = await this.ctx.db.withLookup({ 'app.holder_token_hash': hash }, async (c) => {
      const cr = (
        await c.query<{
          institution_id: string;
          holder_id: string;
          status: string;
          verification_token: string;
          issued_at: Date | null;
          expires_at: Date | null;
          type_id: string;
        }>(
          `SELECT institution_id, holder_id, status::text AS status, verification_token, issued_at, expires_at, type_id
             FROM credentials WHERE holder_token_hash = $1`,
          [hash],
        )
      ).rows[0];
      if (!cr || cr.status === 'DRAFT') return null;
      await c.query(`SELECT set_config('app.institution_id', $1, true)`, [cr.institution_id]);
      const inst = (
        await c.query<{ name: string; slug: string; card_title: string | null; primary_color: string; secondary_color: string; logo_key: string | null }>(
          `SELECT name, slug, card_title, primary_color, secondary_color, logo_key FROM institutions WHERE id = $1`,
          [cr.institution_id],
        )
      ).rows[0];
      const holder = (
        await c.query<{ full_name: string }>(`SELECT full_name FROM credential_holders WHERE id = $1 AND institution_id = $2`, [cr.holder_id, cr.institution_id])
      ).rows[0];
      const type = (
        await c.query<{ code: string; name: string; kind: string }>(
          `SELECT code, name, kind::text AS kind FROM credential_types WHERE id = $1 AND institution_id = $2`,
          [cr.type_id, cr.institution_id],
        )
      ).rows[0];
      return inst && holder && type ? { cr, inst, holder, type } : null;
    });
    if (!found) return await miss();
    const { cr, inst, holder, type } = found;
    const expired = cr.status === 'ACTIVE' && cr.expires_at !== null && cr.expires_at.getTime() <= Date.now();
    const vt = cr.verification_token;
    const cardLive = cr.status === 'ACTIVE' && !expired;
    return {
      holder: { fullName: holder.full_name },
      institution: {
        name: inst.name,
        slug: inst.slug,
        cardTitle: inst.card_title,
        primaryColor: inst.primary_color,
        secondaryColor: inst.secondary_color,
      },
      // The holder token opens exactly the credential it was issued with (ADR 0023): one entry.
      credentials: [
        {
          verificationToken: vt,
          type: { code: type.code, name: type.name, kind: type.kind },
          status: expired ? 'EXPIRED' : cr.status,
          issuedAt: cr.issued_at ? cr.issued_at.toISOString() : null,
          expiresAt: cr.expires_at ? cr.expires_at.toISOString() : null,
          links: {
            verify: `/v/${vt}`,
            credentialJson: `/api/v1/verify/${vt}/credential.json`,
            publicKeys: `/i/${inst.slug}/keys.json`,
            // Token-authenticated downloads (ADR 0031); offered only while the credential is ACTIVE and unexpired.
            card: cardLive ? `/api/v1/holder/${token}/card.png` : null,
            cardPdf: cardLive ? `/api/v1/holder/${token}/card.pdf` : null,
          },
        },
      ],
    };
  }

  /** Holder card download (ADR 0031): the ADR 0029 serve-only-what-verifies rules, authenticated by the holder token. */
  async holderCard(token: string, ext: 'png' | 'pdf', req: FastifyRequest, reply: FastifyReply): Promise<FastifyReply> {
    await this.limit(this.holderIp, req);
    const miss = async (): Promise<never> => {
      const wait = await this.holderMiss.consume(sha256Hex(token));
      if (wait > 0) throw new RateLimitedError(wait);
      throw new NotFoundError();
    };
    if (!TOKEN_RE.test(token)) return await miss();
    const hash = sha256Hex(token);
    const row = await this.ctx.db.withLookup({ 'app.holder_token_hash': hash }, async (c) => {
      const cr = (
        await c.query<{
          id: string;
          institution_id: string;
          status: string;
          payload: unknown;
          data_hash: string;
          signature: string;
          issuer_kid: string;
        }>(
          `SELECT id, institution_id, status::text AS status, payload, data_hash, signature, issuer_kid
             FROM credentials WHERE holder_token_hash = $1`,
          [hash],
        )
      ).rows[0];
      if (!cr || cr.status === 'DRAFT') return null;
      await c.query(`SELECT set_config('app.institution_id', $1, true)`, [cr.institution_id]);
      const key = (
        await c.query<{ public_key: string; status: string }>(
          `SELECT public_key, status::text AS status FROM institution_keys WHERE institution_id = $1 AND kid = $2`,
          [cr.institution_id, cr.issuer_kid],
        )
      ).rows[0];
      return { cr, key };
    });
    if (!row) return await miss();
    const { cr, key } = row;
    const payload = cr.payload as { credentialId?: unknown; institutionId?: unknown; expiresAt?: unknown } | null;
    const ok =
      !!key &&
      key.status !== 'COMPROMISED' &&
      payload?.credentialId === cr.id &&
      payload?.institutionId === cr.institution_id &&
      verifyCredentialIntegrity(cr.payload, cr.data_hash, cr.signature, key.public_key) === 'OK';
    if (!ok) {
      this.ctx.log?.error(
        { event: 'card.integrity_failure', institutionId: cr.institution_id, credentialId: cr.id, via: 'holder' },
        'stored credential failed integrity check; card not served',
      );
      return await miss();
    }
    // Integrity first (invariant 7), then state. Expiry comes from the signed payload.
    const exp = payload?.expiresAt;
    const expired = typeof exp === 'string' && Date.parse(exp) <= Date.now();
    if (cr.status !== 'ACTIVE' || expired) return await miss();

    const storage = this.ctx.storage;
    if (!storage) throw new AppError(503, 'STORAGE_UNAVAILABLE', 'Cards are not available right now');
    const storageKey = cardStorageKeys(cr.institution_id, cr.id)[ext];
    let url: string;
    try {
      if (!(await storage.exists(storageKey))) {
        void reply.header('Retry-After', String(CARD_RETRY_AFTER_SECONDS));
        return reply.status(404).send({ error: { code: 'CARD_NOT_READY', message: 'The card is not ready yet' } });
      }
      url = await storage.signedGetUrl(storageKey, CARD_URL_SECONDS);
    } catch {
      this.ctx.log?.error(
        { event: 'card.storage_failed', institutionId: cr.institution_id, credentialId: cr.id, via: 'holder' },
        'card storage lookup failed',
      );
      throw new AppError(503, 'STORAGE_UNAVAILABLE', 'Cards are not available right now');
    }
    // The URL is a bearer credential: only in the Location header, never logged.
    this.ctx.log?.info(
      { event: 'card.served', institutionId: cr.institution_id, credentialId: cr.id, format: ext, via: 'holder' },
      'card redirect issued',
    );
    return reply.redirect(url, 302);
  }
}

export function registerPublicKeys(app: FastifyInstance, svc: PublicLookupService): void {
  app.get('/i/:slug/keys.json', async (req, reply) => {
    void reply.header('Cache-Control', 'no-store');
    return svc.keys(String((req.params as { slug?: unknown }).slug ?? ''), req);
  });
}

export function registerHolderView(api: FastifyInstance, svc: PublicLookupService): void {
  api.get('/holder/:holderToken', async (req, reply) => {
    void reply.header('Cache-Control', 'no-store');
    void reply.header('Referrer-Policy', 'no-referrer');
    return svc.holderView(String((req.params as { holderToken?: unknown }).holderToken ?? ''), req);
  });
  for (const ext of ['png', 'pdf'] as const) {
    api.get(`/holder/:holderToken/card.${ext}`, async (req, reply) => {
      void reply.header('Cache-Control', 'no-store');
      void reply.header('Referrer-Policy', 'no-referrer');
      return svc.holderCard(String((req.params as { holderToken?: unknown }).holderToken ?? ''), ext, req, reply);
    });
  }
}
