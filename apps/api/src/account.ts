// Invite acceptance and password reset (T-010, ADR 0005).
//
// Tokens are 256 random bits (base64url). Only SHA-256(token) hex is stored. Each token is single
// use: the claiming UPDATE (... WHERE used_at IS NULL AND expires_at > now()) is atomic, so two
// concurrent requests cannot both win. Unknown, expired, used and malformed tokens are
// indistinguishable to the caller (one INVALID_TOKEN error). Raw tokens leave this module only in
// the return value of issue functions and in AccountMailQueue jobs; they are never logged.
import { randomBytes } from 'node:crypto';
import type { FastifyBaseLogger } from 'fastify';
import type { PoolClient } from 'pg';
import { hashPassword, setPasswordAndKillSessions, sha256Hex } from './auth.js';
import { DEFAULT_TOKEN_TTL, type Config } from './config.js';
import { isUuid, type Db, type Session } from './db.js';
import { AppError } from './errors.js';
import { NoopAccountMailQueue, type AccountMailQueue } from './notifications.js';

export const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
export const MIN_PASSWORD = 12;
export const MAX_PASSWORD = 256;
const MAX_NAME = 200;

export const newOneTimeToken = (): string => randomBytes(32).toString('base64url');
export const hashOneTimeToken = (token: string): string => sha256Hex(token);

export const invalidToken = () =>
  new AppError(400, 'INVALID_TOKEN', 'This link is invalid or has expired');
export const weakPassword = () =>
  new AppError(
    400,
    'WEAK_PASSWORD',
    `Password must be between ${MIN_PASSWORD} and ${MAX_PASSWORD} characters`,
  );

export function checkPassword(password: string, email?: string): void {
  if (password.length < MIN_PASSWORD || password.length > MAX_PASSWORD) throw weakPassword();
  if (email && password.toLowerCase() === email.toLowerCase()) throw weakPassword();
}

export const normalizeEmail = (e: string): string => e.trim().toLowerCase();

export interface AccountServiceOptions {
  queue?: AccountMailQueue;
  tokenTtl?: Config['tokenTtl'];
  log?: FastifyBaseLogger;
}

export class AccountService {
  private readonly queue: AccountMailQueue;
  private readonly ttl: Config['tokenTtl'];
  private readonly log: FastifyBaseLogger | undefined;

  constructor(
    private readonly db: Db,
    o: AccountServiceOptions = {},
  ) {
    this.queue = o.queue ?? new NoopAccountMailQueue();
    this.ttl = o.tokenTtl ?? DEFAULT_TOKEN_TTL;
    this.log = o.log;
  }

  /**
   * Create an invite for an INSTITUTION_ADMIN and enqueue the mail. For callers that already
   * authenticated (T-015 platform admin first-admin invite; an institution admin inviting a peer).
   * A tenant session always invites into its own institution; only a platform session names one.
   */
  async issueInvite(
    scope: Session,
    args: { email: string; institutionId?: string },
  ): Promise<{ expiresAt: Date }> {
    const email = normalizeEmail(args.email);
    const institutionId = scope.kind === 'tenant' ? scope.institutionId : args.institutionId;
    if (!institutionId || !isUuid(institutionId)) throw new TypeError('institution required');
    const token = newOneTimeToken();
    const expiresAt = await this.db.withTenant(scope, (c) =>
      this.insertInvite(c, institutionId, email, token),
    );
    await this.sendInvite({ email, token, expiresAt, institutionId });
    return { expiresAt };
  }

  /**
   * Insert an invite row inside a caller-owned transaction (platform scope for the first admin).
   * Only SHA-256(token) is stored. The caller enqueues the mail with sendInvite AFTER commit.
   */
  async insertInvite(
    c: PoolClient,
    institutionId: string,
    email: string,
    token: string,
  ): Promise<Date> {
    const r = await c.query<{ expires_at: Date }>(
      `INSERT INTO invites (id, institution_id, email, token_hash, expires_at)
       VALUES (gen_random_uuid(), $1, $2, $3, now() + make_interval(secs => $4))
       RETURNING expires_at`,
      [institutionId, normalizeEmail(email), hashOneTimeToken(token), this.ttl.inviteSeconds],
    );
    return r.rows[0]!.expires_at;
  }

  /** Enqueue the invite mail carrying the raw token (never logged). Call after the invite committed. */
  async sendInvite(args: {
    email: string;
    token: string;
    expiresAt: Date;
    institutionId: string;
  }): Promise<void> {
    await this.queue.enqueue({
      kind: 'INVITE',
      to: normalizeEmail(args.email),
      token: args.token,
      expiresAt: args.expiresAt,
      institutionId: args.institutionId,
    });
  }

  /**
   * Redeem an invite: create the INSTITUTION_ADMIN user with the chosen password. Does not log the
   * user in. Throws INVALID_TOKEN for any token problem, including an email that already has an
   * account (the invite stays unconsumed in that case).
   */
  async acceptInvite(token: string, password: string, name?: string): Promise<void> {
    if (!TOKEN_RE.test(token)) throw invalidToken();
    checkPassword(password);
    // Hash before touching the database so valid and invalid tokens cost about the same.
    const passwordHash = await hashPassword(password);
    const tokenHash = hashOneTimeToken(token);
    try {
      const ok = await this.db.withLookup({ 'app.invite_token_hash': tokenHash }, async (c) => {
        const r = await c.query<{ id: string; institution_id: string; email: string }>(
          `SELECT id, institution_id, email FROM invites
            WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()`,
          [tokenHash],
        );
        const inv = r.rows[0];
        if (!inv) return false;
        // Scope comes from the invite row we matched by hash, never from the request.
        await c.query(`SELECT set_config('app.institution_id', $1, true)`, [inv.institution_id]);
        const claimed = await c.query(
          `UPDATE invites SET used_at = now()
            WHERE id = $1 AND used_at IS NULL AND expires_at > now() RETURNING id`,
          [inv.id],
        );
        if (claimed.rowCount !== 1) return false;
        const displayName = (name?.trim() || inv.email.split('@')[0] || 'Administrator').slice(
          0,
          MAX_NAME,
        );
        await c.query(
          `INSERT INTO users (id, institution_id, email, name, password_hash, role, status, updated_at)
           VALUES (gen_random_uuid(), $1, $2, $3, $4, 'INSTITUTION_ADMIN', 'ACTIVE', now())`,
          [inv.institution_id, inv.email, displayName, passwordHash],
        );
        return true;
      });
      if (!ok) throw invalidToken();
    } catch (e) {
      // Email already registered: same answer as a bad token; the transaction rolled back.
      if ((e as { code?: string }).code === '23505') throw invalidToken();
      throw e;
    }
  }

  /**
   * Start a reset. Always resolves the same way whether or not the email has an active account.
   * Earlier unused reset tokens for the user are voided.
   */
  async requestReset(email: string): Promise<void> {
    const normalized = normalizeEmail(email);
    const user = await this.db.withLookup({ 'app.login_email': normalized }, async (c) => {
      const r = await c.query<{ id: string; institution_id: string | null; status: string }>(
        `SELECT id, institution_id, status FROM users WHERE email = $1`,
        [normalized],
      );
      return r.rows[0];
    });
    if (!user || user.status !== 'ACTIVE') return;

    const scope: Session = user.institution_id
      ? { kind: 'tenant', userId: user.id, institutionId: user.institution_id }
      : { kind: 'platform', userId: user.id };
    const token = newOneTimeToken();
    const expiresAt = await this.db.withTenant(scope, async (c) => {
      await c.query(
        `UPDATE password_resets SET used_at = now() WHERE user_id = $1 AND used_at IS NULL`,
        [user.id],
      );
      const r = await c.query<{ expires_at: Date }>(
        `INSERT INTO password_resets (id, institution_id, user_id, token_hash, expires_at)
         VALUES (gen_random_uuid(), $1, $2, $3, now() + make_interval(secs => $4))
         RETURNING expires_at`,
        [user.institution_id, user.id, hashOneTimeToken(token), this.ttl.resetSeconds],
      );
      return r.rows[0]!.expires_at;
    });
    try {
      await this.queue.enqueue({ kind: 'PASSWORD_RESET', to: normalized, token, expiresAt });
    } catch (err) {
      // Never let a queue failure change the response (it would reveal the account exists).
      this.log?.error({ err }, 'password reset mail enqueue failed');
    }
  }

  /** Redeem a reset token: set the password and delete every session of the user. */
  async confirmReset(token: string, password: string): Promise<void> {
    if (!TOKEN_RE.test(token)) throw invalidToken();
    checkPassword(password);
    const passwordHash = await hashPassword(password);
    const tokenHash = hashOneTimeToken(token);
    const ok = await this.db.withLookup({ 'app.reset_token_hash': tokenHash }, async (c) => {
      const r = await c.query<{ id: string; user_id: string; institution_id: string | null }>(
        `SELECT id, user_id, institution_id FROM password_resets
          WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()`,
        [tokenHash],
      );
      const reset = r.rows[0];
      if (!reset) return false;
      if (reset.institution_id) {
        await c.query(`SELECT set_config('app.institution_id', $1, true)`, [reset.institution_id]);
      } else {
        await c.query(`SELECT set_config('app.is_platform_admin', 'true', true)`);
      }
      const claimed = await c.query(
        `UPDATE password_resets SET used_at = now()
          WHERE id = $1 AND used_at IS NULL AND expires_at > now() RETURNING id`,
        [reset.id],
      );
      if (claimed.rowCount !== 1) return false;
      const u = await c.query<{ status: string; email: string }>(
        `SELECT status, email FROM users WHERE id = $1`,
        [reset.user_id],
      );
      const user = u.rows[0];
      if (!user || user.status !== 'ACTIVE') return false;
      await setPasswordAndKillSessions(c, reset.user_id, passwordHash);
      // Void any other outstanding reset tokens for this user.
      await c.query(
        `UPDATE password_resets SET used_at = now() WHERE user_id = $1 AND used_at IS NULL`,
        [reset.user_id],
      );
      return true;
    });
    if (!ok) throw invalidToken();
  }
}
