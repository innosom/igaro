// Contract for account mail (invite, password reset) jobs. Shared by the producer (API) and the worker.
// This file must stay free of heavy imports (no nodemailer, no pg-boss) so the API can import the contract cheaply.
//
// SECURITY (ADR 0038, same scheme as ADR 0030): the email must contain the RAW one-time token, which the database
// keeps only as a hash (ADR 0002). The API therefore puts {to, token} in the job only as an AES-256-GCM sealed blob
// under DELIVERY_PAYLOAD_KEY, bound to the kind, the expiry, the institution and a random job reference (AAD). The
// pg-boss table, its backups and anyone able to read it never hold a usable token or address in clear.
// Nothing that touches a job may log the sealed blob, the token, the link or the recipient.
import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'node:crypto';

export const ACCOUNT_MAIL_QUEUE = 'account.mail';

export type AccountMailJob =
  | { kind: 'INVITE'; to: string; token: string; expiresAt: Date; institutionId: string }
  | { kind: 'PASSWORD_RESET'; to: string; token: string; expiresAt: Date };

export interface AccountMailQueue {
  enqueue(job: AccountMailJob): Promise<void>;
}

/**
 * JSON stored in the pg-boss job table. Nothing here is secret: `kind`, the expiry, the institution id and a random
 * reference are routing data; `to` and `token` exist only inside `sealed`.
 */
export type AccountMailJobData =
  | { kind: 'INVITE'; ref: string; expiresAt: string; institutionId: string; sealed: string }
  | { kind: 'PASSWORD_RESET'; ref: string; expiresAt: string; sealed: string };

/** Thrown for a malformed, tampered or wrongly keyed payload. Never carries the payload: a retry cannot fix it. */
export class InvalidAccountMailJobError extends Error {
  constructor() {
    super('invalid account mail job payload');
    this.name = 'InvalidAccountMailJobError';
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL = /^[^\s@<>,;"]+@[^\s@<>,;"]+$/;
// Tokens are base64url; anything else could break the link.
const TOKEN = /^[A-Za-z0-9_-]{16,256}$/;
const VERSION = 'v1';

const aadFor = (kind: string, institutionId: string | undefined, expiresAt: string, ref: string): Buffer =>
  Buffer.from(`igaro.account-mail.v1:${kind}:${institutionId ?? '-'}:${expiresAt}:${ref}`, 'utf8');

function assertKey(key: Buffer): void {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error('delivery payload key must be 32 bytes');
}

/** Validate then seal {to, token}. Format: v1.<iv>.<ciphertext>.<tag> (base64url). */
export function sealAccountMail(job: AccountMailJob, key: Buffer): AccountMailJobData {
  assertKey(key);
  if (!EMAIL.test(job.to) || job.to.length > 320 || !TOKEN.test(job.token)) throw new InvalidAccountMailJobError();
  if (job.kind === 'INVITE' && !UUID.test(job.institutionId)) throw new InvalidAccountMailJobError();
  if (Number.isNaN(job.expiresAt.getTime())) throw new InvalidAccountMailJobError();
  const expiresAt = job.expiresAt.toISOString();
  const ref = randomUUID();
  const institutionId = job.kind === 'INVITE' ? job.institutionId : undefined;
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(aadFor(job.kind, institutionId, expiresAt, ref));
  const ct = Buffer.concat([c.update(JSON.stringify({ to: job.to, token: job.token }), 'utf8'), c.final()]);
  const sealed = [VERSION, iv.toString('base64url'), ct.toString('base64url'), c.getAuthTag().toString('base64url')].join('.');
  return job.kind === 'INVITE'
    ? { kind: 'INVITE', ref, expiresAt, institutionId: job.institutionId, sealed }
    : { kind: 'PASSWORD_RESET', ref, expiresAt, sealed };
}

/**
 * Validate untrusted job data (the table could hold anything) and open it. Any failure (shape, key, tampering, moved
 * fields, an old clear-text job from before ADR 0038) throws the same generic error.
 */
export function openAccountMailJobData(data: unknown, key: Buffer): AccountMailJob {
  assertKey(key);
  if (typeof data !== 'object' || data === null) throw new InvalidAccountMailJobError();
  const d = data as Record<string, unknown>;
  const { kind } = d;
  if (kind !== 'INVITE' && kind !== 'PASSWORD_RESET') throw new InvalidAccountMailJobError();
  if (typeof d.ref !== 'string' || !UUID.test(d.ref)) throw new InvalidAccountMailJobError();
  if (typeof d.expiresAt !== 'string' || typeof d.sealed !== 'string' || d.sealed.length > 2048) {
    throw new InvalidAccountMailJobError();
  }
  const expiresAt = new Date(d.expiresAt);
  if (Number.isNaN(expiresAt.getTime()) || expiresAt.toISOString() !== d.expiresAt) throw new InvalidAccountMailJobError();
  let institutionId: string | undefined;
  if (kind === 'INVITE') {
    if (typeof d.institutionId !== 'string' || !UUID.test(d.institutionId)) throw new InvalidAccountMailJobError();
    institutionId = d.institutionId;
  }
  const parts = d.sealed.split('.');
  if (parts.length !== 4 || parts[0] !== VERSION) throw new InvalidAccountMailJobError();
  try {
    const iv = Buffer.from(parts[1]!, 'base64url');
    const ct = Buffer.from(parts[2]!, 'base64url');
    const tag = Buffer.from(parts[3]!, 'base64url');
    if (iv.length !== 12 || tag.length !== 16) throw new Error('shape');
    const dec = createDecipheriv('aes-256-gcm', key, iv);
    dec.setAAD(aadFor(kind, institutionId, d.expiresAt, d.ref));
    dec.setAuthTag(tag);
    const plain = JSON.parse(Buffer.concat([dec.update(ct), dec.final()]).toString('utf8')) as Record<string, unknown>;
    if (typeof plain.to !== 'string' || !EMAIL.test(plain.to) || typeof plain.token !== 'string' || !TOKEN.test(plain.token)) {
      throw new Error('content');
    }
    return kind === 'INVITE'
      ? { kind, to: plain.to, token: plain.token, expiresAt, institutionId: institutionId as string }
      : { kind, to: plain.to, token: plain.token, expiresAt };
  } catch {
    throw new InvalidAccountMailJobError();
  }
}
