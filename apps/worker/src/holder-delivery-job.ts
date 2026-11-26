// Contract for email.deliver (T-041, ADR 0030). Shared by the producer (API) and the worker.
// Free of heavy imports on purpose (node:crypto only).
//
// SECURITY: the holder email must contain the RAW holder token, which the database keeps only as a hash (ADR 0002).
// So the API puts {to, holderToken} in the job, but only as an AES-256-GCM sealed blob under DELIVERY_PAYLOAD_KEY,
// bound to the institution and credential ids (AAD). The pg-boss table therefore never holds a usable token or
// address in clear. Nothing that touches a job may log the sealed blob, the token, the link or the recipient.
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

export const HOLDER_DELIVERY_QUEUE = 'email.deliver';

export interface HolderDeliveryJob {
  institutionId: string;
  credentialId: string;
  /** Recipient: the holder's email. */
  to: string;
  /** Raw holder token for the /h/<token> link. */
  holderToken: string;
}

/** What the API calls after a credential commits. A queued duplicate is a no-op, not an error. */
export interface HolderDeliveryQueue {
  enqueue(job: HolderDeliveryJob): Promise<void>;
}

/**
 * Short life, nothing lingers: finished AND failed jobs are deleted after 60 s (0 would mean "keep forever").
 * 'short' policy + singletonKey: at most one queued delivery per credential. Retries use exponential backoff.
 */
export const HOLDER_DELIVERY_QUEUE_OPTIONS = {
  policy: 'short',
  retryLimit: 5,
  retryDelay: 30,
  retryBackoff: true,
  expireInSeconds: 120,
  // A job that never starts is dropped (with its sealed token) after 24 h.
  retentionSeconds: 24 * 3600,
  deleteAfterSeconds: 60,
} as const;

/** One pending delivery per credential. */
export const holderDeliverySingletonKey = (credentialId: string): string => `email.deliver:${credentialId}`;

export class InvalidHolderDeliveryJobError extends Error {
  constructor() {
    super('invalid holder delivery job payload');
    this.name = 'InvalidHolderDeliveryJobError';
  }
}

/** JSON stored in the pg-boss job table. Ids are not secret; `sealed` is. */
export interface HolderDeliveryJobData {
  institutionId: string;
  credentialId: string;
  sealed: string;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL = /^[^\s@<>,;"]+@[^\s@<>,;"]+$/;
const HOLDER_TOKEN = /^[A-Za-z0-9_-]{22}$/;
const VERSION = 'v1';

const aadFor = (institutionId: string, credentialId: string): Buffer =>
  Buffer.from(`igaro.holder-delivery.v1:${institutionId}:${credentialId}`, 'utf8');

function assertKey(key: Buffer): void {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error('delivery payload key must be 32 bytes');
}

/** Validate then seal {to, holderToken}. Format: v1.<iv>.<ciphertext>.<tag> (base64url). */
export function sealHolderDelivery(job: HolderDeliveryJob, key: Buffer): HolderDeliveryJobData {
  assertKey(key);
  if (!UUID.test(job.institutionId) || !UUID.test(job.credentialId)) throw new InvalidHolderDeliveryJobError();
  if (!EMAIL.test(job.to) || job.to.length > 320 || !HOLDER_TOKEN.test(job.holderToken)) {
    throw new InvalidHolderDeliveryJobError();
  }
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(aadFor(job.institutionId, job.credentialId));
  const ct = Buffer.concat([c.update(JSON.stringify({ to: job.to, holderToken: job.holderToken }), 'utf8'), c.final()]);
  const sealed = [VERSION, iv.toString('base64url'), ct.toString('base64url'), c.getAuthTag().toString('base64url')].join('.');
  return { institutionId: job.institutionId, credentialId: job.credentialId, sealed };
}

/** Validate untrusted job data and open it. Any failure (shape, key, tampering, wrong ids) throws the same generic error. */
export function openHolderDelivery(data: unknown, key: Buffer): HolderDeliveryJob {
  assertKey(key);
  if (typeof data !== 'object' || data === null) throw new InvalidHolderDeliveryJobError();
  const d = data as Record<string, unknown>;
  if (typeof d.institutionId !== 'string' || !UUID.test(d.institutionId)) throw new InvalidHolderDeliveryJobError();
  if (typeof d.credentialId !== 'string' || !UUID.test(d.credentialId)) throw new InvalidHolderDeliveryJobError();
  if (typeof d.sealed !== 'string' || d.sealed.length > 2048) throw new InvalidHolderDeliveryJobError();
  const parts = d.sealed.split('.');
  if (parts.length !== 4 || parts[0] !== VERSION) throw new InvalidHolderDeliveryJobError();
  try {
    const iv = Buffer.from(parts[1]!, 'base64url');
    const ct = Buffer.from(parts[2]!, 'base64url');
    const tag = Buffer.from(parts[3]!, 'base64url');
    if (iv.length !== 12 || tag.length !== 16) throw new Error('shape');
    const dec = createDecipheriv('aes-256-gcm', key, iv);
    dec.setAAD(aadFor(d.institutionId, d.credentialId));
    dec.setAuthTag(tag);
    const plain = JSON.parse(Buffer.concat([dec.update(ct), dec.final()]).toString('utf8')) as Record<string, unknown>;
    if (typeof plain.to !== 'string' || !EMAIL.test(plain.to) || typeof plain.holderToken !== 'string' || !HOLDER_TOKEN.test(plain.holderToken)) {
      throw new Error('content');
    }
    return { institutionId: d.institutionId, credentialId: d.credentialId, to: plain.to, holderToken: plain.holderToken };
  } catch {
    throw new InvalidHolderDeliveryJobError();
  }
}

/** pg-boss-like sender (API side). Returns false when a delivery is already queued for this credential. */
export interface HolderDeliverySender {
  send(name: string, data: object, options: Record<string, unknown>): Promise<string | null>;
}

export async function enqueueHolderDelivery(boss: HolderDeliverySender, job: HolderDeliveryJob, key: Buffer): Promise<boolean> {
  const id = await boss.send(HOLDER_DELIVERY_QUEUE, sealHolderDelivery(job, key), {
    singletonKey: holderDeliverySingletonKey(job.credentialId),
  });
  return id !== null;
}
