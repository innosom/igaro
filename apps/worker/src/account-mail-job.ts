// Contract for account mail (invite, password reset) jobs. Shared by the producer (API) and the worker.
// This file must stay free of heavy imports (no nodemailer, no pg-boss) so the API can import the contract cheaply.
//
// SECURITY: the job carries the RAW one-time token because the email must contain it (ADR 0005 point 10).
// Nothing that touches a job may log the payload, the token or the recipient.

export const ACCOUNT_MAIL_QUEUE = 'account.mail';

export type AccountMailJob =
  | { kind: 'INVITE'; to: string; token: string; expiresAt: Date; institutionId: string }
  | { kind: 'PASSWORD_RESET'; to: string; token: string; expiresAt: Date };

export interface AccountMailQueue {
  enqueue(job: AccountMailJob): Promise<void>;
}

/** JSON form stored in the pg-boss job table (Dates become ISO strings). */
export type AccountMailJobData =
  | { kind: 'INVITE'; to: string; token: string; expiresAt: string; institutionId: string }
  | { kind: 'PASSWORD_RESET'; to: string; token: string; expiresAt: string };

export function toJobData(job: AccountMailJob): AccountMailJobData {
  const expiresAt = job.expiresAt.toISOString();
  return job.kind === 'INVITE'
    ? {
        kind: 'INVITE',
        to: job.to,
        token: job.token,
        expiresAt,
        institutionId: job.institutionId,
      }
    : { kind: 'PASSWORD_RESET', to: job.to, token: job.token, expiresAt };
}

/** Thrown for a malformed payload. Never carries the payload: a retry cannot fix it. */
export class InvalidAccountMailJobError extends Error {
  constructor() {
    super('invalid account mail job payload');
    this.name = 'InvalidAccountMailJobError';
  }
}

const isNonEmptyString = (v: unknown): v is string => typeof v === 'string' && v.length > 0;

/** Validate untrusted job data (the table could hold anything). Throws InvalidAccountMailJobError. */
export function parseAccountMailJobData(data: unknown): AccountMailJob {
  if (typeof data !== 'object' || data === null) throw new InvalidAccountMailJobError();
  const d = data as Record<string, unknown>;
  const { kind, to, token } = d;
  if (!isNonEmptyString(to) || !isNonEmptyString(token) || !isNonEmptyString(d.expiresAt)) {
    throw new InvalidAccountMailJobError();
  }
  // A recipient with CR/LF or a second address must never reach the SMTP layer.
  if (!/^[^\s@<>,;"]+@[^\s@<>,;"]+$/.test(to)) throw new InvalidAccountMailJobError();
  // Tokens are base64url; anything else could break the link.
  if (!/^[A-Za-z0-9_-]{16,256}$/.test(token)) throw new InvalidAccountMailJobError();
  const expiresAt = new Date(d.expiresAt);
  if (Number.isNaN(expiresAt.getTime())) throw new InvalidAccountMailJobError();
  if (kind === 'INVITE') {
    if (!isNonEmptyString(d.institutionId)) throw new InvalidAccountMailJobError();
    return { kind, to, token, expiresAt, institutionId: d.institutionId };
  }
  if (kind === 'PASSWORD_RESET') return { kind, to, token, expiresAt };
  throw new InvalidAccountMailJobError();
}
