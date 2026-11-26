// Rendering and handling of account mail jobs (INVITE, PASSWORD_RESET).
// Never log the job, the token, the link or the recipient. Errors thrown from here are stored by
// pg-boss as the job output, so they are generic and carry no payload or SMTP response text.
import type { Transporter } from 'nodemailer';
import {
  parseAccountMailJobData,
  type AccountMailJob,
} from './account-mail-job.js';

export interface RenderedMail {
  subject: string;
  text: string;
  html: string;
}

export const escapeHtml = (s: string): string =>
  s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

/**
 * The token goes in the URL fragment: browsers never send it to the server, so it stays out of web
 * server logs and Referer headers. The web app (T-0xx) reads it client-side and POSTs it as JSON.
 */
export function buildLink(webBaseUrl: string, job: AccountMailJob): string {
  const path = job.kind === 'INVITE' ? '/invite/accept' : '/password-reset';
  return `${webBaseUrl.replace(/\/+$/, '')}${path}#token=${job.token}`;
}

export function renderAccountMail(job: AccountMailJob, webBaseUrl: string): RenderedMail {
  const link = buildLink(webBaseUrl, job);
  const when = job.expiresAt.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
  const safeLink = escapeHtml(link);
  if (job.kind === 'INVITE') {
    return {
      subject: 'You have been invited to iGARO',
      text: [
        'You have been invited to administer an institution on iGARO.',
        '',
        'Set your password and activate your account:',
        link,
        '',
        `This link works once and expires at ${when}.`,
        'If you did not expect this invitation, ignore this email.',
      ].join('\n'),
      html: [
        '<p>You have been invited to administer an institution on iGARO.</p>',
        `<p><a href="${safeLink}">Set your password and activate your account</a></p>`,
        `<p>This link works once and expires at ${escapeHtml(when)}.</p>`,
        '<p>If you did not expect this invitation, ignore this email.</p>',
      ].join('\n'),
    };
  }
  return {
    subject: 'Reset your iGARO password',
    text: [
      'We received a request to reset your iGARO password.',
      '',
      'Choose a new password:',
      link,
      '',
      `This link works once and expires at ${when}.`,
      'If you did not ask for this, ignore this email; your password is unchanged.',
    ].join('\n'),
    html: [
      '<p>We received a request to reset your iGARO password.</p>',
      `<p><a href="${safeLink}">Choose a new password</a></p>`,
      `<p>This link works once and expires at ${escapeHtml(when)}.</p>`,
      '<p>If you did not ask for this, ignore this email; your password is unchanged.</p>',
    ].join('\n'),
  };
}

export type AccountMailOutcome = 'sent' | 'skipped_expired';

export interface AccountMailHandlerDeps {
  transport: Pick<Transporter, 'sendMail'>;
  from: string;
  webBaseUrl: string;
  now?: () => Date;
}

/** Thrown when SMTP fails: retryable, and deliberately message-free (SMTP errors can echo the recipient). */
export class MailSendError extends Error {
  constructor() {
    super('smtp send failed');
    this.name = 'MailSendError';
  }
}

export function createAccountMailHandler(deps: AccountMailHandlerDeps) {
  const now = deps.now ?? (() => new Date());
  return async function handle(data: unknown): Promise<AccountMailOutcome> {
    const job = parseAccountMailJobData(data);
    // An expired token is useless; sending it would only confuse the recipient.
    if (job.expiresAt.getTime() <= now().getTime()) return 'skipped_expired';
    const mail = renderAccountMail(job, deps.webBaseUrl);
    try {
      await deps.transport.sendMail({
        from: deps.from,
        to: job.to,
        subject: mail.subject,
        text: mail.text,
        html: mail.html,
      });
    } catch {
      throw new MailSendError();
    }
    return 'sent';
  };
}
