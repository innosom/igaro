// email.deliver (T-041, ADR 0030). Opens the sealed job, checks the credential is still ACTIVE inside the job's
// tenant scope (RLS, column grants of igaro_worker), and emails the holder a private /h/<holderToken> link.
// The worker never signs and never holds key material. Never log the job, token, link or recipient. Errors thrown
// from here are stored by pg-boss as job output, so they are generic.
import type { Pool, PoolClient } from 'pg';
import type { Logger } from 'pino';
import type { Transporter } from 'nodemailer';
import { escapeHtml, MailSendError, type RenderedMail } from './account-mail.js';
import { openHolderDelivery } from './holder-delivery-job.js';

export interface HolderDeliveryDeps {
  pool: Pool;
  transport: Pick<Transporter, 'sendMail'>;
  from: string;
  /** Public web base URL, no trailing slash (WEB_BASE_URL). */
  webBaseUrl: string;
  /** 32-byte DELIVERY_PAYLOAD_KEY. */
  key: Buffer;
  logger: Logger;
  /** Tests connect as the owner and switch with SET LOCAL ROLE. Production connects as igaro_worker. */
  assumeRole?: string;
}

export type HolderDeliveryOutcome = 'sent' | 'skipped_not_active';

export class HolderDeliveryNotFoundError extends Error {
  constructor() {
    super('credential not found for holder delivery');
    this.name = 'HolderDeliveryNotFoundError';
  }
}

interface Row {
  status: string;
  payload: unknown;
  type_name: string;
  inst_name: string;
}

async function inTenantScope<T>(deps: HolderDeliveryDeps, institutionId: string, fn: (c: PoolClient) => Promise<T>): Promise<T> {
  const c = await deps.pool.connect();
  try {
    await c.query('BEGIN');
    if (deps.assumeRole) {
      if (!/^[a-z_][a-z0-9_]*$/.test(deps.assumeRole)) throw new Error('invalid role name');
      await c.query(`SET LOCAL ROLE ${deps.assumeRole}`);
    }
    await c.query(`SELECT set_config('app.institution_id', $1, true)`, [institutionId]);
    const out = await fn(c);
    await c.query('COMMIT');
    return out;
  } catch (e) {
    await c.query('ROLLBACK').catch(() => undefined);
    throw e;
  } finally {
    c.release();
  }
}

/** Remove control, bidi and zero-width characters (a subject must not carry CR/LF or spoof direction). */
const cp = (n: number): string => String.fromCodePoint(n);
const UNSAFE_TEXT = new RegExp(
  `[${cp(0)}-${cp(0x1f)}${cp(0x7f)}-${cp(0x9f)}${cp(0x200b)}-${cp(0x200f)}${cp(0x202a)}-${cp(0x202e)}${cp(0x2066)}-${cp(0x2069)}${cp(0xfeff)}]`,
  'g',
);
const clean = (s: string): string => s.replace(UNSAFE_TEXT, ' ').trim();

export function holderLink(webBaseUrl: string, holderToken: string): string {
  return `${webBaseUrl.replace(/\/+$/, '')}/h/${holderToken}`;
}

export function renderHolderMail(v: { holderName: string; typeName: string; institutionName: string; link: string }): RenderedMail {
  const inst = clean(v.institutionName) || 'your institution';
  const type = clean(v.typeName) || 'credential';
  const name = clean(v.holderName);
  const safeLink = escapeHtml(v.link);
  return {
    subject: `Your ${type} from ${inst}`.slice(0, 200),
    text: [
      name ? `Hello ${name},` : 'Hello,',
      '',
      `${inst} has issued you a digital credential (${type}).`,
      'Open your private page to view and download your card and your signed credential file:',
      v.link,
      '',
      'Keep this link private: anyone who has it can open your page.',
      'To check a credential, use only the verification page it points to (verify.igaro.app).',
      'If you did not expect this email, you can ignore it.',
    ].join('\n'),
    html: [
      `<p>${name ? `Hello ${escapeHtml(name)},` : 'Hello,'}</p>`,
      `<p>${escapeHtml(inst)} has issued you a digital credential (${escapeHtml(type)}).</p>`,
      `<p><a href="${safeLink}">View and download your card and signed credential file</a></p>`,
      '<p>Keep this link private: anyone who has it can open your page.</p>',
      '<p>To check a credential, use only the verification page it points to (verify.igaro.app).</p>',
      '<p>If you did not expect this email, you can ignore it.</p>',
    ].join('\n'),
  };
}

export async function runHolderDelivery(deps: HolderDeliveryDeps, data: unknown): Promise<HolderDeliveryOutcome> {
  const job = openHolderDelivery(data, deps.key);
  const row = await inTenantScope(deps, job.institutionId, async (c) => {
    const r = await c.query<Row>(
      `SELECT c.status, c.payload, t.name AS type_name, i.name AS inst_name
         FROM credentials c
         JOIN credential_types t ON t.institution_id = c.institution_id AND t.id = c.type_id
         JOIN institutions i ON i.id = c.institution_id
        WHERE c.id = $1 AND c.institution_id = $2`,
      [job.credentialId, job.institutionId],
    );
    return r.rows[0];
  });
  // Enqueue happens after commit, but a missing row is retried rather than dropped (odd ordering).
  if (!row) throw new HolderDeliveryNotFoundError();
  // A revoked, suspended or superseded credential must not get a fresh "here is your card" mail.
  if (row.status !== 'ACTIVE') {
    deps.logger.info({ institutionId: job.institutionId, credentialId: job.credentialId, status: row.status }, 'holder delivery skipped');
    return 'skipped_not_active';
  }
  const p = row.payload as { holder?: { fullName?: unknown } } | null;
  const holderName = typeof p?.holder?.fullName === 'string' ? p.holder.fullName : '';
  const mail = renderHolderMail({
    holderName,
    typeName: row.type_name,
    institutionName: row.inst_name,
    link: holderLink(deps.webBaseUrl, job.holderToken),
  });
  try {
    await deps.transport.sendMail({ from: deps.from, to: job.to, subject: mail.subject, text: mail.text, html: mail.html });
  } catch {
    throw new MailSendError();
  }
  deps.logger.info({ institutionId: job.institutionId, credentialId: job.credentialId }, 'holder delivery sent');
  return 'sent';
}
