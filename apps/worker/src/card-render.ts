// card.render (T-039, ADR 0028). Reads one credential inside one tenant's RLS scope, builds the card from
// the SIGNED payload (name, id number, dates, attributes) plus the institution's branding, accepts the holder
// photo only if SHA-256(stored bytes) equals payload.holder.photoSha256, renders PNG and PDF with headless
// Chrome and writes both to private storage under institutions/<institution>/credentials/<credential>/.
//
// The worker never signs and never touches key material: the credential columns it can read exclude the
// signature, hash and holder token hash (migration 20261127000000). Logs carry ids and outcomes only.
import { createHash } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import type { Logger } from 'pino';
import puppeteer, { type Browser } from 'puppeteer-core';
import { cardStorageKeys, parseCardRenderJobData, type CardRenderJob } from './card-render-job.js';
import type { WorkerObjectStorage } from './card-storage.js';
import { CARD_SIZE, renderCardHtml, sniffImage, type CardImage, type CardKind, type CardModel } from './card-template.js';

const PHOTO_MAX_BYTES = 10 * 1024 * 1024;
const LOGO_MAX_BYTES = 2 * 1024 * 1024;

export interface RenderedCard {
  png: Buffer;
  pdf: Buffer;
  /** Requests the page tried to make that were aborted (anything that is not a data: URL). */
  blockedRequests: number;
}

export interface CardRenderer {
  render(html: string, kind: CardKind): Promise<RenderedCard>;
}

export interface ChromeOptions {
  /** Absolute path to the Chrome/Chromium executable (env CHROME_PATH). */
  executablePath: string;
  /** Needed in some containers (no user namespaces). Off by default (env CHROME_NO_SANDBOX=true). */
  noSandbox?: boolean;
  timeoutMs?: number;
}

/** One short-lived browser per job: no state is shared between credentials or tenants. */
export class ChromeCardRenderer implements CardRenderer {
  constructor(private readonly opts: ChromeOptions) {}

  async render(html: string, kind: CardKind): Promise<RenderedCard> {
    const timeout = this.opts.timeoutMs ?? 30_000;
    const { width, height } = CARD_SIZE[kind];
    let browser: Browser | undefined;
    try {
      browser = await puppeteer.launch({
        executablePath: this.opts.executablePath,
        headless: true,
        timeout,
        args: [
          '--disable-gpu',
          '--disable-dev-shm-usage',
          '--disable-extensions',
          '--no-first-run',
          '--no-default-browser-check',
          '--disable-background-networking',
          // Defence in depth: nothing resolves, in addition to request interception below.
          '--host-resolver-rules=MAP * ~NOTFOUND',
          ...(this.opts.noSandbox ? ['--no-sandbox'] : []),
        ],
      });
      const page = await browser.newPage();
      page.setDefaultTimeout(timeout);
      await page.setJavaScriptEnabled(false);
      await page.setViewport({ width, height, deviceScaleFactor: 2 });
      let blocked = 0;
      await page.setRequestInterception(true);
      page.on('request', (req) => {
        const u = req.url();
        if (u.startsWith('data:') || u === 'about:blank') void req.continue();
        else {
          blocked += 1;
          void req.abort('blockedbyclient');
        }
      });
      await page.setContent(html, { waitUntil: 'load', timeout });
      const png = Buffer.from(await page.screenshot({ type: 'png', clip: { x: 0, y: 0, width, height } }));
      const pdf = Buffer.from(
        await page.pdf({ width: `${width}px`, height: `${height}px`, printBackground: true, pageRanges: '1', margin: { top: 0, right: 0, bottom: 0, left: 0 } }),
      );
      return { png, pdf, blockedRequests: blocked };
    } finally {
      await browser?.close().catch(() => undefined);
    }
  }
}

export interface CardRenderDeps {
  pool: Pool;
  storage: WorkerObjectStorage;
  renderer: CardRenderer;
  /** Public base URL of the verification site, no trailing slash (VERIFY_BASE_URL). */
  verifyBaseUrl: string;
  logger: Logger;
  /** Tests connect as the owner and switch with SET LOCAL ROLE. Production connects as igaro_worker. */
  assumeRole?: string;
}

export type CardRenderOutcome = 'rendered' | 'skipped_not_active';

export class CardRenderNotFoundError extends Error {
  constructor() {
    super('credential not found for card render');
    this.name = 'CardRenderNotFoundError';
  }
}

interface Row {
  credential_number: string;
  status: string;
  payload: unknown;
  verification_token: string;
  type_name: string;
  kind: CardKind;
  photo_key: string | null;
  inst_name: string;
  logo_key: string | null;
  primary_color: string;
  secondary_color: string;
  card_title: string | null;
}

async function inTenantScope<T>(deps: CardRenderDeps, institutionId: string, fn: (c: PoolClient) => Promise<T>): Promise<T> {
  const c = await deps.pool.connect();
  try {
    await c.query('BEGIN');
    if (deps.assumeRole) {
      if (!/^[a-z_][a-z0-9_]*$/.test(deps.assumeRole)) throw new Error('invalid role name');
      await c.query(`SET LOCAL ROLE ${deps.assumeRole}`);
    }
    // Tenancy comes from the job's institution_id; RLS then hides every other tenant's rows.
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

const SHA256_HEX = /^[0-9a-f]{64}$/;
const isStr = (v: unknown): v is string => typeof v === 'string';

interface SignedView {
  holderName: string;
  idNumber: string | null;
  photoSha256: string;
  credentialNumber: string;
  issuedAt: string | null;
  expiresAt: string | null;
  attributes: Record<string, string>;
}

/** Read display fields from the signed payload. Structural checks only; the signature is the API's business. */
export function readSignedView(payload: unknown, job: CardRenderJob): SignedView {
  const p = payload as Record<string, unknown> | null;
  const h = (p?.holder ?? null) as Record<string, unknown> | null;
  if (
    !p || typeof p !== 'object' || !h || typeof h !== 'object' ||
    p.credentialId !== job.credentialId || p.institutionId !== job.institutionId ||
    !isStr(h.fullName) || !isStr(p.credentialNumber) || !isStr(h.photoSha256)
  ) {
    throw new CardRenderNotFoundError();
  }
  const attributes: Record<string, string> = {};
  if (p.attributes && typeof p.attributes === 'object') {
    for (const [k, v] of Object.entries(p.attributes as Record<string, unknown>)) if (isStr(v)) attributes[k] = v;
  }
  return {
    holderName: h.fullName,
    idNumber: isStr(h.externalId) ? h.externalId : null,
    photoSha256: h.photoSha256.toLowerCase(),
    credentialNumber: p.credentialNumber,
    issuedAt: isStr(p.issuedAt) ? p.issuedAt : null,
    expiresAt: isStr(p.expiresAt) ? p.expiresAt : null,
    attributes,
  };
}

/** Accept the stored photo only if its bytes hash to the value the institution signed. */
export function photoIfHashMatches(bytes: Buffer | null, expectedSha256: string): CardImage | null {
  if (!bytes || !SHA256_HEX.test(expectedSha256)) return null;
  if (createHash('sha256').update(bytes).digest('hex') !== expectedSha256) return null;
  const mime = sniffImage(bytes);
  return mime ? { mime, bytes } : null;
}

export function logoIfImage(bytes: Buffer | null): CardImage | null {
  if (!bytes) return null;
  const mime = sniffImage(bytes);
  return mime ? { mime, bytes } : null;
}

export async function runCardRender(deps: CardRenderDeps, data: unknown): Promise<CardRenderOutcome> {
  const job = parseCardRenderJobData(data);
  const { logger } = deps;

  const row = await inTenantScope(deps, job.institutionId, async (c) => {
    const r = await c.query<Row>(
      `SELECT c.credential_number, c.status, c.payload, c.verification_token,
              t.name AS type_name, t.kind, h.photo_key,
              i.name AS inst_name, i.logo_key, i.primary_color, i.secondary_color, i.card_title
         FROM credentials c
         JOIN credential_holders h ON h.institution_id = c.institution_id AND h.id = c.holder_id
         JOIN credential_types t ON t.institution_id = c.institution_id AND t.id = c.type_id
         JOIN institutions i ON i.id = c.institution_id
        WHERE c.id = $1 AND c.institution_id = $2`,
      [job.credentialId, job.institutionId],
    );
    return r.rows[0];
  });
  if (!row) throw new CardRenderNotFoundError();
  if (row.status !== 'ACTIVE') {
    logger.info({ institutionId: job.institutionId, credentialId: job.credentialId, status: row.status }, 'card render skipped');
    return 'skipped_not_active';
  }

  const view = readSignedView(row.payload, job);
  const photoBytes = row.photo_key ? await deps.storage.get(row.photo_key, PHOTO_MAX_BYTES) : null;
  const photo = photoIfHashMatches(photoBytes, view.photoSha256);
  if (!photo) {
    // Old credential whose holder photo was replaced, missing object or tampering: render without a photo.
    logger.warn({ institutionId: job.institutionId, credentialId: job.credentialId, photo: 'omitted' }, 'card photo omitted');
  }
  const logo = logoIfImage(row.logo_key && row.logo_key.startsWith(`institutions/${job.institutionId}/logo/`)
      ? await deps.storage.get(row.logo_key, LOGO_MAX_BYTES)
      : null);

  const model: CardModel = {
    kind: row.kind,
    institutionName: row.inst_name,
    cardTitle: row.card_title,
    primaryColor: row.primary_color,
    secondaryColor: row.secondary_color,
    logo,
    photo,
    holderName: view.holderName,
    idNumber: view.idNumber,
    credentialTypeName: row.type_name,
    credentialNumber: view.credentialNumber,
    issuedAt: view.issuedAt,
    expiresAt: view.expiresAt,
    attributes: view.attributes,
    verifyUrl: `${deps.verifyBaseUrl.replace(/\/+$/, '')}/v/${row.verification_token}`,
  };
  const rendered = await deps.renderer.render(renderCardHtml(model), row.kind);

  const keys = cardStorageKeys(job.institutionId, job.credentialId);
  await deps.storage.put(keys.png, rendered.png, 'image/png');
  await deps.storage.put(keys.pdf, rendered.pdf, 'application/pdf');
  logger.info(
    { institutionId: job.institutionId, credentialId: job.credentialId, photo: photo ? 'used' : 'omitted', blockedRequests: rendered.blockedRequests },
    'card rendered',
  );
  return 'rendered';
}
