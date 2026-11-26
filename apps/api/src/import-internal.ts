// Internal, service-authenticated import endpoints for the batch worker (T-044, ADR 0034).
//
// The worker (apps/worker) never signs and never touches tenant tables for imports. It drives a batch through three
// calls and this module does every database write, through the SAME code as single issuance (issueInTransaction):
//   POST /internal/import/batches/:id/start        -> PROCESSING, row list (ids/flags only), source hashes
//   POST /internal/import/batches/:id/rows/:n      -> create/reuse holder, set photo, issue, mark the row (one transaction)
//   POST /internal/import/batches/:id/finish       -> totals from the rows, COMPLETED or FAILED, audit entry
//
// Authentication is a shared secret (INTERNAL_API_TOKEN, Bearer, constant-time compare), not a user session. The
// institution id arrives in the body because there is no session; it is only usable together with the secret, every
// query still runs in Db.withTenant (RLS) with an explicit app_institution_id() filter, and the batch must belong to
// that institution (else 404). The row's values come from import_rows.data (validated at intake), never from the body.
// The body carries only: institution id, an optional sanitised photo, or a fixed failure code.
//
// Nothing here logs tokens, salts, keys, names, addresses or photo bytes: ids, row numbers and codes only.
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import type { FastifyBaseLogger, FastifyInstance, FastifyRequest } from 'fastify';
import type { PoolClient } from 'pg';
import { appendAudit } from './audit.js';
import { enqueueCardAfterCommit } from './card-endpoints.js';
import type { ImportRowData } from './credential-import.js';
import { issueInTransaction } from './credentials.js';
import { isUuid, type Db, type TenantSession } from './db.js';
import { AppError, NotFoundError } from './errors.js';
import { enqueueDeliveryAfterCommit, type HolderDeliveryHook } from './holder-delivery.js';
import { sniffImage, stripMetadata } from './image.js';
import { assertInstitutionActive } from './institution-guard.js';
import type { CardRenderQueue } from './notifications.js';
import type { ObjectStorage } from './storage.js';

const sha256Hex = (b: Buffer | string): string => createHash('sha256').update(b).digest('hex');
const nfc = (s: string) => s.normalize('NFC');
const SHA256_HEX = /^[0-9a-f]{64}$/;

/** Failure codes the worker may record for a row (it found a problem before calling issuance). Fixed strings only. */
export const WORKER_ROW_FAILURES = new Set([
  'PHOTO_REQUIRED',
  'PHOTO_INVALID',
  'PHOTO_ARCHIVE_INVALID',
  'PHOTO_SOURCE_MISSING',
  'PHOTO_SOURCE_MISMATCH',
]);

export interface InternalImportOptions {
  db: Db;
  /** Shared secret. Without it these routes are not registered. */
  token: string;
  storage: ObjectStorage | undefined;
  masterKey: Buffer | undefined;
  maxPhotoBytes: number;
  cardRender?: CardRenderQueue | undefined;
  delivery?: HolderDeliveryHook | undefined;
  log: FastifyBaseLogger;
}

export type RowOutcome = 'IMPORTED' | 'ERROR';

const unauthorised = () => new AppError(401, 'UNAUTHORIZED', 'Authentication required');
const bad = (code: string, message: string) => new AppError(400, code, message);

function bodyObject(body: unknown, allowed: string[]): Record<string, unknown> {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw bad('BAD_REQUEST', 'Invalid request');
  const b = body as Record<string, unknown>;
  if (Object.keys(b).some((k) => !allowed.includes(k))) throw bad('UNKNOWN_PROPERTY', 'Unknown property');
  return b;
}

function scopeOf(b: Record<string, unknown>): string {
  if (!isUuid(b.institutionId)) throw bad('INVALID_INSTITUTION_ID', 'institutionId is required');
  return b.institutionId;
}

interface PhotoInput {
  sha256: string;
  bytes: Buffer;
}

/** The photo must be a well-formed, already metadata-free JPEG whose hash matches what the worker declared. */
function parsePhoto(v: unknown, maxBytes: number): PhotoInput {
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw bad('INVALID_PHOTO', 'Invalid photo');
  const p = v as Record<string, unknown>;
  if (Object.keys(p).some((k) => k !== 'sha256' && k !== 'data')) throw bad('INVALID_PHOTO', 'Invalid photo');
  if (typeof p.sha256 !== 'string' || !SHA256_HEX.test(p.sha256) || typeof p.data !== 'string') throw bad('INVALID_PHOTO', 'Invalid photo');
  if (p.data.length > Math.ceil((maxBytes * 4) / 3) + 8) throw bad('INVALID_PHOTO', 'Invalid photo');
  const bytes = Buffer.from(p.data, 'base64');
  if (bytes.length === 0 || bytes.length > maxBytes) throw bad('INVALID_PHOTO', 'Invalid photo');
  if (sniffImage(bytes) !== 'image/jpeg') throw bad('INVALID_PHOTO', 'Invalid photo');
  // The API re-walks the image (never trusts the worker): stripping must be a no-op and the hash must match the bytes.
  const stripped = stripMetadata(bytes, 'image/jpeg');
  if (!stripped || !stripped.equals(bytes)) throw bad('INVALID_PHOTO', 'Invalid photo');
  if (sha256Hex(bytes) !== p.sha256) throw bad('INVALID_PHOTO', 'Invalid photo');
  return { sha256: p.sha256, bytes };
}

interface BatchRow {
  id: string;
  status: string;
  created_by: string | null;
}

async function lockBatch(c: PoolClient, batchId: string): Promise<BatchRow> {
  const r = await c.query<BatchRow>(
    `SELECT id, status::text AS status, created_by FROM import_batches
      WHERE id = $1 AND institution_id = app_institution_id() FOR UPDATE`,
    [batchId],
  );
  if (!r.rows[0]) throw new NotFoundError();
  return r.rows[0];
}

async function refreshCounts(c: PoolClient, batchId: string): Promise<{ imported: number; error: number; pending: number }> {
  const r = await c.query<{ imported: number; error: number; pending: number }>(
    `SELECT count(*) FILTER (WHERE status = 'IMPORTED')::int AS imported,
            count(*) FILTER (WHERE status = 'ERROR')::int AS error,
            count(*) FILTER (WHERE status = 'PENDING')::int AS pending
       FROM import_rows WHERE batch_id = $1 AND institution_id = app_institution_id()`,
    [batchId],
  );
  const n = r.rows[0]!;
  await c.query(
    `UPDATE import_batches SET imported_rows = $2, error_rows = $3 WHERE id = $1 AND institution_id = app_institution_id()`,
    [batchId, n.imported, n.error],
  );
  return n;
}

export function registerInternalImport(app: FastifyInstance, o: InternalImportOptions): void {
  const expected = createHash('sha256').update(o.token).digest();
  const authenticate = async (req: FastifyRequest): Promise<void> => {
    const h = req.headers.authorization;
    const m = typeof h === 'string' ? /^Bearer (.+)$/.exec(h) : null;
    const given = createHash('sha256').update(m?.[1] ?? '').digest();
    if (!m || !timingSafeEqual(given, expected)) throw unauthorised();
  };
  const noStore = (reply: { header: (k: string, v: string) => unknown }) => void reply.header('Cache-Control', 'no-store');
  const batchParam = (req: FastifyRequest): string => {
    const id = (req.params as { id: string }).id;
    if (!isUuid(id)) throw new NotFoundError();
    return id;
  };
  const scope = (institutionId: string, userId: string | null): TenantSession => ({
    kind: 'tenant',
    userId: userId ?? '00000000-0000-4000-8000-000000000000',
    institutionId,
  });

  // The photo body can be up to ~1.4x the photo limit (base64); everything else is tiny.
  const rowBodyLimit = Math.ceil((o.maxPhotoBytes * 4) / 3) + 4096;

  void app.register(async (sub) => {
    sub.addHook('onRequest', authenticate);

    sub.post('/internal/import/batches/:id/start', async (req, reply) => {
      noStore(reply);
      const batchId = batchParam(req);
      const institutionId = scopeOf(bodyObject(req.body, ['institutionId']));
      return o.db.withTenant(scope(institutionId, null), async (c) => {
        const b = await lockBatch(c, batchId);
        if (b.status === 'COMPLETED' || b.status === 'FAILED') return { status: b.status, rows: [], sources: {} };
        if (b.status === 'PENDING') {
          await c.query(`UPDATE import_batches SET status = 'PROCESSING' WHERE id = $1 AND institution_id = app_institution_id()`, [batchId]);
        }
        const rows = await c.query<{ row_number: number; status: string; external_id: string; photo: string }>(
          `SELECT row_number, status::text AS status, data ->> 'externalId' AS external_id, data ->> 'photo' AS photo
             FROM import_rows WHERE batch_id = $1 AND institution_id = app_institution_id() ORDER BY row_number`,
          [batchId],
        );
        const au = await c.query<{ metadata: { csvSha256?: string; photosSha256?: string } }>(
          `SELECT metadata FROM audit_logs
            WHERE institution_id = app_institution_id() AND action = 'import.created' AND target_id = $1 LIMIT 1`,
          [batchId],
        );
        const md = au.rows[0]?.metadata ?? {};
        return {
          status: 'PROCESSING',
          rows: rows.rows.map((r) => ({ row: r.row_number, status: r.status, externalId: r.external_id, photo: r.photo })),
          sources: { ...(md.csvSha256 ? { csvSha256: md.csvSha256 } : {}), ...(md.photosSha256 ? { photosSha256: md.photosSha256 } : {}) },
        };
      });
    });

    sub.post('/internal/import/batches/:id/rows/:row', { bodyLimit: rowBodyLimit }, async (req, reply) => {
      noStore(reply);
      const batchId = batchParam(req);
      const rowNo = Number((req.params as { row: string }).row);
      if (!Number.isInteger(rowNo) || rowNo < 1 || rowNo > 100000) throw new NotFoundError();
      const body = bodyObject(req.body, ['institutionId', 'photo', 'fail']);
      const institutionId = scopeOf(body);
      let photo: PhotoInput | undefined;
      let fail: string | undefined;
      if (body.fail !== undefined) {
        if (typeof body.fail !== 'string' || !WORKER_ROW_FAILURES.has(body.fail)) throw bad('INVALID_FAILURE', 'Invalid failure code');
        fail = body.fail;
      }
      if (body.photo !== undefined) photo = parsePhoto(body.photo, o.maxPhotoBytes);
      if (fail && photo) throw bad('BAD_REQUEST', 'Invalid request');

      const result = await processRow(o, institutionId, batchId, rowNo, photo, fail);
      if (result.issued) {
        const s = scope(institutionId, result.createdBy);
        await enqueueCardAfterCommit(o.cardRender, o.log, { institutionId, credentialId: result.issued.id });
        await enqueueDeliveryAfterCommit(o.delivery, o.log, s, result.issued);
      }
      o.log.info(
        { event: 'import.row', institutionId, batchId, row: rowNo, outcome: result.outcome, ...(result.code ? { code: result.code } : {}) },
        'import row processed',
      );
      return { outcome: result.outcome, ...(result.code ? { code: result.code } : {}) };
    });

    sub.post('/internal/import/batches/:id/finish', async (req, reply) => {
      noStore(reply);
      const batchId = batchParam(req);
      const body = bodyObject(req.body, ['institutionId', 'outcome']);
      const institutionId = scopeOf(body);
      if (body.outcome !== 'complete' && body.outcome !== 'failed') throw bad('INVALID_OUTCOME', 'Invalid outcome');
      const outcome = body.outcome;
      const out = await o.db.withTenant(scope(institutionId, null), async (c) => {
        const b = await lockBatch(c, batchId);
        if (b.status === 'COMPLETED' || b.status === 'FAILED') {
          const n = await refreshCounts(c, batchId);
          return { status: b.status, ...n };
        }
        const n = await refreshCounts(c, batchId);
        if (outcome === 'complete' && n.pending > 0) throw new AppError(409, 'ROWS_PENDING', 'Some rows are still pending');
        const status = outcome === 'complete' ? 'COMPLETED' : 'FAILED';
        await c.query(
          `UPDATE import_batches SET status = $2::import_batch_status, completed_at = now() WHERE id = $1 AND institution_id = app_institution_id()`,
          [batchId, status],
        );
        await appendAudit(c, {
          institutionId,
          actorId: b.created_by,
          action: status === 'COMPLETED' ? 'import.completed' : 'import.failed',
          targetType: 'import_batch',
          targetId: batchId,
          metadata: { importedRows: n.imported, errorRows: n.error, pendingRows: n.pending },
        });
        return { status, ...n };
      });
      o.log.info({ event: 'import.finished', institutionId, batchId, status: out.status, imported: out.imported, errors: out.error }, 'import batch finished');
      return out;
    });
  });
}

interface RowResult {
  outcome: RowOutcome;
  code?: string;
  issued?: { id: string; holderId: string; holderToken: string };
  createdBy: string | null;
}

async function processRow(
  o: InternalImportOptions,
  institutionId: string,
  batchId: string,
  rowNo: number,
  photo: PhotoInput | undefined,
  fail: string | undefined,
): Promise<RowResult> {
  const tenant: TenantSession = { kind: 'tenant', userId: '00000000-0000-4000-8000-000000000000', institutionId };
  let createdBy: string | null = null;
  let putKey: string | null = null;
  let newHolder = false;
  let staleKey: string | null = null;
  let rowLoaded = false;

  const markError = async (code: string): Promise<RowResult> => {
    await o.db.withTenant(tenant, async (c) => {
      await lockBatch(c, batchId);
      await c.query(
        `UPDATE import_rows SET status = 'ERROR', error = $3
          WHERE batch_id = $1 AND row_number = $2 AND institution_id = app_institution_id() AND status = 'PENDING'`,
        [batchId, rowNo, code],
      );
      await refreshCounts(c, batchId);
    });
    return { outcome: 'ERROR', code, createdBy };
  };

  try {
    const res = await o.db.withTenant(tenant, async (c): Promise<RowResult> => {
      const batch = await lockBatch(c, batchId);
      createdBy = batch.created_by;
      const r = (
        await c.query<{ id: string; status: string; error: string | null; data: ImportRowData }>(
          `SELECT id, status::text AS status, error, data FROM import_rows
            WHERE batch_id = $1 AND row_number = $2 AND institution_id = app_institution_id() FOR UPDATE`,
          [batchId, rowNo],
        )
      ).rows[0];
      if (!r) throw new NotFoundError();
      rowLoaded = true;
      // Idempotent: a finished row is never processed twice (retries, duplicate calls).
      if (r.status === 'IMPORTED') return { outcome: 'IMPORTED', createdBy };
      if (r.status === 'ERROR') return { outcome: 'ERROR', ...(r.error ? { code: r.error } : {}), createdBy };
      if (batch.status !== 'PROCESSING') throw new AppError(409, 'BATCH_NOT_PROCESSING', 'The batch is not being processed');
      // Photo input is only valid for rows that declared a ZIP photo at intake.
      if ((photo || (fail && fail.startsWith('PHOTO_'))) && r.data.photo !== 'zip') {
        throw new AppError(422, 'PHOTO_NOT_EXPECTED', 'This row does not take a photo from the archive');
      }
      if (fail) throw new AppError(422, fail, 'Row failed before issuance');

      const data = r.data;
      await assertInstitutionActive(c);

      // Holder: reuse by external id (never overwrite identity data), else create.
      let holder = (
        await c.query<{ id: string; full_name: string; email: string | null; photo_sha256: string | null; photo_key: string | null }>(
          `SELECT id, full_name, email, photo_sha256, photo_key FROM credential_holders
            WHERE institution_id = app_institution_id() AND external_id = $1 FOR UPDATE`,
          [data.externalId],
        )
      ).rows[0];
      if (holder) {
        if (nfc(holder.full_name) !== nfc(data.fullName)) {
          throw new AppError(422, 'HOLDER_NAME_MISMATCH', 'A holder with this external id exists under a different name');
        }
        if (holder.email === null && data.email) {
          await c.query(
            `UPDATE credential_holders SET email = $2, updated_at = now() WHERE id = $1 AND institution_id = app_institution_id()`,
            [holder.id, data.email],
          );
        }
      } else {
        const id = randomUUID();
        await c.query(
          `INSERT INTO credential_holders (id, institution_id, full_name, external_id, email, updated_at)
           VALUES ($1, app_institution_id(), $2, $3, $4, now())`,
          [id, data.fullName, data.externalId, data.email],
        );
        await appendAudit(c, { institutionId, actorId: batch.created_by, action: 'holder.created', targetType: 'holder', targetId: id, metadata: { viaImport: batchId } });
        newHolder = true;
        holder = { id, full_name: data.fullName, email: data.email, photo_sha256: null, photo_key: null };
      }

      if (data.photo === 'zip' && !photo) throw new AppError(422, 'PHOTO_REQUIRED', 'No photo for this row');
      if (photo) {
        if (!o.storage) throw new AppError(503, 'STORAGE_UNAVAILABLE', 'File storage is not available');
        // Content-addressed key, same scheme as POST /holders/:id/photo; the hash is over exactly the stored bytes.
        const key = `institutions/${institutionId}/holders/${holder.id}/photo/${photo.sha256}.jpg`;
        await o.storage.put(key, photo.bytes, 'image/jpeg');
        putKey = key;
        if (holder.photo_key !== key) {
          await c.query(
            `UPDATE credential_holders SET photo_key = $2, photo_sha256 = $3, updated_at = now()
              WHERE id = $1 AND institution_id = app_institution_id()`,
            [holder.id, key, photo.sha256],
          );
          let deletable = holder.photo_key !== null;
          if (deletable && holder.photo_sha256) {
            const used = await c.query(
              `SELECT 1 FROM credentials WHERE holder_id = $1 AND institution_id = app_institution_id()
                 AND payload -> 'holder' ->> 'photoSha256' = $2 LIMIT 1`,
              [holder.id, holder.photo_sha256],
            );
            if (used.rowCount) deletable = false;
          }
          staleKey = deletable ? holder.photo_key : null;
          await appendAudit(c, {
            institutionId,
            actorId: batch.created_by,
            action: 'holder.photo_updated',
            targetType: 'holder',
            targetId: holder.id,
            metadata: { photoSha256: photo.sha256, previousPhotoSha256: holder.photo_sha256, viaImport: batchId },
          });
        }
      }

      const issued = await issueInTransaction(
        c,
        { institutionId, actorId: batch.created_by, masterKey: o.masterKey },
        {
          holderId: holder.id,
          credentialTypeCode: data.credentialType,
          attributes: data.attributes,
          ...(data.expiresAt ? { expiresAt: data.expiresAt } : {}),
        },
      );
      await c.query(
        `UPDATE import_rows SET status = 'IMPORTED', error = NULL, credential_id = $3
          WHERE id = $1 AND institution_id = app_institution_id() AND batch_id = $2`,
        [r.id, batchId, issued.id],
      );
      await refreshCounts(c, batchId);
      return { outcome: 'IMPORTED', issued: { id: issued.id, holderId: issued.holderId, holderToken: issued.holderToken }, createdBy };
    });
    if (staleKey && o.storage) await o.storage.delete(staleKey).catch(() => undefined);
    return res;
  } catch (e) {
    // A transaction that failed rolled back the holder too: drop a photo object that only that holder could use.
    if (newHolder && putKey && o.storage) await o.storage.delete(putKey).catch(() => undefined);
    // 4xx = a problem with this row: record it and carry on. Anything else (database, signing, storage) is transient
    // and bubbles up as an error so the worker retries the row later.
    // A 404 after the row was found means its credential type is gone: a row problem, not a missing row.
    if (e instanceof NotFoundError && rowLoaded) return markError('CREDENTIAL_TYPE_NOT_FOUND');
    if (e instanceof AppError && e.statusCode >= 400 && e.statusCode < 500 && e.statusCode !== 404 && e.statusCode !== 429) {
      if (e.code === 'BATCH_NOT_PROCESSING') throw e;
      return markError(e.code);
    }
    throw e;
  }
}
