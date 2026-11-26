// Routes for credential import intake (T-043, ADR 0033). See credential-import.ts for the validation rules.
import { createHash, randomUUID } from 'node:crypto';
import multipart from '@fastify/multipart';
import type { FastifyBaseLogger, FastifyInstance, FastifyRequest } from 'fastify';
import type { PoolClient } from 'pg';
import { importStorageKeys } from '@igaro/worker/producer';
import { appendAudit } from './audit.js';
import type { AuthSession } from './auth.js';
import {
  DEFAULT_IMPORT_LIMITS,
  DEFAULT_IMPORT_RATE_LIMIT,
  fileError,
  validateRows,
  type ExistingHolder,
  type ImportLimits,
  type ImportRateLimit,
  type ImportRowData,
  type Preview,
  type TypeInfo,
} from './credential-import.js';
import { parseAttributes, type AttributeDef } from './credential-types.js';
import { BAD_TEXT_RE } from './credentials.js';
import { isUuid, type Db, type TenantSession } from './db.js';
import { AppError, NotFoundError, RateLimitedError } from './errors.js';
import { sniffImage, stripMetadata } from './image.js';
import { CsvError, decodeCsv, parseCsv } from './import-csv.js';
import { readZip, ZipError, type ZipEntry } from './import-zip.js';
import { assertInstitutionActive } from './institution-guard.js';
import type { ImportBatchQueue } from './notifications.js';
import { RateLimiter } from './rate-limit.js';
import type { ObjectStorage } from './storage.js';

const tenantScope = (req: FastifyRequest): TenantSession => {
  const s: AuthSession | null = req.session;
  if (!s || s.kind !== 'tenant') throw new AppError(403, 'FORBIDDEN', 'Insufficient role');
  return { kind: 'tenant', userId: s.userId, institutionId: s.institutionId };
};

const sha256 = (b: Buffer): string => createHash('sha256').update(b).digest('hex');
const nfc = (s: string) => s.normalize('NFC');
const JPEG_NAME = /^(.+)\.(?:jpe?g)$/i;
const BAD_TEXT_G = new RegExp(BAD_TEXT_RE.source, 'gu');

const cleanFilename = (v: unknown): string | null => {
  if (typeof v !== 'string') return null;
  const base = v.split(/[\\/]/).pop() ?? '';
  const t = base.replace(BAD_TEXT_G, '').trim().slice(0, 100);
  return t === '' ? null : t;
};

export interface ImportRoutesOptions {
  db: Db;
  storage: ObjectStorage | undefined;
  queue: ImportBatchQueue | undefined;
  limits?: Partial<ImportLimits> | undefined;
  rateLimit?: ImportRateLimit | undefined;
  log: FastifyBaseLogger;
  hashIp?: (ip: string | undefined) => string | undefined;
}

interface Upload {
  csv: Buffer;
  csvName: string | null;
  zip: Buffer | null;
}

export function registerCredentialImport(app: FastifyInstance, o: ImportRoutesOptions): void {
  const limits: ImportLimits = { ...DEFAULT_IMPORT_LIMITS, ...o.limits };
  const rl = o.rateLimit ?? DEFAULT_IMPORT_RATE_LIMIT;
  const limiter = new RateLimiter({ max: rl.max, windowSeconds: rl.windowSeconds });
  const ia = { preHandler: app.requireRole('INSTITUTION_ADMIN') };

  const readUpload = async (req: FastifyRequest): Promise<Upload> => {
    if (!req.isMultipart()) throw new AppError(415, 'UNSUPPORTED_MEDIA_TYPE', 'Expected multipart/form-data');
    let csv: Buffer | undefined;
    let csvName: string | null = null;
    let zip: Buffer | null = null;
    try {
      for await (const part of req.parts()) {
        if (part.type !== 'file') throw fileError('BAD_REQUEST', 'Only file fields "csv" and "photos" are accepted');
        const buf = await part.toBuffer();
        if (part.file.truncated) throw fileError('PAYLOAD_TOO_LARGE', 'A file is too large', 413);
        if (part.fieldname === 'csv' && !csv) {
          if (buf.length > limits.maxCsvBytes) throw fileError('PAYLOAD_TOO_LARGE', 'The CSV file is too large', 413);
          csv = buf;
          csvName = cleanFilename(part.filename);
        } else if (part.fieldname === 'photos' && !zip) {
          zip = buf;
        } else throw fileError('BAD_REQUEST', 'Only file fields "csv" and "photos" are accepted, once each');
      }
    } catch (e) {
      if (e instanceof AppError) throw e;
      if ((e as { code?: string }).code === 'FST_REQ_FILE_TOO_LARGE') throw fileError('PAYLOAD_TOO_LARGE', 'A file is too large', 413);
      throw fileError('BAD_REQUEST', 'Invalid upload');
    }
    if (!csv || csv.length === 0) throw fileError('CSV_REQUIRED', 'A CSV file in the "csv" field is required');
    if (zip && zip.length > limits.maxZipBytes) throw fileError('PAYLOAD_TOO_LARGE', 'The photo archive is too large', 413);
    return { csv, csvName, zip };
  };

  /** Parse and validate everything. Reads the DB only; writes nothing. */
  const analyse = async (scope: TenantSession, up: Upload, dryRun: boolean) => {
    let records: string[][];
    try {
      records = parseCsv(decodeCsv(up.csv), {
        maxRecords: limits.maxRows + 1,
        maxColumns: limits.maxColumns,
        maxCellChars: limits.maxCellChars,
      });
    } catch (e) {
      if (e instanceof CsvError) throw fileError(e.code, e.message, e.code === 'CSV_TOO_MANY_ROWS' ? 413 : 400);
      throw e;
    }
    if (records.length < 2) throw fileError('CSV_EMPTY', 'The CSV file needs a header and at least one row');

    // ZIP: structure and names first (nothing inflated yet).
    const photoEntries = new Map<string, ZipEntry>();
    if (up.zip) {
      try {
        for (const e of readZip(up.zip, {
          maxEntries: limits.maxZipEntries,
          maxEntryBytes: limits.maxPhotoBytes,
          maxTotalBytes: limits.maxZipUncompressedBytes,
        })) {
          const m = JPEG_NAME.exec(e.name);
          if (!m) throw fileError('ZIP_ENTRY_NOT_JPEG', 'Photos in the archive must be .jpg or .jpeg files');
          const key = nfc(m[1]!);
          if (photoEntries.has(key)) throw fileError('ZIP_DUPLICATE_ENTRY', 'The photo archive has duplicate file names');
          photoEntries.set(key, e);
        }
      } catch (e) {
        if (e instanceof ZipError) {
          const big = e.code === 'ZIP_TOO_LARGE' || e.code === 'ZIP_ENTRY_TOO_LARGE';
          throw fileError(e.code, e.message, big ? 413 : 400);
        }
        throw e;
      }
    }

    const header = records[0]!.map((h) => h.trim());
    const extIdx = header.indexOf('externalId');
    const { types, holders } = await o.db.withTenant(scope, async (c) => {
      await assertInstitutionActive(c);
      const t = await c.query<{ id: string; code: string; attribute_schema: unknown }>(
        `SELECT id, code, attribute_schema FROM credential_types WHERE institution_id = app_institution_id()`,
      );
      const infos: TypeInfo[] = t.rows.map((r) => {
        let defs: AttributeDef[] = [];
        try {
          defs = parseAttributes(r.attribute_schema);
        } catch {
          defs = []; // a broken stored schema surfaces per row as TYPE_SCHEMA_INVALID from buildAttributes
        }
        return { id: r.id, code: r.code, schema: r.attribute_schema, defs };
      });
      const ext = extIdx < 0 ? [] : records.slice(1).map((r) => (r[extIdx] ?? '').trim()).filter((v) => v !== '' && v.length <= 100);
      const h = await c.query<{ external_id: string; full_name: string; photo_sha256: string | null }>(
        `SELECT external_id, full_name, photo_sha256 FROM credential_holders
          WHERE institution_id = app_institution_id() AND external_id = ANY($1::text[])`,
        [ext],
      );
      const map = new Map<string, ExistingHolder>();
      for (const r of h.rows) map.set(r.external_id, { fullName: r.full_name, hasPhoto: r.photo_sha256 !== null });
      return { types: infos, holders: map };
    });

    // Inflate and validate only the photos some row asks for; other entries are counted, never decoded.
    const photoValid = new Map<string, boolean>();
    if (extIdx >= 0) {
      for (const r of records.slice(1)) {
        const key = nfc((r[extIdx] ?? '').trim());
        const entry = photoEntries.get(key);
        if (!entry || photoValid.has(key)) continue;
        try {
          const bytes = entry.read();
          photoValid.set(key, sniffImage(bytes) === 'image/jpeg' && stripMetadata(bytes, 'image/jpeg') !== null);
        } catch {
          photoValid.set(key, false);
        }
      }
    }
    const v = validateRows(records, types, holders, new Set(photoEntries.keys()), photoValid);
    const errorRows = v.results.filter((r) => !r.ok).length;
    const preview: Preview = {
      dryRun,
      totalRows: v.results.length,
      validRows: v.results.length - errorRows,
      errorRows,
      photos: { provided: photoEntries.size, matched: v.matched.size, unmatched: photoEntries.size - v.matched.size },
      rows: v.results,
    };
    return { preview, data: v.data };
  };

  const noStore = (reply: { header: (k: string, v: string) => unknown }) => void reply.header('Cache-Control', 'no-store');

  // Multipart is registered only in this encapsulated scope, so no other credential route accepts uploads.
  void app.register(async (sub) => {
    await sub.register(multipart, {
      limits: { fileSize: limits.maxZipBytes, files: 2, fields: 0, parts: 3, headerPairs: 20 },
    });

    sub.post('/credentials/import', ia, async (req, reply) => {
      noStore(reply);
      const scope = tenantScope(req);
      const q = (req.query ?? {}) as Record<string, unknown>;
      if (Object.keys(q).some((k) => k !== 'dryRun')) throw fileError('UNKNOWN_PROPERTY', 'Unknown query parameter');
      if (q.dryRun !== undefined && q.dryRun !== 'true' && q.dryRun !== 'false') {
        throw fileError('INVALID_DRY_RUN', 'dryRun must be true or false');
      }
      const dryRun = q.dryRun === 'true';

      const wait = limiter.consume(`import:${scope.institutionId}`);
      if (wait > 0) throw new RateLimitedError(wait);
      if (!dryRun && !o.storage) throw new AppError(503, 'STORAGE_UNAVAILABLE', 'File storage is not available');
      // Refuse before reading the body when the institution cannot issue.
      await o.db.withTenant(scope, assertInstitutionActive);

      const up = await readUpload(req);
      const { preview, data } = await analyse(scope, up, dryRun);

      if (dryRun) {
        o.log.info(
          { event: 'import.dry_run', actorId: scope.userId, institutionId: scope.institutionId, rows: preview.totalRows, errorRows: preview.errorRows },
          'import dry run',
        );
        return reply.status(200).send(preview);
      }
      if (preview.errorRows > 0) {
        return reply.status(422).send({
          error: { code: 'IMPORT_VALIDATION_FAILED', message: 'Some rows are invalid; nothing was imported' },
          preview,
        });
      }

      const storage = o.storage!;
      const batchId = randomUUID();
      const keys = importStorageKeys(scope.institutionId, batchId);
      const stored: string[] = [];
      const cleanup = async () => {
        for (const k of stored) await storage.delete(k).catch(() => undefined);
      };
      try {
        await storage.put(keys.csv, up.csv, 'text/csv');
        stored.push(keys.csv);
        if (up.zip) {
          await storage.put(keys.photos, up.zip, 'application/zip');
          stored.push(keys.photos);
        }
      } catch {
        await cleanup();
        o.log.error({ event: 'import.store_failed', institutionId: scope.institutionId }, 'import source store failed');
        throw new AppError(503, 'STORAGE_UNAVAILABLE', 'File storage is not available');
      }

      try {
        await o.db.withTenant(scope, async (c: PoolClient) => {
          await assertInstitutionActive(c);
          await c.query(`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, [`igaro.import:${scope.institutionId}`]);
          const active = await c.query<{ n: number }>(
            `SELECT count(*)::int AS n FROM import_batches
              WHERE institution_id = app_institution_id() AND status IN ('PENDING','PROCESSING')
                AND created_at > now() - interval '24 hours'`,
          );
          if (active.rows[0]!.n >= limits.maxActiveBatches) {
            throw new AppError(409, 'TOO_MANY_ACTIVE_IMPORTS', 'Wait for the running imports to finish');
          }
          await c.query(
            `INSERT INTO import_batches (id, institution_id, created_by, filename, source_key, status, total_rows)
             VALUES ($1, app_institution_id(), $2, $3, $4, 'PENDING', $5)`,
            [batchId, scope.userId, up.csvName, keys.csv, preview.totalRows],
          );
          const rows = data.map((d, i) => ({ n: i + 1, d: d as ImportRowData }));
          await c.query(
            `INSERT INTO import_rows (id, institution_id, batch_id, row_number, status, data)
             SELECT gen_random_uuid(), app_institution_id(), $1, (e->>'n')::int, 'PENDING', e->'d'
               FROM jsonb_array_elements($2::jsonb) AS e`,
            [batchId, JSON.stringify(rows)],
          );
          await appendAudit(c, {
            institutionId: scope.institutionId,
            actorId: scope.userId,
            action: 'import.created',
            targetType: 'import_batch',
            targetId: batchId,
            metadata: {
              totalRows: preview.totalRows,
              photosProvided: preview.photos.provided,
              csvSha256: sha256(up.csv),
              ...(up.zip ? { photosSha256: sha256(up.zip) } : {}),
            },
            ip: o.hashIp?.(req.ip) ?? null,
          });
        });
      } catch (e) {
        await cleanup();
        throw e;
      }

      o.log.info(
        { event: 'import.created', actorId: scope.userId, institutionId: scope.institutionId, batchId, rows: preview.totalRows },
        'import batch created',
      );
      // After commit: ids only. On failure the batch is marked FAILED so it does not wait forever.
      if (o.queue) {
        try {
          await o.queue.enqueue({ institutionId: scope.institutionId, batchId });
        } catch (err) {
          o.log.error(
            { event: 'import.enqueue_failed', institutionId: scope.institutionId, batchId, errorClass: err instanceof Error ? err.name : 'UnknownError' },
            'import job could not be queued',
          );
          await o.db
            .withTenant(scope, (c) =>
              c.query(
                `UPDATE import_batches SET status = 'FAILED', completed_at = now()
                  WHERE id = $1 AND institution_id = app_institution_id() AND status = 'PENDING'`,
                [batchId],
              ),
            )
            .catch(() => undefined);
          throw new AppError(503, 'QUEUE_UNAVAILABLE', 'The import could not be queued; try again');
        }
      }
      return reply.status(202).send({
        batchId,
        status: 'PENDING',
        totalRows: preview.totalRows,
        photos: preview.photos,
      });
    });

    sub.get<{ Params: { id: string } }>('/credentials/import/:id', ia, async (req, reply) => {
      noStore(reply);
      const scope = tenantScope(req);
      const id = req.params.id;
      if (!isUuid(id)) throw new NotFoundError();
      return o.db.withTenant(scope, async (c) => {
        const b = await c.query<{
          id: string;
          filename: string | null;
          status: string;
          total_rows: number;
          imported_rows: number;
          error_rows: number;
          created_at: Date;
          completed_at: Date | null;
        }>(
          `SELECT id, filename, status::text AS status, total_rows, imported_rows, error_rows, created_at, completed_at
             FROM import_batches WHERE id = $1 AND institution_id = app_institution_id()`,
          [id],
        );
        const row = b.rows[0];
        if (!row) throw new NotFoundError();
        const errs = await c.query<{ row_number: number; error: string | null }>(
          `SELECT row_number, error FROM import_rows
            WHERE batch_id = $1 AND institution_id = app_institution_id() AND status = 'ERROR'
            ORDER BY row_number LIMIT 100`,
          [id],
        );
        return {
          id: row.id,
          filename: row.filename,
          status: row.status,
          totalRows: row.total_rows,
          importedRows: row.imported_rows,
          errorRows: row.error_rows,
          pendingRows: Math.max(0, row.total_rows - row.imported_rows - row.error_rows),
          createdAt: row.created_at.toISOString(),
          completedAt: row.completed_at ? row.completed_at.toISOString() : null,
          errors: errs.rows.map((r) => ({ row: r.row_number, error: (r.error ?? '').slice(0, 200) })),
        };
      });
    });
  });
}
