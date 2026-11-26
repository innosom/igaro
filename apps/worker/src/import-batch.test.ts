// Unit tests for the import.batch consumer (T-044, ADR 0034) with a fake API and in-memory storage. Test values only.
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createLogger } from './logger.js';
import { MemoryWorkerStorage } from './card-storage.js';
import { importStorageKeys } from './import-batch-job.js';
import {
  failImportBatch,
  HttpImportApi,
  ImportApiError,
  ImportBatchIncompleteError,
  runImportBatch,
  type ImportApi,
  type ImportFinishResponse,
  type ImportRowResponse,
  type ImportStartResponse,
} from './import-batch.js';
import { JPEG, PNG } from './test-images.js';
import { makeZip, type TestZipEntry } from './test-zip.js';

const INST = '11111111-1111-4111-8111-111111111111';
const BATCH = '22222222-2222-4222-8222-222222222222';
const JOB = { institutionId: INST, batchId: BATCH };
const sha = (b: Buffer | string) => createHash('sha256').update(b).digest('hex');

type Body = { photo?: { sha256: string; data: string }; fail?: string };

class FakeApi implements ImportApi {
  status = 'PENDING';
  rows: { row: number; status: string; externalId: string; photo: string }[] = [];
  sources: { csvSha256?: string; photosSha256?: string } = {};
  calls: { row: number; body: Body }[] = [];
  finishes: string[] = [];
  /** rows whose next call throws a transient error */
  failRows = new Set<number>();
  failAll = false;
  async start(): Promise<ImportStartResponse> {
    if (this.status === 'COMPLETED' || this.status === 'FAILED') return { status: this.status, rows: [], sources: {} };
    this.status = 'PROCESSING';
    return { status: 'PROCESSING', rows: this.rows.map((r) => ({ ...r })), sources: this.sources };
  }
  async processRow(_job: unknown, row: number, body: Body): Promise<ImportRowResponse> {
    this.calls.push({ row, body });
    if (this.failAll || this.failRows.has(row)) throw new ImportApiError(503);
    const r = this.rows.find((x) => x.row === row)!;
    if (r.status !== 'PENDING') return { outcome: r.status === 'IMPORTED' ? 'IMPORTED' : 'ERROR' };
    if (body.fail) {
      r.status = 'ERROR';
      return { outcome: 'ERROR', code: body.fail };
    }
    r.status = 'IMPORTED';
    return { outcome: 'IMPORTED' };
  }
  async finish(_job: unknown, outcome: 'complete' | 'failed'): Promise<ImportFinishResponse> {
    this.finishes.push(outcome);
    this.status = outcome === 'complete' ? 'COMPLETED' : 'FAILED';
    return { status: this.status, imported: 0, error: 0, pending: 0 };
  }
}

function setup(rows: { id: string; photo?: 'zip' | 'holder' }[], zipEntries?: TestZipEntry[]) {
  const api = new FakeApi();
  api.rows = rows.map((r, i) => ({ row: i + 1, status: 'PENDING', externalId: r.id, photo: r.photo ?? 'zip' }));
  const storage = new MemoryWorkerStorage();
  const keys = importStorageKeys(INST, BATCH);
  void storage.put(keys.csv, Buffer.from('fullName\nSecret Person\n'), 'text/csv');
  if (zipEntries) {
    const zip = makeZip(zipEntries);
    void storage.put(keys.photos, zip, 'application/zip');
    api.sources = { photosSha256: sha(zip) };
  }
  const logs: string[] = [];
  const logger = createLogger('debug', { write: (s: string) => void logs.push(s) });
  return { api, storage, keys, logs, deps: { api, storage, logger } };
}

describe('runImportBatch', () => {
  it('strips metadata, hashes the stored bytes, processes every row and deletes the sources', async () => {
    const withExif = JPEG('Exif-GPS-secret', 'TRAILING-ARCHIVE');
    const s = setup(
      [{ id: 'S-1' }, { id: 'S-2' }, { id: 'S-3', photo: 'holder' }],
      [{ name: 'S-1.jpg', data: withExif }, { name: 'S-2.JPEG', data: JPEG() }, { name: 'unused.jpg', data: JPEG() }],
    );
    await expect(runImportBatch(s.deps, JOB)).resolves.toBe('completed');
    expect(s.api.calls.map((c) => c.row)).toEqual([1, 2, 3]);
    const p1 = s.api.calls[0]!.body.photo!;
    const sent = Buffer.from(p1.data, 'base64');
    expect(sent.includes(Buffer.from('Exif-GPS-secret'))).toBe(false);
    expect(sent.includes(Buffer.from('TRAILING-ARCHIVE'))).toBe(false);
    expect(p1.sha256).toBe(sha(sent)); // hash of exactly the bytes that will be stored
    expect(s.api.calls[2]!.body).toEqual({}); // existing holder photo: nothing sent
    expect(s.api.finishes).toEqual(['complete']);
    expect(s.storage.objects.size).toBe(0); // CSV and ZIP deleted (personal data)
    const out = s.logs.join('');
    expect(out).not.toContain('Secret Person');
    expect(out).not.toContain('S-1');
  });

  it('records a bad photo on that row and keeps going', async () => {
    const s = setup(
      [{ id: 'a' }, { id: 'b' }, { id: 'c' }, { id: 'd' }],
      [{ name: 'a.jpg', data: PNG() }, { name: 'b.jpg', data: JPEG() }, { name: 'd.jpg', data: Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe1, 0x00, 0x40]), Buffer.from('x')]) }],
    );
    await runImportBatch(s.deps, JOB);
    expect(s.api.calls.map((c) => c.body.fail ?? 'ok')).toEqual(['PHOTO_INVALID', 'ok', 'PHOTO_REQUIRED', 'PHOTO_INVALID']);
    expect(s.api.finishes).toEqual(['complete']);
  });

  it('refuses a ZIP that does not match the hash recorded at intake', async () => {
    const s = setup([{ id: 'a' }], [{ name: 'a.jpg', data: JPEG() }]);
    s.api.sources = { photosSha256: sha('something else') };
    await runImportBatch(s.deps, JOB);
    expect(s.api.calls[0]!.body).toEqual({ fail: 'PHOTO_SOURCE_MISMATCH' });
  });

  it('fails rows when the ZIP is missing, hostile or has non-JPEG names', async () => {
    const missing = setup([{ id: 'a' }]);
    missing.api.sources = { photosSha256: sha('x') };
    await runImportBatch(missing.deps, JOB);
    expect(missing.api.calls[0]!.body).toEqual({ fail: 'PHOTO_SOURCE_MISSING' });

    const nested = setup([{ id: 'a' }], [{ name: 'dir/a.jpg', data: JPEG() }]);
    await runImportBatch(nested.deps, JOB);
    expect(nested.api.calls[0]!.body).toEqual({ fail: 'PHOTO_ARCHIVE_INVALID' });

    const png = setup([{ id: 'a' }], [{ name: 'a.png', data: PNG() }]);
    await runImportBatch(png.deps, JOB);
    expect(png.api.calls[0]!.body).toEqual({ fail: 'PHOTO_ARCHIVE_INVALID' });

    const bomb = setup([{ id: 'a' }], [{ name: 'a.jpg', data: JPEG(), declaredSize: 50 * 1024 * 1024 }]);
    await runImportBatch(bomb.deps, JOB);
    expect(bomb.api.calls[0]!.body).toEqual({ fail: 'PHOTO_ARCHIVE_INVALID' });
  });

  it('does not read the ZIP when no row needs it', async () => {
    const s = setup([{ id: 'a', photo: 'holder' }]);
    await expect(runImportBatch(s.deps, JOB)).resolves.toBe('completed');
    expect(s.api.calls[0]!.body).toEqual({});
  });

  it('transient failures leave rows pending, throw for a retry, and the retry skips finished rows', async () => {
    const s = setup([{ id: 'a' }, { id: 'b' }, { id: 'c' }], ['a', 'b', 'c'].map((n) => ({ name: `${n}.jpg`, data: JPEG() })));
    s.api.failRows.add(2);
    await expect(runImportBatch(s.deps, JOB)).rejects.toBeInstanceOf(ImportBatchIncompleteError);
    expect(s.api.finishes).toEqual([]);
    expect(s.storage.objects.size).toBe(2); // sources are kept for the retry
    expect(s.api.rows.map((r) => r.status)).toEqual(['IMPORTED', 'PENDING', 'IMPORTED']);

    s.api.failRows.clear();
    s.api.calls.length = 0;
    await expect(runImportBatch(s.deps, JOB)).resolves.toBe('completed');
    expect(s.api.calls.map((c) => c.row)).toEqual([2]); // only the pending row
    expect(s.api.finishes).toEqual(['complete']);
    expect(s.storage.objects.size).toBe(0);
  });

  it('gives up a pass after consecutive transient failures', async () => {
    const s = setup(Array.from({ length: 20 }, (_, i) => ({ id: `r${i}` })), Array.from({ length: 20 }, (_, i) => ({ name: `r${i}.jpg`, data: JPEG() })));
    s.api.failAll = true;
    await expect(runImportBatch({ ...s.deps, maxConsecutiveTransient: 3 }, JOB)).rejects.toBeInstanceOf(ImportBatchIncompleteError);
    expect(s.api.calls).toHaveLength(3);
  });

  it('is a no-op for a batch that already finished', async () => {
    const s = setup([{ id: 'a' }], [{ name: 'a.jpg', data: JPEG() }]);
    s.api.status = 'COMPLETED';
    await expect(runImportBatch(s.deps, JOB)).resolves.toBe('skipped_finished');
    expect(s.api.calls).toHaveLength(0);
  });

  it('rejects a malformed job payload before any call', async () => {
    const s = setup([{ id: 'a' }]);
    await expect(runImportBatch(s.deps, { institutionId: 'x', batchId: BATCH })).rejects.toThrow('invalid import batch job payload');
    await expect(runImportBatch(s.deps, null)).rejects.toThrow();
    expect(s.api.calls).toHaveLength(0);
  });

  it('failImportBatch marks the batch FAILED and drops the sources', async () => {
    const s = setup([{ id: 'a' }], [{ name: 'a.jpg', data: JPEG() }]);
    await failImportBatch(s.deps, JOB);
    expect(s.api.finishes).toEqual(['failed']);
    expect(s.storage.objects.size).toBe(0);
  });

  it('handles a 500-holder batch', async () => {
    const n = 500;
    const ids = Array.from({ length: n }, (_, i) => `EXT-${String(i).padStart(4, '0')}`);
    const s = setup(ids.map((id) => ({ id })), ids.map((id, i) => ({ name: `${id}.jpg`, data: JPEG(`exif-${i}`) })));
    await expect(runImportBatch(s.deps, JOB)).resolves.toBe('completed');
    expect(s.api.calls).toHaveLength(n);
    expect(s.api.rows.every((r) => r.status === 'IMPORTED')).toBe(true);
    expect(s.api.calls.every((c) => c.body.photo && !Buffer.from(c.body.photo.data, 'base64').includes(Buffer.from('exif-')))).toBe(true);
  });
});

describe('HttpImportApi', () => {
  const job = JOB;
  const fakeFetch = (status: number, body: unknown, seen: { url?: string; init?: RequestInit } = {}): typeof fetch =>
    (async (url: string | URL | Request, init?: RequestInit) => {
      seen.url = String(url);
      seen.init = init;
      return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
    }) as typeof fetch;

  it('posts JSON with the bearer token and the institution id', async () => {
    const seen: { url?: string; init?: RequestInit } = {};
    const api = new HttpImportApi({ baseUrl: 'http://api.test/api/v1/', token: 'T'.repeat(40), fetchImpl: fakeFetch(200, { outcome: 'IMPORTED' }, seen) });
    await expect(api.processRow(job, 7, { fail: 'PHOTO_INVALID' })).resolves.toEqual({ outcome: 'IMPORTED' });
    expect(seen.url).toBe(`http://api.test/api/v1/internal/import/batches/${BATCH}/rows/7`);
    expect((seen.init!.headers as Record<string, string>).authorization).toBe(`Bearer ${'T'.repeat(40)}`);
    expect(JSON.parse(String(seen.init!.body))).toEqual({ institutionId: INST, fail: 'PHOTO_INVALID' });
  });

  it('throws a generic error that carries neither the body, the url nor the token', async () => {
    const token = 'SECRET-TOKEN-'.padEnd(40, 'x');
    const bad = new HttpImportApi({ baseUrl: 'http://api.test/api/v1', token, fetchImpl: fakeFetch(500, { error: 'boom with Secret Person' }) });
    const err = await bad.start(job).catch((e: unknown) => e as Error);
    expect(err).toBeInstanceOf(ImportApiError);
    expect((err as ImportApiError).status).toBe(500);
    expect(String((err as Error).message)).not.toMatch(/Secret|api\.test|SECRET-TOKEN/);

    const net = new HttpImportApi({
      baseUrl: 'http://api.test/api/v1',
      token,
      fetchImpl: (async () => {
        throw new Error('connect ECONNREFUSED http://api.test with SECRET-TOKEN');
      }) as typeof fetch,
    });
    const e2 = await net.finish(job, 'complete').catch((e: unknown) => e as Error);
    expect(e2).toBeInstanceOf(ImportApiError);
    expect(String((e2 as Error).message)).not.toMatch(/SECRET-TOKEN|api\.test/);
  });
});
