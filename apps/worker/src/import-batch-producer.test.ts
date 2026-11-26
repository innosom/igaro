import { describe, expect, it } from 'vitest';
import { PgBossImportBatchQueue } from './import-batch-producer.js';
import { importStorageKeys, InvalidImportBatchJobError, parseImportBatchJobData } from './import-batch-job.js';

const IDS = { institutionId: '11111111-1111-4111-8111-111111111111', batchId: '22222222-2222-4222-8222-222222222222' };

describe('import.batch contract', () => {
  it('sends ids only with a per-batch singleton key', async () => {
    const calls: { name: string; data: object; opts: Record<string, unknown> }[] = [];
    const q = new PgBossImportBatchQueue({ send: async (name, data, opts) => (calls.push({ name, data, opts }), 'id') });
    await q.enqueue({ ...IDS, extra: 'ignored' } as typeof IDS);
    expect(calls).toEqual([{ name: 'import.batch', data: IDS, opts: { singletonKey: `import.batch:${IDS.batchId}` } }]);
  });
  it('parses only well-formed payloads', () => {
    expect(parseImportBatchJobData({ ...IDS, x: 1 })).toEqual(IDS);
    expect(() => parseImportBatchJobData({ institutionId: 'x', batchId: IDS.batchId })).toThrow(InvalidImportBatchJobError);
    expect(() => parseImportBatchJobData(null)).toThrow(InvalidImportBatchJobError);
  });
  it('keys are scoped under the institution', () => {
    const k = importStorageKeys(IDS.institutionId, IDS.batchId);
    expect(k.csv.startsWith(`institutions/${IDS.institutionId}/imports/${IDS.batchId}/`)).toBe(true);
    expect(k.photos).not.toBe(k.csv);
  });
});
