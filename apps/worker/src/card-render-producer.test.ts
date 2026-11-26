import { describe, expect, it } from 'vitest';
import { PgBossCardRenderQueue } from './card-render-producer.js';

const IDS = { institutionId: '11111111-1111-4111-8111-111111111111', credentialId: '22222222-2222-4222-8222-222222222222' };

describe('PgBossCardRenderQueue', () => {
  it('sends the card.render job with ids only and a per-credential singleton key', async () => {
    const calls: { name: string; data: object; opts: Record<string, unknown> }[] = [];
    const q = new PgBossCardRenderQueue({ send: async (name, data, opts) => (calls.push({ name, data, opts }), 'id') });
    await q.enqueue({ ...IDS, extra: 'ignored' } as typeof IDS);
    expect(calls).toEqual([{ name: 'card.render', data: IDS, opts: { singletonKey: `card.render:${IDS.credentialId}` } }]);
  });

  it('treats a declined duplicate (null id) as success', async () => {
    const q = new PgBossCardRenderQueue({ send: async () => null });
    await expect(q.enqueue(IDS)).resolves.toBeUndefined();
  });

  it('propagates sender errors (the API logs and swallows them)', async () => {
    const q = new PgBossCardRenderQueue({ send: async () => Promise.reject(new Error('down')) });
    await expect(q.enqueue(IDS)).rejects.toThrow('down');
  });
});
