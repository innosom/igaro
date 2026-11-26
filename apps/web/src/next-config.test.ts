// T-047 (ADR 0035): the public origin must never proxy /api/v1/internal/*.
import { describe, expect, it } from 'vitest';
// @ts-expect-error plain .mjs config without types
import config from '../next.config.mjs';

describe('web rewrites', () => {
  it('exclude /api/v1/internal/*', async () => {
    const rules = (await config.rewrites()) as { source: string }[];
    const api = rules.find((r) => r.source.startsWith('/api/v1/'))!;
    // Next compiles `:path(<regex>)`; check the embedded regex directly.
    const inner = /:path\((.*)\)$/.exec(api.source)![1]!;
    const re = new RegExp('^' + inner + '$');
    expect(re.test('verify/abc')).toBe(true);
    expect(re.test('internal/import/batches/x/start')).toBe(false);
    expect(re.test('internal')).toBe(false);
    expect(re.test('internalx/foo')).toBe(true);
  });
});
