import { describe, expect, it } from 'vitest';
import { RateLimiter } from './rate-limit.js';

describe('RateLimiter', () => {
  it('allows max attempts per window, then reports seconds to wait', () => {
    let t = 1_000_000;
    const l = new RateLimiter({ max: 2, windowSeconds: 60, now: () => t });
    expect(l.consume('a')).toBe(0);
    expect(l.consume('a')).toBe(0);
    expect(l.consume('a')).toBe(60);
    t += 30_000;
    expect(l.consume('a')).toBe(30); // blocked attempts do not extend the window
    expect(l.consume('b')).toBe(0); // other keys are independent
    t += 30_000;
    expect(l.consume('a')).toBe(0); // new window
  });

  it('reset clears a key', () => {
    const l = new RateLimiter({ max: 1, windowSeconds: 60 });
    l.consume('a');
    expect(l.consume('a')).toBeGreaterThan(0);
    l.reset('a');
    expect(l.consume('a')).toBe(0);
  });

  it('keeps memory bounded', () => {
    const l = new RateLimiter({ max: 1, windowSeconds: 60, maxKeys: 10 });
    for (let i = 0; i < 100; i++) l.consume(`k${i}`);
    expect((l as unknown as { entries: Map<string, unknown> }).entries.size).toBeLessThanOrEqual(
      10,
    );
  });
});
