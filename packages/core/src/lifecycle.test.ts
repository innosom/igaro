import { describe, expect, it } from 'vitest';
import {
  AUDIT_GENESIS_HASH, canTransition, chainEntry, computeEntryHash, isExpired, LifecycleError,
  NoopAnchorService, planTransition, verifyChain, type AuditEntryContent, type ChainedEntry,
  type LifecycleAction,
} from './index.js';

describe('lifecycle', () => {
  it('allows the documented transitions', () => {
    expect(planTransition('DRAFT', 'ISSUE')).toEqual({ to: 'ACTIVE', event: 'ISSUED' });
    expect(planTransition('ACTIVE', 'SUSPEND', 'fraud check').to).toBe('SUSPENDED');
    expect(planTransition('SUSPENDED', 'REINSTATE').to).toBe('ACTIVE');
    expect(planTransition('ACTIVE', 'REVOKE', 'error').to).toBe('REVOKED');
    expect(planTransition('ACTIVE', 'REISSUE').to).toBe('SUPERSEDED');
  });
  it('requires a reason for suspend and revoke', () => {
    for (const a of ['SUSPEND', 'REVOKE'] as const) {
      expect(() => planTransition('ACTIVE', a)).toThrow(LifecycleError);
      expect(() => planTransition('ACTIVE', a, '   ')).toThrow(LifecycleError);
    }
  });
  it('REVOKED and SUPERSEDED are terminal; nothing else is allowed', () => {
    const actions: LifecycleAction[] = ['ISSUE', 'SUSPEND', 'REINSTATE', 'REVOKE', 'REISSUE'];
    for (const s of ['REVOKED', 'SUPERSEDED'] as const) for (const a of actions) expect(canTransition(s, a)).toBe(false);
    expect(canTransition('SUSPENDED', 'REVOKE')).toBe(false);
    expect(canTransition('DRAFT', 'REVOKE')).toBe(false);
    expect(canTransition('ACTIVE', 'ISSUE')).toBe(false);
    expect(canTransition('ACTIVE', 'constructor' as LifecycleAction)).toBe(false);
  });
  it('computes EXPIRED at read time', () => {
    const now = new Date('2027-01-01T00:00:00Z');
    expect(isExpired(null, now)).toBe(false);
    expect(isExpired('2026-12-31T00:00:00Z', now)).toBe(true);
    expect(isExpired('2027-06-01T00:00:00Z', now)).toBe(false);
    expect(isExpired('not a date', now)).toBe(true);
    expect(isExpired('June 1 2030', now)).toBe(true);
  });
});

const mk = (seq: number, action: string): AuditEntryContent => ({
  institutionId: 'i1', seq, actorId: 'u1', action, targetType: null, targetId: null,
  metadata: { a: 1 }, ip: null, createdAt: '2026-11-25T00:00:00.000Z',
});
function build(n: number): ChainedEntry[] {
  const out: ChainedEntry[] = [];
  for (let i = 1; i <= n; i++) out.push(chainEntry(out.at(-1)?.entryHash ?? null, mk(i, 'a' + i)));
  return out;
}

describe('audit chain', () => {
  it('entry hash is stable and seq-type independent', () => {
    const h = computeEntryHash(AUDIT_GENESIS_HASH, mk(1, 'x'));
    expect(h).toMatch(/^[0-9a-f]{64}$/);
    expect(h).toBe('d0d0e48c5aaebe500802fb2fd547c6bdff48a1ae25ca3e7e0ce74cf92bcddfe3');
    expect(h).toBe(computeEntryHash(AUDIT_GENESIS_HASH, { ...mk(1, 'x'), seq: '1' }));
  });
  it('verifies an intact chain and returns the head', () => {
    const c = build(4);
    expect(verifyChain(c)).toEqual({ ok: true, head: c[3]!.entryHash });
  });
  it('detects edits, relinking, and gaps', () => {
    const c = build(4);
    expect(verifyChain(c.map((e, i) => (i === 1 ? { ...e, action: 'evil' } : e)))).toMatchObject({ ok: false, brokenAtSeq: '2', reason: 'HASH_MISMATCH' });
    expect(verifyChain([c[0]!, c[2]!, c[3]!])).toMatchObject({ ok: false, reason: 'SEQ_GAP' });
    expect(verifyChain([{ ...c[0]!, prevHash: 'f'.repeat(64) }])).toMatchObject({ ok: false, reason: 'PREV_MISMATCH' });
  });
  it('a recomputed chain verifies but its head differs from the signed head', () => {
    const c = build(3);
    const forged: ChainedEntry[] = [];
    for (const e of c) forged.push(chainEntry(forged.at(-1)?.entryHash ?? null, e.seq === 2 ? { ...e, action: 'evil' } : e));
    const r = verifyChain(forged);
    expect(r.ok).toBe(true);
    expect(r.ok && r.head).not.toBe(c[2]!.entryHash);
  });
  it('rejects malformed prevHash', () => {
    expect(() => computeEntryHash('abc', mk(1, 'x'))).toThrow();
  });
});

describe('NoopAnchorService', () => {
  it('always reports NOT_ANCHORED', async () => {
    const s = new NoopAnchorService();
    expect(await s.anchor()).toEqual({ status: 'NOT_ANCHORED' });
    expect(await s.getStatus()).toEqual({ status: 'NOT_ANCHORED' });
  });
});
