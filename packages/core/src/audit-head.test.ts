import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { auditHeadMessage, signAuditHead, verifyAuditHeadSignature, signDataHash, SIGNATURE_DOMAIN_PREFIX } from './index.js';

const head = 'ab'.repeat(32);
const inst = '11111111-2222-4333-8444-555555555555';
const stmt = { institutionId: inst, day: '2026-11-26', headHash: head };

describe('audit head signing', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const other = generateKeyPairSync('ed25519');

  it('pins the signed message bytes (golden)', () => {
    expect(auditHeadMessage(stmt).toString('utf8')).toBe(`igaro.audit.head.sig.v1:${inst}:2026-11-26:${head}`);
    expect(auditHeadMessage({ ...stmt, institutionId: null }).toString('utf8')).toBe(
      `igaro.audit.head.sig.v1:platform:2026-11-26:${head}`,
    );
  });

  it('round-trips and rejects any changed field or key', () => {
    const sig = signAuditHead(stmt, privateKey);
    expect(verifyAuditHeadSignature(stmt, sig, publicKey)).toBe(true);
    expect(verifyAuditHeadSignature({ ...stmt, day: '2026-11-27' }, sig, publicKey)).toBe(false);
    expect(verifyAuditHeadSignature({ ...stmt, institutionId: null }, sig, publicKey)).toBe(false);
    expect(verifyAuditHeadSignature({ ...stmt, headHash: 'cd'.repeat(32) }, sig, publicKey)).toBe(false);
    expect(verifyAuditHeadSignature(stmt, sig, other.publicKey)).toBe(false);
    expect(verifyAuditHeadSignature(stmt, 'not-a-signature', publicKey)).toBe(false);
  });

  it('is domain separated from credential signatures', () => {
    // A credential signature over the same hex string must not verify as a head signature.
    const credSig = signDataHash(head, privateKey);
    expect(SIGNATURE_DOMAIN_PREFIX).not.toBe('igaro.audit.head.sig.v1:');
    expect(verifyAuditHeadSignature(stmt, credSig, publicKey)).toBe(false);
  });

  it('rejects malformed statements', () => {
    expect(() => auditHeadMessage({ ...stmt, headHash: 'xyz' })).toThrow();
    expect(() => auditHeadMessage({ ...stmt, day: '26-11-2026' })).toThrow();
    expect(() => auditHeadMessage({ ...stmt, institutionId: 'nope' })).toThrow();
  });
});
