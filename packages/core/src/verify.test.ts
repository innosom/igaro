import { createPrivateKey } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { signCredential, type CredentialPayloadV1 } from './credential.js';
import { verifyCredential, type VerificationInput } from './verify.js';

const SEED = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
const RAW_PUB = '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo';
const privateKey = createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(SEED, 'hex')]),
  format: 'der',
  type: 'pkcs8',
});

const payload: CredentialPayloadV1 = {
  schemaVersion: 'igaro.credential.v1',
  credentialId: '11111111-2222-4333-8444-555555555555',
  credentialNumber: 'EAU-2026-7K4M9QXT',
  institutionId: '66666666-7777-4888-9999-aaaaaaaaaaaa',
  issuerKeyId: 'eau-2026-01',
  credentialType: 'STUDENT_ID',
  holder: { fullName: 'Ahmed Hassan', externalId: 'EAU20260125', photoSha256: 'ab'.repeat(32) },
  attributes: { program: 'Computer Science' },
  issuedAt: '2026-08-13T00:00:00Z',
  expiresAt: '2027-08-13T00:00:00Z',
  salt: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8',
};
const signed = signCredential(payload, privateKey);
const NOW = new Date('2026-11-26T00:00:00Z');

function input(over: Partial<VerificationInput> & { status?: 'ACTIVE' | 'SUSPENDED' | 'REVOKED' | 'SUPERSEDED' | 'DRAFT'; payload?: unknown } = {}): VerificationInput {
  return {
    record: {
      id: payload.credentialId,
      institutionId: payload.institutionId,
      status: over.status ?? 'ACTIVE',
      payload: over.payload ?? payload,
      dataHash: signed.dataHash,
      signature: signed.signature,
      supersededByCredentialId: 'new-id',
    },
    key: { kid: 'eau-2026-01', institutionId: payload.institutionId, publicKey: RAW_PUB, status: 'ACTIVE' },
    institutionSuspended: false,
    now: NOW,
    ...(over.key !== undefined ? { key: over.key } : {}),
    ...(over.institutionSuspended !== undefined ? { institutionSuspended: over.institutionSuspended } : {}),
    ...(over.record !== undefined ? { record: over.record } : {}),
  };
}

describe('verifyCredential', () => {
  it('VERIFIED for an active, untampered credential', () => {
    expect(verifyCredential(input())).toMatchObject({ result: 'VERIFIED', alertOps: false });
  });
  it('NOT_FOUND for unknown token and for DRAFT', () => {
    expect(verifyCredential(input({ record: null })).result).toBe('NOT_FOUND');
    expect(verifyCredential(input({ status: 'DRAFT' })).result).toBe('NOT_FOUND');
  });
  it('tampered payload fails and alerts, even when REVOKED', () => {
    const bad = { ...payload, holder: { ...payload.holder, fullName: 'Mallory' } };
    for (const status of ['ACTIVE', 'REVOKED', 'SUSPENDED', 'SUPERSEDED'] as const) {
      expect(verifyCredential(input({ status, payload: bad }))).toMatchObject({
        result: 'VERIFICATION_FAILED', reason: 'HASH_MISMATCH', alertOps: true,
      });
    }
  });
  it('malformed payload and wrong signature fail with alert', () => {
    expect(verifyCredential(input({ payload: { x: 1 } })).alertOps).toBe(true);
    const r = input();
    r.record!.signature = 'A'.repeat(86);
    expect(verifyCredential(r)).toMatchObject({ result: 'VERIFICATION_FAILED', reason: 'SIGNATURE_INVALID', alertOps: true });
  });
  it('missing or mismatched key fails', () => {
    expect(verifyCredential(input({ key: null })).reason).toBe('KEY_MISSING');
    expect(verifyCredential(input({ key: { kid: 'other', institutionId: payload.institutionId, publicKey: RAW_PUB, status: 'ACTIVE' } })).reason).toBe('KEY_MISSING');
  });
  it('COMPROMISED key fails (even when revoked); RETIRED key still verifies', () => {
    const k = (status: 'COMPROMISED' | 'RETIRED') => ({ kid: 'eau-2026-01', institutionId: payload.institutionId, publicKey: RAW_PUB, status });
    expect(verifyCredential(input({ key: k('COMPROMISED'), status: 'REVOKED' }))).toMatchObject({
      result: 'VERIFICATION_FAILED', reason: 'KEY_COMPROMISED', alertOps: false,
    });
    expect(verifyCredential(input({ key: k('RETIRED') })).result).toBe('VERIFIED');
  });
  it('status results, with replacement link for SUPERSEDED', () => {
    expect(verifyCredential(input({ status: 'REVOKED' })).result).toBe('REVOKED');
    expect(verifyCredential(input({ status: 'SUSPENDED' })).result).toBe('SUSPENDED');
    expect(verifyCredential(input({ status: 'SUPERSEDED' }))).toMatchObject({ result: 'SUPERSEDED', supersededByCredentialId: 'new-id' });
  });
  it('status outranks expiry and institution suspension', () => {
    const late = { ...input({ status: 'REVOKED', institutionSuspended: true }), now: new Date('2030-01-01T00:00:00Z') };
    expect(verifyCredential(late).result).toBe('REVOKED');
  });
  it('EXPIRED after the signed expiry, ahead of institution warning', () => {
    const late = { ...input({ institutionSuspended: true }), now: new Date('2028-01-01T00:00:00Z') };
    expect(verifyCredential(late).result).toBe('EXPIRED');
  });
  it('payload moved to another row or tenant fails with alert', () => {
    const a = input();
    a.record!.id = '99999999-2222-4333-8444-555555555555';
    expect(verifyCredential(a)).toMatchObject({ result: 'VERIFICATION_FAILED', reason: 'BINDING_MISMATCH', alertOps: true });
    const b = input();
    b.record!.institutionId = '99999999-7777-4888-9999-aaaaaaaaaaaa';
    expect(verifyCredential(b).reason).toBe('BINDING_MISMATCH');
    const c = input({ key: { kid: 'eau-2026-01', institutionId: '99999999-7777-4888-9999-aaaaaaaaaaaa', publicKey: RAW_PUB, status: 'ACTIVE' } });
    expect(verifyCredential(c).result).toBe('VERIFICATION_FAILED');
  });
  it('fails closed on unknown record or key status', () => {
    expect(verifyCredential(input({ status: 'EXPIRED' as never })).reason).toBe('UNKNOWN_STATE');
    const k = { kid: 'eau-2026-01', institutionId: payload.institutionId, publicKey: RAW_PUB, status: 'WEIRD' as never };
    expect(verifyCredential(input({ key: k })).reason).toBe('UNKNOWN_STATE');
  });
  it('tampered payload beats a compromised key; altered stored dataHash fails', () => {
    const bad = { ...payload, attributes: { program: 'x' } };
    const k = { kid: 'eau-2026-01', institutionId: payload.institutionId, publicKey: RAW_PUB, status: 'COMPROMISED' as const };
    expect(verifyCredential(input({ key: k, payload: bad }))).toMatchObject({ reason: 'HASH_MISMATCH', alertOps: true });
    const r = input();
    r.record!.dataHash = 'f'.repeat(64);
    expect(verifyCredential(r).reason).toBe('HASH_MISMATCH');
  });
  it('VALID_WITH_WARNING when the institution is suspended', () => {
    expect(verifyCredential(input({ institutionSuspended: true }))).toMatchObject({
      result: 'VALID_WITH_WARNING', reason: 'INSTITUTION_SUSPENDED',
    });
  });
});
