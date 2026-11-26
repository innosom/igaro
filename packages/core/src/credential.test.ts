import { createHash, createPrivateKey } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  canonicalPayload, computeDataHash, generateSalt, signCredential, verifyCredentialIntegrity,
  verifyDataHashSignature, type CredentialPayloadV1,
} from './credential.js';

// RFC 8032 test 1 seed: a fixed key so signatures are reproducible (Ed25519 is deterministic).
const SEED = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
const RAW_PUB = '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo';
const privateKey = createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(SEED, 'hex')]),
  format: 'der',
  type: 'pkcs8',
});

const photo = 'ab'.repeat(32);
const payload: CredentialPayloadV1 = {
  schemaVersion: 'igaro.credential.v1',
  credentialId: '11111111-2222-4333-8444-555555555555',
  credentialNumber: 'EAU-2026-7K4M9QXT',
  institutionId: '66666666-7777-4888-9999-aaaaaaaaaaaa',
  issuerKeyId: 'eau-2026-01',
  credentialType: 'STUDENT_ID',
  holder: { fullName: 'Ahmed Hassan', externalId: 'EAU20260125', photoSha256: photo },
  attributes: { program: 'Computer Science' },
  issuedAt: '2026-08-13T00:00:00Z',
  expiresAt: '2027-08-13T00:00:00Z',
  salt: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8',
};

// GOLDEN VALUES: must never change for igaro.credential.v1. A change needs a new schemaVersion.
const GOLDEN_CANONICAL =
  '{"attributes":{"program":"Computer Science"},"credentialId":"11111111-2222-4333-8444-555555555555",' +
  '"credentialNumber":"EAU-2026-7K4M9QXT","credentialType":"STUDENT_ID","expiresAt":"2027-08-13T00:00:00Z",' +
  '"holder":{"externalId":"EAU20260125","fullName":"Ahmed Hassan","photoSha256":"' + photo + '"},' +
  '"institutionId":"66666666-7777-4888-9999-aaaaaaaaaaaa","issuedAt":"2026-08-13T00:00:00Z",' +
  '"issuerKeyId":"eau-2026-01","salt":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","schemaVersion":"igaro.credential.v1"}';
const GOLDEN_HASH = createHash('sha256').update(GOLDEN_CANONICAL).digest('hex');
const GOLDEN_SIGNATURE = 'FbZ_rBFekgcLk2W4F9aKA5JQUeU0o54xHvZrLTu-rRl1gDttlFLAAAL_ddofykiMMi_yGtxV2iltkNy7Qqs4CA';

describe('credential signing', () => {
  it('canonical bytes match the golden string', () => {
    expect(canonicalPayload(payload)).toBe(GOLDEN_CANONICAL);
  });
  it('dataHash and signature are byte-identical to golden values', () => {
    const s = signCredential(payload, privateKey);
    expect(s.dataHash).toBe(GOLDEN_HASH);
    expect(s.dataHash).toBe(computeDataHash(payload));
    expect(s.signature).toBe(GOLDEN_SIGNATURE);
    expect(verifyDataHashSignature(s.dataHash, s.signature, RAW_PUB)).toBe(true);
  });
  it('key order of the input does not matter', () => {
    const reordered = JSON.parse(JSON.stringify(Object.fromEntries(Object.entries(payload).reverse())));
    expect(computeDataHash(reordered)).toBe(GOLDEN_HASH);
  });
  it('detects tampering of any signed field', () => {
    const s = signCredential(payload, privateKey);
    const mutations: Array<(p: CredentialPayloadV1) => void> = [
      (p) => { p.holder.fullName = 'Ahmed Hassan '; },
      (p) => { p.holder.photoSha256 = 'cd'.repeat(32); },
      (p) => { p.attributes.program = 'Law'; },
      (p) => { p.expiresAt = null; },
      (p) => { p.issuerKeyId = 'other'; },
      (p) => { p.credentialNumber = 'EAU-2026-AAAAAAAA'; },
    ];
    for (const m of mutations) {
      const p = structuredClone(payload);
      m(p);
      expect(verifyCredentialIntegrity(p, s.dataHash, s.signature, RAW_PUB)).toBe('HASH_MISMATCH');
    }
    expect(verifyCredentialIntegrity(payload, s.dataHash, s.signature, RAW_PUB)).toBe('OK');
  });
  it('detects a bad signature', () => {
    const s = signCredential(payload, privateKey);
    const bad = Buffer.from(s.signature, 'base64url');
    bad[0] = (bad[0] ?? 0) ^ 1;
    expect(verifyCredentialIntegrity(payload, s.dataHash, bad.toString('base64url'), RAW_PUB)).toBe('SIGNATURE_INVALID');
    expect(verifyCredentialIntegrity(payload, s.dataHash, 'not a signature', RAW_PUB)).toBe('SIGNATURE_INVALID');
  });
  it('rejects non-canonical base64url signature encodings (same 64 bytes, different string)', () => {
    expect(GOLDEN_SIGNATURE.endsWith('A')).toBe(true);
    expect(verifyDataHashSignature(GOLDEN_HASH, GOLDEN_SIGNATURE, RAW_PUB)).toBe(true);
    for (const last of ['B', 'C', 'D', 'P']) {
      const alt = GOLDEN_SIGNATURE.slice(0, -1) + last;
      expect(Buffer.from(alt, 'base64url').equals(Buffer.from(GOLDEN_SIGNATURE, 'base64url'))).toBe(true);
      expect(verifyDataHashSignature(GOLDEN_HASH, alt, RAW_PUB)).toBe(false);
    }
  });
  it('rejects a signature made without the domain prefix', async () => {
    const { sign } = await import('node:crypto');
    const raw = sign(null, Buffer.from(GOLDEN_HASH, 'utf8'), privateKey).toString('base64url');
    expect(verifyDataHashSignature(GOLDEN_HASH, raw, RAW_PUB)).toBe(false);
  });
  it('rejects malformed payloads and unknown fields', () => {
    expect(() => computeDataHash({ ...payload, extra: 1 } as never)).toThrow();
    expect(() => computeDataHash({ ...payload, salt: 'short' })).toThrow();
    expect(() => computeDataHash({ ...payload, schemaVersion: 'igaro.credential.v2' } as never)).toThrow();
  });
  it('rejects impossible dates and uppercase UUIDs', () => {
    expect(() => computeDataHash({ ...payload, expiresAt: '2027-02-30T00:00:00Z' })).toThrow();
    expect(() => computeDataHash({ ...payload, issuedAt: '2026-08-13T24:00:00Z' })).toThrow();
    expect(() => computeDataHash({ ...payload, institutionId: payload.institutionId.toUpperCase() })).toThrow();
  });
  it('generates distinct 256-bit salts', () => {
    const a = generateSalt();
    expect(Buffer.from(a, 'base64url')).toHaveLength(32);
    expect(generateSalt()).not.toBe(a);
  });
});
