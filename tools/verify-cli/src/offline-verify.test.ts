import { randomBytes, randomUUID, sign as edSign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  computeDataHash,
  generateSalt,
  generateSigningKey,
  signCredential,
  unwrapPrivateKey,
  verifyCredential,
  type CredentialPayloadV1,
  type SigningKeyStatus,
} from '@igaro/core';
import { KeysDocumentError, parseKeysDocument, verifyCredentialFile, type PublishedKey } from './offline-verify.js';

const NOW = new Date('2027-01-01T00:00:00Z');
const MASTER = randomBytes(32);

/** Issue a credential exactly as the API does: core key generation, envelope unwrap, core signing. */
function issue(over: Partial<CredentialPayloadV1> = {}, keyStatus: SigningKeyStatus = 'ACTIVE') {
  const gen = generateSigningKey(MASTER);
  const priv = unwrapPrivateKey(gen.encryptedPrivateKey, MASTER, gen.kid);
  const payload: CredentialPayloadV1 = {
    schemaVersion: 'igaro.credential.v1',
    credentialId: randomUUID(),
    credentialNumber: 'EAU-2026-AB12CD34',
    institutionId: randomUUID(),
    issuerKeyId: gen.kid,
    credentialType: 'STUDENT_ID',
    holder: { fullName: 'Amina Yusuf', externalId: 'EAU-0042', photoSha256: 'cd'.repeat(32) },
    attributes: { program: 'Law', year: '2' },
    issuedAt: '2026-09-01T00:00:00Z',
    expiresAt: '2027-09-01T00:00:00Z',
    salt: generateSalt(),
    ...over,
  };
  const signed = signCredential(payload, priv);
  const file = { payload, dataHash: signed.dataHash, signature: signed.signature, kid: gen.kid, publicKeysUrl: '/i/eau/keys.json' };
  const key: PublishedKey = { kid: gen.kid, alg: 'Ed25519', publicKey: gen.publicKey, status: keyStatus, createdAt: null, retiredAt: null };
  return { file, key, priv, gen };
}

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

describe('verifyCredentialFile: valid credentials', () => {
  it('ACTIVE key, not expired: VALID with every check passing and status marked NOT_CHECKED', () => {
    const { file, key } = issue();
    const out = verifyCredentialFile(clone(file), [key], NOW);
    expect(out.result).toBe('VALID');
    expect(out.reason).toBe('OK');
    expect(out.statusChecked).toBe(false);
    expect(out.checks.map((c) => c.check)).toEqual([
      'FILE', 'PAYLOAD_SCHEMA', 'KEY_ID', 'KEY_FOUND', 'DATA_HASH', 'SIGNATURE', 'KEY_STATUS', 'STATUS', 'EXPIRY',
    ]);
    expect(out.checks.filter((c) => c.outcome === 'FAIL')).toEqual([]);
    expect(out.checks.find((c) => c.check === 'STATUS')?.outcome).toBe('NOT_CHECKED');
    expect(out.credential?.dataHash).toBe(computeDataHash(file.payload));
  });

  it('RETIRED key still verifies older credentials', () => {
    const { file, key } = issue({}, 'RETIRED');
    expect(verifyCredentialFile(file, [key], NOW)).toMatchObject({ result: 'VALID', key: { status: 'RETIRED' } });
  });

  it('picks the right key among several published keys', () => {
    const a = issue();
    const b = issue();
    const keys = [{ ...b.key, status: 'RETIRED' }, a.key, { ...issue().key, status: 'COMPROMISED' }];
    expect(verifyCredentialFile(a.file, keys, NOW).result).toBe('VALID');
  });

  it('no expiry date: VALID', () => {
    const { file, key } = issue({ expiresAt: null });
    expect(verifyCredentialFile(file, [key], new Date('2099-01-01T00:00:00Z')).result).toBe('VALID');
  });

  it('payload key order in the file does not matter (RFC 8785)', () => {
    const { file, key } = issue();
    const reversed = Object.fromEntries(Object.entries(file.payload).reverse());
    expect(verifyCredentialFile({ ...file, payload: reversed }, [key], NOW).result).toBe('VALID');
  });
});

describe('verifyCredentialFile: key status', () => {
  it('COMPROMISED key fails even though the signature is genuine', () => {
    const { file, key } = issue({}, 'COMPROMISED');
    const out = verifyCredentialFile(file, [key], NOW);
    expect(out).toMatchObject({ result: 'VERIFICATION_FAILED', reason: 'KEY_COMPROMISED' });
    expect(out.checks.find((c) => c.check === 'SIGNATURE')?.outcome).toBe('PASS');
  });

  it('unknown key status fails closed', () => {
    const { file, key } = issue();
    for (const status of ['REVOKED', 'active', '', 'PENDING']) {
      expect(verifyCredentialFile(file, [{ ...key, status }], NOW)).toMatchObject({
        result: 'VERIFICATION_FAILED',
        reason: 'UNKNOWN_KEY_STATUS',
      });
    }
  });

  it('kid not published: KEY_MISSING; published twice: KEY_AMBIGUOUS', () => {
    const { file, key } = issue();
    expect(verifyCredentialFile(file, [], NOW).reason).toBe('KEY_MISSING');
    expect(verifyCredentialFile(file, [{ ...key, kid: 'kid_other' }], NOW).reason).toBe('KEY_MISSING');
    expect(verifyCredentialFile(file, [key, { ...key, status: 'RETIRED' }], NOW).reason).toBe('KEY_AMBIGUOUS');
  });

  it("another institution's key published under the same kid: SIGNATURE_INVALID", () => {
    const { file, key } = issue();
    const other = issue();
    expect(verifyCredentialFile(file, [{ ...key, publicKey: other.key.publicKey }], NOW).reason).toBe('SIGNATURE_INVALID');
  });

  it('malformed public key: SIGNATURE_INVALID, never VALID', () => {
    const { file, key } = issue();
    for (const publicKey of ['', 'short', key.publicKey + 'AA', key.publicKey.toUpperCase()]) {
      expect(verifyCredentialFile(file, [{ ...key, publicKey }], NOW).result).toBe('VERIFICATION_FAILED');
    }
  });
});

describe('verifyCredentialFile: tamper detection', () => {
  const { file, key } = issue();

  const mutations: Record<string, (p: Record<string, unknown> & { holder: Record<string, unknown>; attributes: Record<string, unknown> }) => void> = {
    credentialId: (p) => { p.credentialId = randomUUID(); },
    credentialNumber: (p) => { p.credentialNumber = 'EAU-2026-AB12CD35'; },
    institutionId: (p) => { p.institutionId = randomUUID(); },
    credentialType: (p) => { p.credentialType = 'CERTIFICATE'; },
    'holder.fullName': (p) => { p.holder.fullName = 'Amina Yusuf '; },
    'holder.externalId': (p) => { p.holder.externalId = 'EAU-0043'; },
    'holder.externalId null': (p) => { p.holder.externalId = null; },
    'holder.photoSha256': (p) => { p.holder.photoSha256 = 'cd'.repeat(31) + 'ce'; },
    'attributes value': (p) => { p.attributes.program = 'Medicine'; },
    'attributes added': (p) => { p.attributes.honours = 'yes'; },
    'attributes removed': (p) => { delete p.attributes.year; },
    issuedAt: (p) => { p.issuedAt = '2026-09-01T00:00:01Z'; },
    expiresAt: (p) => { p.expiresAt = '2030-09-01T00:00:00Z'; },
    'expiresAt removed': (p) => { p.expiresAt = null; },
    salt: (p) => { p.salt = generateSalt(); },
    'salt one char': (p) => { const s = p.salt as string; p.salt = s.slice(0, -1) + (s.endsWith('A') ? 'B' : 'A'); },
    'extra field': (p) => { p.status = 'ACTIVE'; },
    schemaVersion: (p) => { p.schemaVersion = 'igaro.credential.v2'; },
  };

  for (const [name, mutate] of Object.entries(mutations)) {
    it(`changing ${name} fails verification`, () => {
      const t = clone(file) as unknown as { payload: Parameters<typeof mutate>[0] };
      mutate(t.payload);
      const out = verifyCredentialFile(t, [key], NOW);
      expect(out.result).toBe('VERIFICATION_FAILED');
      expect(['HASH_MISMATCH', 'PAYLOAD_INVALID']).toContain(out.reason);
    });
    it(`changing ${name} and recomputing dataHash still fails on the signature`, () => {
      const t = clone(file) as unknown as { payload: Parameters<typeof mutate>[0]; dataHash: string };
      mutate(t.payload);
      try {
        t.dataHash = computeDataHash(t.payload as unknown as CredentialPayloadV1);
      } catch {
        return; // schema-invalid mutation: covered above
      }
      expect(verifyCredentialFile(t, [key], NOW)).toMatchObject({ result: 'VERIFICATION_FAILED', reason: 'SIGNATURE_INVALID' });
    });
  }

  it('changed dataHash: HASH_MISMATCH', () => {
    const h = file.dataHash;
    const t = { ...clone(file), dataHash: (h[0] === 'a' ? 'b' : 'a') + h.slice(1) };
    expect(verifyCredentialFile(t, [key], NOW).reason).toBe('HASH_MISMATCH');
    expect(verifyCredentialFile({ ...clone(file), dataHash: h.toUpperCase() }, [key], NOW).reason).toBe('HASH_MISMATCH');
  });

  it('changed signature byte, non-canonical encoding, or undomained signature: SIGNATURE_INVALID', () => {
    const raw = Buffer.from(file.signature, 'base64url');
    for (let i = 0; i < raw.length; i += 7) {
      const bad = Buffer.from(raw);
      bad[i] = (bad[i] ?? 0) ^ 0x01;
      expect(verifyCredentialFile({ ...clone(file), signature: bad.toString('base64url') }, [key], NOW).reason).toBe('SIGNATURE_INVALID');
    }
    // Same 64 bytes, different last character.
    const canonicalLast = file.signature.at(-1) as string;
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const aliases = [...alphabet].filter(
      (ch) => ch !== canonicalLast && Buffer.from(file.signature.slice(0, -1) + ch, 'base64url').equals(raw),
    );
    expect(aliases.length).toBeGreaterThan(0);
    for (const ch of aliases) {
      expect(verifyCredentialFile({ ...clone(file), signature: file.signature.slice(0, -1) + ch }, [key], NOW).reason).toBe('SIGNATURE_INVALID');
    }
    const { priv } = issue();
    const undomained = edSign(null, Buffer.from(file.dataHash, 'utf8'), priv).toString('base64url');
    expect(verifyCredentialFile({ ...clone(file), signature: undomained }, [key], NOW).reason).toBe('SIGNATURE_INVALID');
  });

  it('file kid differs from the signed issuerKeyId: KID_MISMATCH', () => {
    expect(verifyCredentialFile({ ...clone(file), kid: 'kid_0000000000000000' }, [key], NOW).reason).toBe('KID_MISMATCH');
  });

  it('a payload re-signed by a different key under the original kid fails', () => {
    const attacker = issue();
    const forged = signCredential(file.payload, attacker.priv);
    expect(verifyCredentialFile({ ...clone(file), ...forged, kid: file.kid }, [key], NOW).reason).toBe('SIGNATURE_INVALID');
  });

  it('malformed files fail closed', () => {
    const bad: unknown[] = [undefined, null, 'x', 42, [], {}, { payload: file.payload }, { ...file, dataHash: 1 }, { ...file, signature: null },
      { dataHash: file.dataHash, signature: file.signature, kid: file.kid }, { ...file, payload: null }, { ...file, payload: [] }];
    for (const b of bad) {
      const out = verifyCredentialFile(b, [key], NOW);
      expect(out.result).toBe('VERIFICATION_FAILED');
      expect(['MALFORMED_FILE', 'PAYLOAD_INVALID']).toContain(out.reason);
    }
  });
});

describe('verifyCredentialFile: invariant 7 order', () => {
  it('integrity before key status: tampered + COMPROMISED reports the tamper', () => {
    const { file, key } = issue({}, 'COMPROMISED');
    const t = clone(file);
    t.payload.holder.fullName = 'Someone Else';
    expect(verifyCredentialFile(t, [key], NOW).reason).toBe('HASH_MISMATCH');
  });
  it('integrity before expiry: tampered + expired reports the tamper', () => {
    const { file, key } = issue({ expiresAt: '2026-10-01T00:00:00Z' });
    const t = clone(file);
    t.payload.salt = generateSalt();
    expect(verifyCredentialFile(t, [key], NOW).reason).toBe('HASH_MISMATCH');
  });
  it('key compromise before expiry: expired + COMPROMISED is FAILED, not EXPIRED', () => {
    const { file, key } = issue({ expiresAt: '2026-10-01T00:00:00Z' }, 'COMPROMISED');
    expect(verifyCredentialFile(file, [key], NOW).reason).toBe('KEY_COMPROMISED');
  });
  it('expired (signed expiry) with a trusted key: EXPIRED; boundary instant counts as expired', () => {
    const { file, key } = issue({ expiresAt: '2026-12-31T23:59:59Z' }, 'RETIRED');
    expect(verifyCredentialFile(file, [key], NOW).result).toBe('EXPIRED');
    expect(verifyCredentialFile(file, [key], new Date('2026-12-31T23:59:59Z')).result).toBe('EXPIRED');
    expect(verifyCredentialFile(file, [key], new Date('2026-12-31T23:59:58Z')).result).toBe('VALID');
  });
});

describe('agreement with core verifyCredential (as the API would answer for an ACTIVE credential)', () => {
  const map = { VERIFIED: 'VALID', EXPIRED: 'EXPIRED', VERIFICATION_FAILED: 'VERIFICATION_FAILED' } as Record<string, string>;
  const scenarios: [string, () => { file: ReturnType<typeof issue>['file']; key: PublishedKey }][] = [
    ['valid', () => issue()],
    ['retired', () => issue({}, 'RETIRED')],
    ['compromised', () => issue({}, 'COMPROMISED')],
    ['expired', () => issue({ expiresAt: '2026-10-01T00:00:00Z' })],
    ['tampered', () => { const s = issue(); s.file.payload = { ...s.file.payload, credentialType: 'X' }; return s; }],
    ['bad signature', () => { const s = issue(); s.file.signature = issue().file.signature; return s; }],
  ];
  for (const [name, make] of scenarios) {
    it(name, () => {
      const { file, key } = make();
      const api = verifyCredential({
        record: { id: file.payload.credentialId, institutionId: file.payload.institutionId, status: 'ACTIVE', payload: file.payload, dataHash: file.dataHash, signature: file.signature },
        key: { kid: key.kid, institutionId: file.payload.institutionId, publicKey: key.publicKey, status: key.status as SigningKeyStatus },
        institutionSuspended: false,
        now: NOW,
      });
      expect(verifyCredentialFile(file, [key], NOW).result).toBe(map[api.result]);
    });
  }
});

describe('parseKeysDocument', () => {
  it('accepts the keys.json shape served by /i/:slug/keys.json', () => {
    const { key } = issue();
    const keys = parseKeysDocument({ keys: [{ ...key, createdAt: '2026-01-01T00:00:00.000Z', retiredAt: null }] });
    expect(keys).toHaveLength(1);
    expect(keys[0]?.kid).toBe(key.kid);
  });
  it('rejects malformed documents', () => {
    const { key } = issue();
    for (const doc of [null, [], {}, { keys: {} }, { keys: [null] }, { keys: [{ ...key, kid: '' }] }, { keys: [{ ...key, alg: 'RS256' }] },
      { keys: [{ ...key, publicKey: 5 }] }, { keys: [{ ...key, status: undefined }] }]) {
      expect(() => parseKeysDocument(doc)).toThrow(KeysDocumentError);
    }
  });
});

describe('output hygiene', () => {
  it('the outcome never contains the salt or the signature, for any result', () => {
    for (const status of ['ACTIVE', 'COMPROMISED'] as const) {
      const { file, key } = issue({}, status);
      for (const f of [file, { ...file, dataHash: '0'.repeat(64) }]) {
        const s = JSON.stringify(verifyCredentialFile(f, [key], NOW));
        expect(s).not.toContain(file.payload.salt);
        expect(s).not.toContain(file.signature);
        expect(s).not.toContain(file.payload.holder.externalId as string);
      }
    }
  });
});
