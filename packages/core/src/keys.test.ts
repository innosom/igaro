import { randomBytes, sign, verify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  generateSigningKey,
  parseMasterKey,
  publicKeyFromRaw,
  unwrapPrivateKey,
  unwrapSecret,
  wrapSecret,
} from './keys.js';

const mk = randomBytes(32);

describe('signing key generation', () => {
  it('generates a kid, raw public key and wrapped private key', () => {
    const k = generateSigningKey(mk);
    expect(k.kid).toMatch(/^kid_[0-9a-f]{16}$/);
    expect(Buffer.from(k.publicKey, 'base64url')).toHaveLength(32);
    expect(k.encryptedPrivateKey.startsWith('igaro.key.v1.')).toBe(true);
    expect(generateSigningKey(mk).kid).not.toBe(k.kid);
  });

  it('round-trips: unwrapped key signs, published public key verifies', () => {
    const k = generateSigningKey(mk);
    const priv = unwrapPrivateKey(k.encryptedPrivateKey, mk, k.kid);
    const msg = Buffer.from('hello');
    const sig = sign(null, msg, priv);
    expect(verify(null, msg, publicKeyFromRaw(k.publicKey), sig)).toBe(true);
  });

  it('does not contain the plaintext private key in the envelope', () => {
    const k = generateSigningKey(mk);
    const priv = unwrapPrivateKey(k.encryptedPrivateKey, mk, k.kid);
    const der = priv.export({ type: 'pkcs8', format: 'der' });
    expect(k.encryptedPrivateKey).not.toContain(der.toString('base64url'));
  });
});

describe('AES-256-GCM wrapping', () => {
  it('rejects the wrong master key', () => {
    const k = generateSigningKey(mk);
    expect(() => unwrapPrivateKey(k.encryptedPrivateKey, randomBytes(32), k.kid)).toThrow('authentication failed');
  });
  it('rejects a different kid (envelope bound to key row)', () => {
    const k = generateSigningKey(mk);
    expect(() => unwrapPrivateKey(k.encryptedPrivateKey, mk, 'kid_0000000000000000')).toThrow();
  });
  it('rejects tampered ciphertext', () => {
    const e = wrapSecret(Buffer.from('secret'), mk, 'a').split('.');
    e[4] = Buffer.from('xxxxxx').toString('base64url');
    expect(() => unwrapSecret(e.join('.'), mk, 'a')).toThrow();
  });
  it('rejects malformed envelopes and bad master key length', () => {
    expect(() => unwrapSecret('garbage', mk, 'a')).toThrow('invalid key envelope');
    expect(() => wrapSecret(Buffer.from('x'), randomBytes(16), 'a')).toThrow('exactly 32 bytes');
  });
  it('rejects an empty kid binding', () => {
    expect(() => wrapSecret(Buffer.from('x'), mk, '')).toThrow('non-empty');
    expect(() => unwrapSecret('x', mk, '')).toThrow('non-empty');
  });
  it('uses a fresh IV per wrap', () => {
    expect(wrapSecret(Buffer.from('x'), mk, 'a')).not.toBe(wrapSecret(Buffer.from('x'), mk, 'a'));
  });
});

describe('parseMasterKey', () => {
  it('accepts base64 and hex of 32 bytes', () => {
    const b = randomBytes(32);
    expect(parseMasterKey(b.toString('base64')).equals(b)).toBe(true);
    expect(parseMasterKey(b.toString('hex')).equals(b)).toBe(true);
  });
  it('rejects wrong length without echoing the value', () => {
    expect(() => parseMasterKey('REPLACE_ME_short')).toThrow('exactly 32 bytes');
    try {
      parseMasterKey('REPLACE_ME_short');
    } catch (e) {
      expect(String(e)).not.toContain('REPLACE_ME_short');
    }
  });
});
