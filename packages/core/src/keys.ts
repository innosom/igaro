import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  type KeyObject,
} from 'node:crypto';

/** Envelope version prefix. Changing the format requires a new prefix. */
const ENVELOPE_PREFIX = 'igaro.key.v1';
const MASTER_KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export interface GeneratedSigningKey {
  /** Key id, unique per key pair, safe to publish. */
  kid: string;
  /** Raw 32-byte Ed25519 public key, base64url. Published in keys.json. */
  publicKey: string;
  /** AES-256-GCM envelope of the PKCS#8 private key, bound to the kid. Safe to store in the DB. */
  encryptedPrivateKey: string;
}

/** Parse a master key supplied as base64 (standard or url) or 64-char hex. Never echoes the input in errors. */
export function parseMasterKey(value: string): Buffer {
  const v = value.trim();
  const buf = /^[0-9a-fA-F]{64}$/.test(v) ? Buffer.from(v, 'hex') : Buffer.from(v, 'base64');
  if (buf.length !== MASTER_KEY_BYTES) {
    throw new Error(`master key must decode to exactly ${MASTER_KEY_BYTES} bytes`);
  }
  return buf;
}

function assertAad(aad: string): void {
  if (typeof aad !== 'string' || aad.length === 0) throw new Error('key envelope requires a non-empty kid binding');
}

function assertMasterKey(masterKey: Buffer): void {
  if (!Buffer.isBuffer(masterKey) || masterKey.length !== MASTER_KEY_BYTES) {
    throw new Error(`master key must be exactly ${MASTER_KEY_BYTES} bytes`);
  }
}

export function generateKid(): string {
  return `kid_${randomBytes(8).toString('hex')}`;
}

/**
 * Wrap plaintext under the master key with AES-256-GCM. The associated data (kid) is
 * authenticated, so an envelope cannot be moved to a different key row.
 */
export function wrapSecret(plaintext: Buffer, masterKey: Buffer, aad: string): string {
  assertMasterKey(masterKey);
  assertAad(aad);
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', masterKey, iv);
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [ENVELOPE_PREFIX, iv.toString('base64url'), ct.toString('base64url'), tag.toString('base64url')].join('.');
}

export function unwrapSecret(envelope: string, masterKey: Buffer, aad: string): Buffer {
  assertMasterKey(masterKey);
  assertAad(aad);
  const parts = envelope.split('.');
  // the prefix itself contains two dots: igaro . key . v1
  const [p1, p2, p3, ivB, ctB, tagB] = parts;
  if (parts.length !== 6 || `${p1}.${p2}.${p3}` !== ENVELOPE_PREFIX || !ivB || !ctB || !tagB) {
    throw new Error('invalid key envelope');
  }
  const iv = Buffer.from(ivB, 'base64url');
  const tag = Buffer.from(tagB, 'base64url');
  if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) throw new Error('invalid key envelope');
  try {
    const decipher = createDecipheriv('aes-256-gcm', masterKey, iv);
    decipher.setAAD(Buffer.from(aad, 'utf8'));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(Buffer.from(ctB, 'base64url')), decipher.final()]);
  } catch {
    throw new Error('key envelope authentication failed');
  }
}

/** Generate an Ed25519 key pair with a fresh kid; the private key is returned only in wrapped form. */
export function generateSigningKey(masterKey: Buffer): GeneratedSigningKey {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const kid = generateKid();
  const pkcs8 = privateKey.export({ type: 'pkcs8', format: 'der' });
  try {
    const spki = publicKey.export({ type: 'spki', format: 'der' });
    return {
      kid,
      publicKey: spki.subarray(ED25519_SPKI_PREFIX.length).toString('base64url'),
      encryptedPrivateKey: wrapSecret(pkcs8, masterKey, kid),
    };
  } finally {
    pkcs8.fill(0);
  }
}

/** Decrypt a private key. Call only at the moment of signing; do not cache or log the result. */
export function unwrapPrivateKey(encryptedPrivateKey: string, masterKey: Buffer, kid: string): KeyObject {
  const der = unwrapSecret(encryptedPrivateKey, masterKey, kid);
  try {
    return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  } finally {
    der.fill(0);
  }
}

/** Build a public KeyObject from the raw base64url form stored/published for a kid. */
export function publicKeyFromRaw(publicKey: string): KeyObject {
  const raw = Buffer.from(publicKey, 'base64url');
  if (raw.length !== 32) throw new Error('invalid Ed25519 public key');
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
}
