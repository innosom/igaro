import { createHash, randomBytes, sign as edSign, verify as edVerify, type KeyObject } from 'node:crypto';
import { canonicalize } from './canonicalize.js';
import { publicKeyFromRaw } from './keys.js';

export const CREDENTIAL_SCHEMA_VERSION = 'igaro.credential.v1';
export const SIGNATURE_DOMAIN_PREFIX = 'igaro.credential.sig.v1:';

export interface CredentialPayloadV1 {
  schemaVersion: typeof CREDENTIAL_SCHEMA_VERSION;
  credentialId: string;
  credentialNumber: string;
  institutionId: string;
  issuerKeyId: string;
  credentialType: string;
  holder: { fullName: string; externalId: string | null; photoSha256: string };
  attributes: Record<string, string>;
  issuedAt: string;
  expiresAt: string | null;
  /** 32 random bytes, base64url (256 bits). */
  salt: string;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const B64URL_SIG = /^[A-Za-z0-9_-]{86}$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const B64URL_32 = /^[A-Za-z0-9_-]{43}$/;

/** 256-bit random salt as base64url. */
export function generateSalt(): string {
  return randomBytes(32).toString('base64url');
}

function isIsoUtc(v: unknown): v is string {
  if (typeof v !== 'string' || !ISO_UTC.test(v)) return false;
  const t = Date.parse(v);
  // Round-trip so impossible dates (Feb 30, T24:00) are refused instead of rolling over.
  return !Number.isNaN(t) && new Date(t).toISOString().slice(0, 19) + 'Z' === v;
}

/** Throws on any deviation from the igaro.credential.v1 shape (unknown keys included). */
export function assertCredentialPayload(p: unknown): asserts p is CredentialPayloadV1 {
  const fail = (m: string): never => {
    throw new Error('invalid credential payload: ' + m);
  };
  if (typeof p !== 'object' || p === null || Array.isArray(p)) return fail('not an object');
  const o = p as Record<string, unknown>;
  const allowed = ['schemaVersion', 'credentialId', 'credentialNumber', 'institutionId', 'issuerKeyId',
    'credentialType', 'holder', 'attributes', 'issuedAt', 'expiresAt', 'salt'];
  for (const k of Object.keys(o)) if (!allowed.includes(k)) fail('unknown field ' + k);
  for (const k of allowed) if (!(k in o)) fail('missing field ' + k);
  if (o.schemaVersion !== CREDENTIAL_SCHEMA_VERSION) fail('schemaVersion');
  if (typeof o.credentialId !== 'string' || !UUID.test(o.credentialId)) fail('credentialId');
  if (typeof o.institutionId !== 'string' || !UUID.test(o.institutionId)) fail('institutionId');
  for (const k of ['credentialNumber', 'issuerKeyId', 'credentialType'] as const) {
    if (typeof o[k] !== 'string' || (o[k] as string).length === 0) fail(k);
  }
  const h = o.holder as Record<string, unknown> | null;
  if (typeof h !== 'object' || h === null || Array.isArray(h)) return fail('holder');
  for (const k of Object.keys(h)) if (!['fullName', 'externalId', 'photoSha256'].includes(k)) fail('unknown holder field ' + k);
  if (typeof h.fullName !== 'string' || h.fullName.length === 0) fail('holder.fullName');
  if (h.externalId !== null && typeof h.externalId !== 'string') fail('holder.externalId');
  if (typeof h.photoSha256 !== 'string' || !SHA256_HEX.test(h.photoSha256)) fail('holder.photoSha256');
  const a = o.attributes as Record<string, unknown> | null;
  if (typeof a !== 'object' || a === null || Array.isArray(a)) return fail('attributes');
  for (const v of Object.values(a)) if (typeof v !== 'string') fail('attributes values must be strings');
  if (!isIsoUtc(o.issuedAt)) fail('issuedAt');
  if (o.expiresAt !== null && !isIsoUtc(o.expiresAt)) fail('expiresAt');
  if (typeof o.salt !== 'string' || !B64URL_32.test(o.salt)) fail('salt');
}

/** RFC 8785 canonical form of the payload. */
export function canonicalPayload(payload: CredentialPayloadV1): string {
  assertCredentialPayload(payload);
  return canonicalize(payload);
}

/** dataHash = lowercase hex SHA-256(JCS(payload)). */
export function computeDataHash(payload: CredentialPayloadV1): string {
  return createHash('sha256').update(canonicalPayload(payload), 'utf8').digest('hex');
}

export function signingMessage(dataHash: string): Buffer {
  if (!SHA256_HEX.test(dataHash)) throw new Error('dataHash must be 64 lowercase hex characters');
  return Buffer.from(SIGNATURE_DOMAIN_PREFIX + dataHash, 'utf8');
}

/** signature = Ed25519(key, "igaro.credential.sig.v1:" + dataHash), base64url. */
export function signDataHash(dataHash: string, privateKey: KeyObject): string {
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('signing key must be Ed25519');
  return edSign(null, signingMessage(dataHash), privateKey).toString('base64url');
}

export interface SignedCredential {
  dataHash: string;
  signature: string;
  issuerKeyId: string;
}

export function signCredential(payload: CredentialPayloadV1, privateKey: KeyObject): SignedCredential {
  const dataHash = computeDataHash(payload);
  return { dataHash, signature: signDataHash(dataHash, privateKey), issuerKeyId: payload.issuerKeyId };
}

/** Verify a signature over a dataHash. `publicKey` is a KeyObject or the raw base64url key from keys.json. */
export function verifyDataHashSignature(dataHash: string, signature: string, publicKey: KeyObject | string): boolean {
  try {
    const key = typeof publicKey === 'string' ? publicKeyFromRaw(publicKey) : publicKey;
    if (key.asymmetricKeyType !== 'ed25519' || !B64URL_SIG.test(signature)) return false;
    const sig = Buffer.from(signature, 'base64url');
    // Canonical encoding only: the last of the 86 characters carries 4 unused bits, so without this check several
    // different strings would decode to the same 64 bytes and a one-character edit could still verify.
    if (sig.length !== 64 || sig.toString('base64url') !== signature) return false;
    return edVerify(null, signingMessage(dataHash), key, sig);
  } catch {
    return false;
  }
}

export type IntegrityResult = 'OK' | 'HASH_MISMATCH' | 'SIGNATURE_INVALID';

/** Recompute the hash from the stored payload (never trust the stored dataHash), then check the signature. */
export function verifyCredentialIntegrity(
  payload: unknown,
  storedDataHash: string,
  signature: string,
  publicKey: KeyObject | string,
): IntegrityResult {
  let recomputed: string;
  try {
    assertCredentialPayload(payload);
    recomputed = computeDataHash(payload);
  } catch {
    return 'HASH_MISMATCH';
  }
  if (recomputed !== storedDataHash) return 'HASH_MISMATCH';
  return verifyDataHashSignature(recomputed, signature, publicKey) ? 'OK' : 'SIGNATURE_INVALID';
}
