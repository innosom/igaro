// Offline verification of a downloaded credential.json against a published keys.json (T-034).
// Pure: no I/O, no clock unless `now` is omitted. Uses @igaro/core for the schema check, RFC 8785 canonicalization, SHA-256
// and Ed25519 verification, so the CLI can never disagree with the API about the bytes.
//
// Order is the offline subset of CLAUDE.md invariant 7 (white paper section 8):
//   file readable -> integrity/signature (FAILED) -> key compromised (FAILED) -> [status: not knowable offline] -> EXPIRED -> VALID
// Integrity is always checked before anything else. Lifecycle status (SUSPENDED/REVOKED/SUPERSEDED) and institution standing live
// outside the signed payload, so an offline verifier cannot see them: VALID means "authentic, unaltered, signed by a trusted key
// and not expired", and the output says so.
import {
  assertCredentialPayload,
  isExpired,
  verifyCredentialIntegrity,
  type CredentialPayloadV1,
  type SigningKeyStatus,
} from '@igaro/core';

export type OfflineResult = 'VALID' | 'EXPIRED' | 'VERIFICATION_FAILED';

export type OfflineReason =
  | 'OK'
  | 'EXPIRED'
  | 'MALFORMED_FILE'
  | 'PAYLOAD_INVALID'
  | 'KID_MISMATCH'
  | 'KEY_MISSING'
  | 'KEY_AMBIGUOUS'
  | 'HASH_MISMATCH'
  | 'SIGNATURE_INVALID'
  | 'KEY_COMPROMISED'
  | 'UNKNOWN_KEY_STATUS';

/** One entry of keys.json (`GET /i/:slug/keys.json`, ADR 0023). */
export interface PublishedKey {
  kid: string;
  alg: 'Ed25519';
  publicKey: string;
  status: string;
  createdAt?: string | null;
  retiredAt?: string | null;
}

export interface CheckLine {
  /** Stable machine name of the check. */
  check: 'FILE' | 'PAYLOAD_SCHEMA' | 'KEY_ID' | 'KEY_FOUND' | 'DATA_HASH' | 'SIGNATURE' | 'KEY_STATUS' | 'STATUS' | 'EXPIRY';
  outcome: 'PASS' | 'FAIL' | 'NOT_CHECKED';
  detail: string;
}

/** Non-secret facts about the credential for display. Never contains the salt, tokens, attributes or externalId. */
export interface CredentialSummary {
  schemaVersion: string;
  credentialNumber: string;
  credentialType: string;
  institutionId: string;
  holderName: string;
  issuedAt: string;
  expiresAt: string | null;
  kid: string;
  dataHash: string;
}

export interface OfflineOutcome {
  result: OfflineResult;
  reason: OfflineReason;
  /** Always false: revocation/suspension cannot be checked without the issuer. */
  statusChecked: false;
  checks: CheckLine[];
  credential?: CredentialSummary;
  key?: { kid: string; status: string };
}

export class KeysDocumentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KeysDocumentError';
  }
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/**
 * Validate a keys.json document. Throws KeysDocumentError (an input problem, not a credential failure) on a malformed document.
 * Entries are kept as published; status strings are judged during verification (unknown statuses fail closed there).
 */
export function parseKeysDocument(doc: unknown): PublishedKey[] {
  if (!isObj(doc) || !Array.isArray(doc.keys)) throw new KeysDocumentError('keys document must be an object with a "keys" array');
  return doc.keys.map((k, i) => {
    if (!isObj(k)) throw new KeysDocumentError(`keys[${i}] is not an object`);
    if (typeof k.kid !== 'string' || k.kid.length === 0) throw new KeysDocumentError(`keys[${i}].kid must be a non-empty string`);
    if (k.alg !== 'Ed25519') throw new KeysDocumentError(`keys[${i}].alg must be "Ed25519"`);
    if (typeof k.publicKey !== 'string') throw new KeysDocumentError(`keys[${i}].publicKey must be a string`);
    if (typeof k.status !== 'string') throw new KeysDocumentError(`keys[${i}].status must be a string`);
    return {
      kid: k.kid,
      alg: 'Ed25519',
      publicKey: k.publicKey,
      status: k.status,
      createdAt: typeof k.createdAt === 'string' ? k.createdAt : null,
      retiredAt: typeof k.retiredAt === 'string' ? k.retiredAt : null,
    };
  });
}

function summarize(p: CredentialPayloadV1, dataHash: string): CredentialSummary {
  return {
    schemaVersion: p.schemaVersion,
    credentialNumber: p.credentialNumber,
    credentialType: p.credentialType,
    institutionId: p.institutionId,
    holderName: p.holder.fullName,
    issuedAt: p.issuedAt,
    expiresAt: p.expiresAt,
    kid: p.issuerKeyId,
    dataHash,
  };
}

const STATUS_NOTE: CheckLine = {
  check: 'STATUS',
  outcome: 'NOT_CHECKED',
  detail: 'revocation/suspension is not part of the signed data and cannot be checked offline; see the verification page',
};

/**
 * Verify a credential file (`GET /api/v1/verify/:token/credential.json`: `{payload, dataHash, signature, kid, publicKeysUrl}`)
 * against the institution's published keys. `credentialFile` is the parsed JSON (or anything: malformed input fails closed).
 */
export function verifyCredentialFile(credentialFile: unknown, keys: readonly PublishedKey[], now: Date = new Date()): OfflineOutcome {
  const checks: CheckLine[] = [];
  const fail = (reason: OfflineReason, extra: Partial<OfflineOutcome> = {}): OfflineOutcome => ({
    result: 'VERIFICATION_FAILED',
    reason,
    statusChecked: false,
    checks,
    ...extra,
  });

  // File shape. Anything unreadable is a failed verification, never a pass.
  const f = credentialFile;
  if (!isObj(f) || typeof f.dataHash !== 'string' || typeof f.signature !== 'string' || typeof f.kid !== 'string' || !('payload' in f)) {
    checks.push({ check: 'FILE', outcome: 'FAIL', detail: 'not an iGARO credential file {payload, dataHash, signature, kid}' });
    return fail('MALFORMED_FILE');
  }
  checks.push({ check: 'FILE', outcome: 'PASS', detail: 'credential file structure' });

  // 2. Integrity and authenticity.
  const payload: unknown = f.payload;
  try {
    assertCredentialPayload(payload);
  } catch {
    // The core error names the offending field only, never its value; still, keep the output generic.
    checks.push({ check: 'PAYLOAD_SCHEMA', outcome: 'FAIL', detail: 'payload does not match igaro.credential.v1' });
    return fail('PAYLOAD_INVALID');
  }
  checks.push({ check: 'PAYLOAD_SCHEMA', outcome: 'PASS', detail: `payload matches ${payload.schemaVersion}` });
  const credential = summarize(payload, f.dataHash);

  if (f.kid !== payload.issuerKeyId) {
    checks.push({ check: 'KEY_ID', outcome: 'FAIL', detail: 'file kid differs from the signed issuerKeyId' });
    return fail('KID_MISMATCH', { credential });
  }
  checks.push({ check: 'KEY_ID', outcome: 'PASS', detail: `signed issuerKeyId ${payload.issuerKeyId}` });

  const matches = keys.filter((k) => k.kid === payload.issuerKeyId);
  if (matches.length === 0) {
    checks.push({ check: 'KEY_FOUND', outcome: 'FAIL', detail: `key ${payload.issuerKeyId} is not in the published keys` });
    return fail('KEY_MISSING', { credential });
  }
  if (matches.length > 1) {
    checks.push({ check: 'KEY_FOUND', outcome: 'FAIL', detail: `key ${payload.issuerKeyId} is published more than once` });
    return fail('KEY_AMBIGUOUS', { credential });
  }
  const key = matches[0] as PublishedKey;
  const keyInfo = { kid: key.kid, status: key.status };
  checks.push({ check: 'KEY_FOUND', outcome: 'PASS', detail: `key ${key.kid} found in published keys (${key.status})` });

  // Recompute SHA-256(JCS(payload)) and compare with the file's dataHash, then check the Ed25519 signature over the
  // domain-separated recomputed hash. Never trusts the file's dataHash on its own.
  const integrity = verifyCredentialIntegrity(payload, f.dataHash, f.signature, key.publicKey);
  if (integrity === 'HASH_MISMATCH') {
    checks.push({ check: 'DATA_HASH', outcome: 'FAIL', detail: 'SHA-256 of the RFC 8785 canonical payload does not match dataHash' });
    return fail('HASH_MISMATCH', { credential, key: keyInfo });
  }
  checks.push({ check: 'DATA_HASH', outcome: 'PASS', detail: 'SHA-256 of the RFC 8785 canonical payload matches dataHash' });
  if (integrity !== 'OK') {
    checks.push({ check: 'SIGNATURE', outcome: 'FAIL', detail: 'Ed25519 signature does not verify with the published key' });
    return fail('SIGNATURE_INVALID', { credential, key: keyInfo });
  }
  checks.push({ check: 'SIGNATURE', outcome: 'PASS', detail: 'Ed25519 signature verifies with the published key' });

  // 3. Key still trusted? RETIRED keys keep verifying older credentials; COMPROMISED fails everything it signed.
  const status = key.status as SigningKeyStatus;
  if (status === 'COMPROMISED') {
    checks.push({ check: 'KEY_STATUS', outcome: 'FAIL', detail: 'signing key is marked COMPROMISED by the institution' });
    return fail('KEY_COMPROMISED', { credential, key: keyInfo });
  }
  if (status !== 'ACTIVE' && status !== 'RETIRED') {
    checks.push({ check: 'KEY_STATUS', outcome: 'FAIL', detail: 'signing key has an unrecognised status' });
    return fail('UNKNOWN_KEY_STATUS', { credential, key: keyInfo });
  }
  checks.push({ check: 'KEY_STATUS', outcome: 'PASS', detail: `signing key is ${status}` });

  // 4. Lifecycle status: not knowable offline.
  checks.push(STATUS_NOTE);

  // 5. Expiry from the signed (now proven authentic) expiresAt.
  if (isExpired(payload.expiresAt, now)) {
    checks.push({ check: 'EXPIRY', outcome: 'FAIL', detail: `expired at ${payload.expiresAt}` });
    return { result: 'EXPIRED', reason: 'EXPIRED', statusChecked: false, checks, credential, key: keyInfo };
  }
  checks.push({
    check: 'EXPIRY',
    outcome: 'PASS',
    detail: payload.expiresAt === null ? 'no expiry date' : `valid until ${payload.expiresAt}`,
  });

  return { result: 'VALID', reason: 'OK', statusChecked: false, checks, credential, key: keyInfo };
}
