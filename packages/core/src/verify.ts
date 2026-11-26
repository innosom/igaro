import type { CredentialStatus } from './lifecycle.js';
import { isExpired } from './lifecycle.js';
import { verifyCredentialIntegrity, assertCredentialPayload } from './credential.js';

/**
 * Verification algorithm (CLAUDE.md invariant 7, white paper section 8). Pure: callers load the record and pass it in.
 * Order: NOT_FOUND -> integrity (FAILED) -> key compromised (FAILED) -> REVOKED/SUSPENDED/SUPERSEDED -> EXPIRED
 * -> institution suspended (VALID_WITH_WARNING) -> VERIFIED. Integrity always precedes status.
 */
export type VerificationResult =
  | 'VERIFIED'
  | 'VALID_WITH_WARNING'
  | 'SUSPENDED'
  | 'REVOKED'
  | 'SUPERSEDED'
  | 'EXPIRED'
  | 'NOT_FOUND'
  | 'VERIFICATION_FAILED';

export type VerificationReason =
  | 'NOT_FOUND'
  | 'DRAFT'
  | 'HASH_MISMATCH'
  | 'SIGNATURE_INVALID'
  | 'KEY_MISSING'
  | 'BINDING_MISMATCH'
  | 'UNKNOWN_STATE'
  | 'KEY_COMPROMISED'
  | 'STATUS'
  | 'EXPIRED'
  | 'INSTITUTION_SUSPENDED'
  | 'OK';

export type SigningKeyStatus = 'ACTIVE' | 'RETIRED' | 'COMPROMISED';

export interface VerificationInput {
  /** Null/undefined when the token matched no credential. */
  record: {
    /** Row identity: must match the signed payload, so a signed payload cannot be moved between rows or tenants. */
    id: string;
    institutionId: string;
    status: CredentialStatus;
    /** The stored signed payload, as read from the database. */
    payload: unknown;
    dataHash: string;
    signature: string;
    supersededByCredentialId?: string | null;
  } | null | undefined;
  /** The institution's key row for the payload's issuerKeyId; null if absent. `kid` must equal payload.issuerKeyId. */
  key: { kid: string; institutionId: string; publicKey: string; status: SigningKeyStatus } | null | undefined;
  institutionSuspended: boolean;
  now?: Date;
}

export interface VerificationOutcome {
  result: VerificationResult;
  reason: VerificationReason;
  /** True only for integrity failures: the caller must raise an operations alert. */
  alertOps: boolean;
  supersededByCredentialId?: string | null;
}

const fail = (reason: VerificationReason, alertOps: boolean): VerificationOutcome =>
  ({ result: 'VERIFICATION_FAILED', reason, alertOps });

export function verifyCredential(input: VerificationInput): VerificationOutcome {
  const { record, key } = input;
  // 1. Exists? Missing or still a draft is indistinguishable from unknown.
  if (!record) return { result: 'NOT_FOUND', reason: 'NOT_FOUND', alertOps: false };
  if (record.status === 'DRAFT') return { result: 'NOT_FOUND', reason: 'DRAFT', alertOps: false };

  // 2. Unaltered and authentic? Always before status, so tampering never shows as a clean "revoked".
  try {
    assertCredentialPayload(record.payload);
  } catch {
    return fail('HASH_MISMATCH', true);
  }
  const payload = record.payload;
  if (!key || key.kid !== payload.issuerKeyId || key.institutionId !== payload.institutionId) return fail('KEY_MISSING', true);
  // Bind the signed payload to the row (and tenant) it was read from.
  if (payload.credentialId !== record.id || payload.institutionId !== record.institutionId) return fail('BINDING_MISMATCH', true);
  const integrity = verifyCredentialIntegrity(payload, record.dataHash, record.signature, key.publicKey);
  if (integrity !== 'OK') return fail(integrity, true);

  // 3. Key still trusted? (RETIRED keys keep verifying older credentials.)
  if (key.status === 'COMPROMISED') return fail('KEY_COMPROMISED', false);
  if (key.status !== 'ACTIVE' && key.status !== 'RETIRED') return fail('UNKNOWN_STATE', true);

  // 4. Status.
  if (record.status === 'REVOKED' || record.status === 'SUSPENDED' || record.status === 'SUPERSEDED') {
    return {
      result: record.status,
      reason: 'STATUS',
      alertOps: false,
      ...(record.status === 'SUPERSEDED' ? { supersededByCredentialId: record.supersededByCredentialId ?? null } : {}),
    };
  }

  // Fail closed on any other status (EXPIRED is never stored).
  if (record.status !== 'ACTIVE') return fail('UNKNOWN_STATE', true);

  // 5. Expired? Uses the signed expiry (the payload has just been proven authentic).
  if (isExpired(payload.expiresAt, input.now)) return { result: 'EXPIRED', reason: 'EXPIRED', alertOps: false };

  // 6. Institution in good standing?
  if (input.institutionSuspended) return { result: 'VALID_WITH_WARNING', reason: 'INSTITUTION_SUSPENDED', alertOps: false };

  // 7. Otherwise verified.
  return { result: 'VERIFIED', reason: 'OK', alertOps: false };
}
