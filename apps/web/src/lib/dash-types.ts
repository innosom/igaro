// Response shapes of the institution-admin API (docs/api.md). Types only.
import type { AttributeDef } from './dashboard';

export interface Profile {
  id: string;
  name: string;
  slug: string;
  status: string;
  cardTitle: string | null;
  primaryColor: string | null;
  secondaryColor: string | null;
  publicFields: string[];
  hasLogo: boolean;
  updatedAt: string;
}

export interface SigningKey {
  kid: string;
  algorithm: string;
  publicKey: string;
  status: 'ACTIVE' | 'RETIRED' | 'COMPROMISED';
  createdAt: string;
  retiredAt: string | null;
}

export interface Holder {
  id: string;
  fullName: string;
  externalId: string | null;
  email: string | null;
  hasPhoto: boolean;
  photoSha256: string | null;
  credentialCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface CredentialType {
  id: string;
  code: string;
  name: string;
  kind: 'ID_CARD' | 'CERTIFICATE';
  attributes: AttributeDef[];
  defaultValidityDays: number | null;
  credentialCount: number;
}

export interface CredentialRow {
  id: string;
  credentialNumber: string;
  status: string;
  holder: { id: string; fullName: string };
  type: { code: string; name: string };
  issuedAt: string | null;
  expiresAt: string | null;
  supersededBy: string | null;
  createdAt: string;
}

export interface CredentialDetail extends CredentialRow {
  storedStatus: string;
  attributes: Record<string, string>;
  dataHash: string;
  signature: string;
  issuerKeyId: string;
  anchorStatus: string;
  events: { id: string; type: string; payload: Record<string, unknown>; createdAt: string }[];
}

export interface IssuedCredential {
  id: string;
  credentialNumber: string;
  verificationToken: string;
  holderToken: string;
}

export interface Stats {
  total: number;
  byStatus: Record<string, number>;
}

export interface AuditEntry {
  id: string;
  seq: number | string;
  actorId: string | null;
  action: string;
  targetType: string | null;
  targetId: string | null;
  metadata: Record<string, unknown> | null;
  createdAt: string;
  entryHash: string;
}

export interface ChainResult {
  valid: boolean;
  entries: number;
  head?: string;
  brokenAtSeq?: number | string;
  reason?: string;
  headsRecorded: boolean;
  signedHeads: { checked: number; matched: number; mismatchedDays: string[] };
}
