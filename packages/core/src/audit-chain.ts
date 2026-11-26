import { createHash, sign as edSign, verify as edVerify, type KeyObject } from 'node:crypto';
import { canonicalize } from './canonicalize.js';
import { publicKeyFromRaw } from './keys.js';

/** prev_hash of the first entry of every chain. */
export const AUDIT_GENESIS_HASH = '0'.repeat(64);

/** The fields an entry hash commits to. Never contains secrets, tokens or salts. */
export interface AuditEntryContent {
  institutionId: string | null;
  seq: number | string;
  actorId: string | null;
  action: string;
  targetType: string | null;
  targetId: string | null;
  metadata: unknown;
  ip: string | null; // already hashed upstream
  createdAt: string; // ISO-8601 UTC
}

export interface ChainedEntry extends AuditEntryContent { prevHash: string; entryHash: string }

const HEX64 = /^[0-9a-f]{64}$/;

/** entry_hash = SHA-256(prev_hash || JCS(entry)), hex. seq is normalised to a string so bigint columns hash the same. */
export function computeEntryHash(prevHash: string, entry: AuditEntryContent): string {
  if (!HEX64.test(prevHash)) throw new Error('audit: prevHash must be 64 lowercase hex chars');
  const content = {
    institutionId: entry.institutionId, seq: String(entry.seq), actorId: entry.actorId, action: entry.action,
    targetType: entry.targetType, targetId: entry.targetId, metadata: entry.metadata, ip: entry.ip, createdAt: entry.createdAt,
  };
  return createHash('sha256').update(prevHash, 'utf8').update(canonicalize(content), 'utf8').digest('hex');
}

export function chainEntry(prevHash: string | null, entry: AuditEntryContent): ChainedEntry {
  const p = prevHash ?? AUDIT_GENESIS_HASH;
  return { ...entry, prevHash: p, entryHash: computeEntryHash(p, entry) };
}

export type ChainResult =
  | { ok: true; head: string }
  | { ok: false; brokenAtSeq: string; reason: 'PREV_MISMATCH' | 'HASH_MISMATCH' | 'SEQ_GAP' };

/** Recomputes a chain ordered by seq. Compare `head` with the signed daily head hash to catch recomputed chains. */
export function verifyChain(entries: readonly ChainedEntry[], startPrev: string = AUDIT_GENESIS_HASH): ChainResult {
  let prev = startPrev;
  let lastSeq: bigint | null = null;
  for (const e of entries) {
    const seq = BigInt(e.seq);
    if (lastSeq !== null && seq !== lastSeq + 1n) return { ok: false, brokenAtSeq: String(e.seq), reason: 'SEQ_GAP' };
    if (e.prevHash !== prev) return { ok: false, brokenAtSeq: String(e.seq), reason: 'PREV_MISMATCH' };
    if (computeEntryHash(e.prevHash, e) !== e.entryHash) return { ok: false, brokenAtSeq: String(e.seq), reason: 'HASH_MISMATCH' };
    prev = e.entryHash;
    lastSeq = seq;
  }
  return { ok: true, head: prev };
}

/** Domain separation for signed audit chain heads. Never shared with credentials (igaro.credential.sig.v1:). */
export const AUDIT_HEAD_SIGNATURE_DOMAIN = 'igaro.audit.head.sig.v1:';

export interface AuditHeadStatement {
  /** null = the platform chain. */
  institutionId: string | null;
  /** UTC calendar day the head was taken for, YYYY-MM-DD. */
  day: string;
  /** entry_hash of the latest entry of that chain (64 lowercase hex). */
  headHash: string;
}

const DAY = /^\d{4}-\d{2}-\d{2}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Exact bytes that are signed (and timestamped, as SHA-256 of these bytes):
 * "igaro.audit.head.sig.v1:" + (institutionId | "platform") + ":" + day + ":" + headHash.
 * Binding the chain and day stops a head being replayed for another chain or date.
 */
export function auditHeadMessage(s: AuditHeadStatement): Buffer {
  if (!HEX64.test(s.headHash)) throw new Error('audit head: headHash must be 64 lowercase hex chars');
  if (!DAY.test(s.day)) throw new Error('audit head: day must be YYYY-MM-DD');
  if (s.institutionId !== null && !UUID.test(s.institutionId)) {
    throw new Error('audit head: institutionId must be a lowercase uuid or null');
  }
  return Buffer.from(`${AUDIT_HEAD_SIGNATURE_DOMAIN}${s.institutionId ?? 'platform'}:${s.day}:${s.headHash}`, 'utf8');
}

export function signAuditHead(s: AuditHeadStatement, privateKey: KeyObject): string {
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('signing key must be Ed25519');
  return edSign(null, auditHeadMessage(s), privateKey).toString('base64url');
}

/** `publicKey` is a KeyObject or the raw base64url key. Returns false on any malformed input. */
export function verifyAuditHeadSignature(
  s: AuditHeadStatement,
  signature: string,
  publicKey: KeyObject | string,
): boolean {
  try {
    const key = typeof publicKey === 'string' ? publicKeyFromRaw(publicKey) : publicKey;
    if (key.asymmetricKeyType !== 'ed25519' || !/^[A-Za-z0-9_-]{86}$/.test(signature)) return false;
    return edVerify(null, auditHeadMessage(s), key, Buffer.from(signature, 'base64url'));
  } catch {
    return false;
  }
}
