import { createHash } from 'node:crypto';
import { canonicalize } from './canonicalize.js';

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
