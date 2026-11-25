// Audit log service (T-024, invariant 6). Appends hash-chained entries to a per-institution chain
// (institution_id NULL = platform chain). Every append runs inside the caller's transaction, so the
// audited change and its audit entry commit or roll back together.
//
// Chain integrity: a transaction-scoped advisory lock keyed on the chain serialises writers, so the
// predecessor read and the insert cannot interleave (one entry at a time per institution). The DB
// also enforces UNIQUE NULLS NOT DISTINCT (institution_id, seq) and (institution_id, prev_hash), so a
// forked chain is refused even if the lock were bypassed. The igaro_app role has SELECT and INSERT
// only on audit_logs plus a no-update/delete trigger (migration 20261124010000).
//
// Entries never carry secrets (invariant 9): metadata keys are checked against a deny-list and the IP
// is stored only as the keyed hash handed in by the caller (ADR 0003).
import { randomUUID } from 'node:crypto';
import type { PoolClient } from 'pg';
import {
  AUDIT_GENESIS_HASH,
  computeEntryHash,
  verifyChain,
  type ChainResult,
  type ChainedEntry,
} from '@igaro/core';

export interface AuditInput {
  /** NULL for the platform-level chain. */
  institutionId: string | null;
  actorId: string | null;
  action: string;
  targetType?: string | null;
  targetId?: string | null;
  metadata?: Record<string, unknown>;
  /** Already hashed (hashIp). Never a raw address. */
  ip?: string | null;
}

const FORBIDDEN_KEY = /token|secret|password|salt|private|key|cookie|authorization/i;

/** JSON round-trip (drops undefined, matches what JSONB returns) and refuse secret-looking keys. */
export function normaliseMetadata(m: Record<string, unknown> | undefined): Record<string, unknown> {
  const out: unknown = JSON.parse(JSON.stringify(m ?? {}));
  const walk = (v: unknown): void => {
    if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === 'object') {
      for (const [k, x] of Object.entries(v)) {
        if (FORBIDDEN_KEY.test(k)) throw new TypeError(`audit metadata key "${k}" is not allowed`);
        walk(x);
      }
    }
  };
  walk(out);
  return out as Record<string, unknown>;
}

export type AuditRecord = ChainedEntry & { id: string };

/** Append one entry. Call inside a transaction (Db.withTenant) that already carries the right scope. */
export async function appendAudit(c: PoolClient, input: AuditInput): Promise<AuditRecord> {
  const metadata = normaliseMetadata(input.metadata);
  // Lock before reading the head so concurrent appends to the same chain queue up.
  await c.query(`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, [
    `igaro.audit:${input.institutionId ?? 'platform'}`,
  ]);
  const last = (
    await c.query<{ seq: string; entry_hash: string }>(
      `SELECT seq::text AS seq, entry_hash FROM audit_logs
        WHERE ${input.institutionId === null ? 'institution_id IS NULL' : 'institution_id = $1::uuid'}
        ORDER BY audit_logs.seq DESC LIMIT 1`, // qualified: bare "seq" would sort the text alias lexically (and equality can use the index)
      input.institutionId === null ? [] : [input.institutionId],
    )
  ).rows[0];
  const seq = last ? (BigInt(last.seq) + 1n).toString() : '1';
  const prevHash = last ? last.entry_hash : AUDIT_GENESIS_HASH;
  // Written explicitly (ADR 0014): the hash commits to this exact millisecond string.
  const createdAt = new Date().toISOString();
  const content = {
    institutionId: input.institutionId,
    seq,
    actorId: input.actorId,
    action: input.action,
    targetType: input.targetType ?? null,
    targetId: input.targetId ?? null,
    metadata,
    ip: input.ip ?? null,
    createdAt,
  };
  const entryHash = computeEntryHash(prevHash, content);
  const id = randomUUID();
  await c.query(
    `INSERT INTO audit_logs
       (id, institution_id, seq, actor_id, action, target_type, target_id, metadata, ip, created_at, prev_hash, entry_hash)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10::timestamptz,$11,$12)`,
    [
      id, content.institutionId, seq, content.actorId, content.action, content.targetType,
      content.targetId, JSON.stringify(metadata), content.ip, createdAt, prevHash, entryHash,
    ],
  );
  return { id, ...content, prevHash, entryHash };
}

/** Read a whole chain in order and recompute it (T-027 exposes this over HTTP). */
export async function verifyAuditChain(
  c: PoolClient,
  institutionId: string | null,
): Promise<ChainResult & { count: number }> {
  const rows = (
    await c.query(
      `SELECT institution_id, seq::text AS seq, actor_id, action, target_type, target_id, metadata, ip,
              to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
              prev_hash, entry_hash
         FROM audit_logs WHERE institution_id IS NOT DISTINCT FROM $1::uuid ORDER BY audit_logs.seq`,
      [institutionId],
    )
  ).rows;
  const entries: ChainedEntry[] = rows.map((r) => ({
    institutionId: r.institution_id, seq: r.seq, actorId: r.actor_id, action: r.action,
    targetType: r.target_type, targetId: r.target_id, metadata: r.metadata, ip: r.ip,
    createdAt: r.created_at, prevHash: r.prev_hash, entryHash: r.entry_hash,
  }));
  return { ...verifyChain(entries), count: entries.length };
}
