// audit.dailyHead (T-028, ADR 0019, invariant 6). For every audit chain (each institution plus the
// platform chain) take the latest entry_hash, sign it with the PLATFORM head key under the
// "igaro.audit.head.sig.v1:" domain, insert it into audit_head_hashes (idempotent per chain and day),
// submit it to OpenTimestamps and, on later runs, upgrade pending proofs. Proofs live in the
// append-only audit_head_timestamps table because audit_head_hashes refuses UPDATE.
//
// The worker never reads institution_keys and never holds an institution signing key (v1.0 section 5).
// Every chain is handled in its own transaction scoped by RLS settings (app.institution_id; platform
// scope only to list institutions and to write the NULL platform chain). Logs carry ids and counts only.
import { createHash, randomUUID, type KeyObject } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { auditHeadMessage, signAuditHead, unwrapPrivateKey, parseMasterKey } from '@igaro/core';
import type { Logger } from 'pino';
import { isCompleteProof, OtsError, type Timestamper } from './ots.js';

export const AUDIT_DAILY_HEAD_QUEUE = 'audit.dailyHead';
/** 00:10 UTC every day. */
export const AUDIT_DAILY_HEAD_CRON = '10 0 * * *';

/** Retry with exponential backoff; a failed run is safe to repeat (idempotent per chain and day). */
export const AUDIT_DAILY_HEAD_QUEUE_OPTIONS = {
  retryLimit: 6,
  retryDelay: 60,
  retryBackoff: true,
  expireInSeconds: 15 * 60,
  retentionSeconds: 7 * 24 * 3600,
} as const;

export interface HeadSigner {
  kid: string;
  /** Called once per run; the key object is dropped at the end of the run (never cached). */
  load(): KeyObject;
}

/** Platform head key: an igaro.key.v1 envelope under AUDIT_HEAD_WRAP_KEY (never MASTER_KEY), bound to its kid. */
export function headSignerFromEnvelope(envelope: string, wrapKeyRaw: string, kid: string): HeadSigner {
  const wrap = parseMasterKey(wrapKeyRaw);
  return { kid, load: () => unwrapPrivateKey(envelope, wrap, kid) };
}

/** Startup self-check (M2): the connected role must be able to INSERT signed heads. Fails loudly. */
export async function assertHeadInsertPrivilege(pool: Pool, assumeRole?: string): Promise<void> {
  const c = await pool.connect();
  try {
    if (assumeRole) {
      if (!/^[a-z_][a-z0-9_]*$/.test(assumeRole)) throw new Error('invalid role name');
      await c.query('BEGIN');
      await c.query(`SET LOCAL ROLE ${assumeRole}`);
    }
    const r = await c.query<{ ok: boolean }>(
      `SELECT has_table_privilege(current_user, 'audit_head_hashes', 'INSERT') AS ok`,
    );
    if (assumeRole) await c.query('ROLLBACK');
    if (r.rows[0]?.ok !== true) {
      throw new Error(
        'audit head startup check failed: the database role has no INSERT on audit_head_hashes (use the igaro_worker login via WORKER_DATABASE_URL)',
      );
    }
  } finally {
    c.release();
  }
}

export interface AuditHeadDeps {
  /** Pool whose role is igaro_worker (or a superuser in tests together with assumeRole). */
  pool: Pool;
  signer: HeadSigner;
  timestamper: Timestamper;
  logger: Logger;
  /** Tests connect as the owner and switch with SET LOCAL ROLE. Production connects as igaro_worker. */
  assumeRole?: string;
  now?: () => Date;
  /** Max heads handled per chain per run for timestamp submit / upgrade. */
  batchLimit?: number;
}

export interface AuditHeadSummary {
  chains: number;
  signed: number;
  alreadyDone: number;
  empty: number;
  submitted: number;
  upgraded: number;
  stillPending: number;
  failures: number;
}

type Chain = string | null;

async function scoped<T>(deps: AuditHeadDeps, chain: Chain | 'list', fn: (c: PoolClient) => Promise<T>): Promise<T> {
  const c = await deps.pool.connect();
  try {
    await c.query('BEGIN');
    if (deps.assumeRole) {
      if (!/^[a-z_][a-z0-9_]*$/.test(deps.assumeRole)) throw new Error('invalid role name');
      await c.query(`SET LOCAL ROLE ${deps.assumeRole}`);
    }
    if (typeof chain === 'string' && chain !== 'list') {
      await c.query(`SELECT set_config('app.institution_id', $1, true)`, [chain]);
    } else {
      // Listing institutions and writing the NULL platform chain need platform scope.
      await c.query(`SELECT set_config('app.is_platform_admin', 'true', true)`);
    }
    const out = await fn(c);
    await c.query('COMMIT');
    return out;
  } catch (e) {
    await c.query('ROLLBACK').catch(() => undefined);
    throw e;
  } finally {
    c.release();
  }
}

/** Log-safe error summary: driver messages can echo row values, so only our own OtsError text is kept. */
function safeErr(err: unknown): { errName: string; errCode?: string; errMessage?: string } {
  const e = err as { name?: string; code?: string };
  return {
    errName: e?.name ?? 'Error',
    ...(typeof e?.code === 'string' ? { errCode: e.code } : {}),
    ...(err instanceof OtsError ? { errMessage: err.message } : {}),
  };
}

const utcDay =(d: Date): string => d.toISOString().slice(0, 10);

interface HeadRow {
  id: string;
  day: string;
  head_hash: string;
}

export async function runAuditDailyHead(deps: AuditHeadDeps): Promise<AuditHeadSummary> {
  const { logger } = deps;
  const day = utcDay((deps.now ?? (() => new Date()))());
  const limit = deps.batchLimit ?? 200;
  const summary: AuditHeadSummary = {
    chains: 0, signed: 0, alreadyDone: 0, empty: 0, submitted: 0, upgraded: 0, stillPending: 0, failures: 0,
  };

  const ids = await scoped(deps, 'list', async (c) =>
    (await c.query<{ id: string }>('SELECT id FROM institutions ORDER BY id')).rows.map((r) => r.id),
  );
  const chains: Chain[] = [null, ...ids];
  summary.chains = chains.length;

  let key: KeyObject | undefined;
  try {
    for (const chain of chains) {
      try {
        // 1. Sign today's head (idempotent: one row per chain and day).
        const done = await scoped(deps, chain, async (c) => {
          const existing = await c.query(
            `SELECT 1 FROM audit_head_hashes WHERE institution_id IS NOT DISTINCT FROM $1::uuid AND day = $2::date`,
            [chain, day],
          );
          if (existing.rowCount) return 'exists' as const;
          const last = await c.query<{ entry_hash: string }>(
            `SELECT entry_hash FROM audit_logs WHERE institution_id IS NOT DISTINCT FROM $1::uuid ORDER BY seq DESC LIMIT 1`,
            [chain],
          );
          const head = last.rows[0]?.entry_hash;
          if (!head) return 'empty' as const;
          key ??= deps.signer.load();
          const signature = signAuditHead({ institutionId: chain, day, headHash: head }, key);
          const ins = await c.query(
            `INSERT INTO audit_head_hashes (id, institution_id, day, head_hash, signature, signer_kid)
             VALUES ($1, $2, $3::date, $4, $5, $6)
             ON CONFLICT ON CONSTRAINT audit_head_hashes_chain_day_uniq DO NOTHING`,
            [randomUUID(), chain, day, head, signature, deps.signer.kid],
          );
          return ins.rowCount ? ('signed' as const) : ('exists' as const);
        });
        if (done === 'signed') summary.signed += 1;
        else if (done === 'empty') summary.empty += 1;
        else summary.alreadyDone += 1;

        // 2. Timestamp (submit missing, upgrade pending). Skipped entirely when disabled.
        if (deps.timestamper.enabled) await timestampChain(deps, chain, limit, summary);
      } catch (err) {
        summary.failures += 1;
        logger.error({ chain, ...safeErr(err) }, 'audit head chain failed');
      }
    }
  } finally {
    key = undefined;
  }
  logger.info({ day, ...summary }, 'audit daily head run complete');
  return summary;
}

async function timestampChain(deps: AuditHeadDeps, chain: Chain, limit: number, s: AuditHeadSummary): Promise<void> {
  const ts = deps.timestamper;
  const { toSubmit, toUpgrade } = await scoped(deps, chain, async (c) => {
    const sub = await c.query<HeadRow>(
      `SELECT h.id, h.day::text AS day, h.head_hash FROM audit_head_hashes h
        WHERE h.institution_id IS NOT DISTINCT FROM $1::uuid
          AND NOT EXISTS (SELECT 1 FROM audit_head_timestamps t WHERE t.head_id = h.id)
        ORDER BY h.day DESC LIMIT $2`,
      [chain, limit],
    );
    const upg = await c.query<{ id: string; ots_proof: Buffer }>(
      `SELECT p.head_id AS id, p.ots_proof FROM audit_head_timestamps p
        WHERE p.institution_id IS NOT DISTINCT FROM $1::uuid AND p.state = 'PENDING'
          AND NOT EXISTS (SELECT 1 FROM audit_head_timestamps d WHERE d.head_id = p.head_id AND d.state = 'COMPLETE')
        ORDER BY p.created_at LIMIT $2`,
      [chain, limit],
    );
    return { toSubmit: sub.rows, toUpgrade: upg.rows };
  });

  const insertProof = (headId: string, state: 'PENDING' | 'COMPLETE', proof: Buffer) =>
    scoped(deps, chain, (c) =>
      c.query(
        `INSERT INTO audit_head_timestamps (id, head_id, institution_id, state, ots_proof)
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT ON CONSTRAINT audit_head_timestamps_head_state_key DO NOTHING`,
        [randomUUID(), headId, chain, state, proof],
      ),
    );

  for (const h of toSubmit) {
    try {
      const digest = createHash('sha256')
        .update(auditHeadMessage({ institutionId: chain, day: h.day, headHash: h.head_hash }))
        .digest();
      const proof = await ts.submit(digest);
      // A calendar may already answer with a complete proof (rare); store it in the right state.
      await insertProof(h.id, isCompleteProof(proof) ? 'COMPLETE' : 'PENDING', proof);
      s.submitted += 1;
    } catch (err) {
      // Not fatal: the head stays without a proof row and the next run submits it again.
      s.failures += 1;
      deps.logger.warn({ chain, headId: h.id, ...safeErr(err) }, 'ots submit failed, will retry');
    }
  }

  for (const p of toUpgrade) {
    try {
      const r = await ts.upgrade(p.ots_proof);
      if (r.status === 'complete') {
        await insertProof(p.id, 'COMPLETE', r.proof);
        s.upgraded += 1;
      } else {
        s.stillPending += 1;
      }
    } catch (err) {
      s.failures += 1;
      deps.logger.warn({ chain, headId: p.id, ...safeErr(err) }, 'ots upgrade failed, will retry');
    }
  }
}
