// T-028 (ADR 0019): audit_head_hashes / audit_head_timestamps are written by igaro_worker only.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createHarness, hasDatabase, type Harness } from './testing/harness.js';

describe.skipIf(!hasDatabase)('audit head tables: worker-only writes (needs Postgres at DATABASE_URL)', () => {
  let h: Harness;
  beforeAll(async () => {
    h = await createHarness('t028');
  }, 60000);
  afterAll(async () => {
    await h?.close();
  });

  const head = (id: string, inst: string | null, day: string): [string, unknown[]] => [
    `INSERT INTO audit_head_hashes (id, institution_id, day, head_hash, signature, signer_kid) VALUES ($1,$2,$3::date,'h','s','k')`,
    [id, inst, day],
  ];

  it('igaro_app can read heads and timestamps but never insert them, in any scope', async () => {
    await h.asTenant(h.A.institutionId, async (c) => {
      expect((await c.query('SELECT 1 FROM audit_head_hashes')).rowCount).toBe(1);
      expect((await c.query('SELECT 1 FROM audit_head_timestamps')).rowCount).toBe(1);
      expect(await h.code(() => c.query(...head(h.uid(), h.A.institutionId, '2026-11-26')))).toBe('42501');
      expect(
        await h.code(() =>
          c.query(
            `INSERT INTO audit_head_timestamps (id, head_id, institution_id, state, ots_proof) VALUES ($1,$2,$3,'COMPLETE','\\x00')`,
            [h.uid(), h.A.headHashId, h.A.institutionId],
          ),
        ),
      ).toBe('42501');
    });
    await h.asPlatform(async (c) => {
      expect(await h.code(() => c.query(...head(h.uid(), null, '2026-11-26')))).toBe('42501');
    });
  });

  it('igaro_worker inserts a head only for the chain in its scope', async () => {
    await h.asWorker({ 'app.institution_id': h.A.institutionId }, async (c) => {
      expect(await h.code(() => c.query(...head(h.uid(), h.A.institutionId, '2026-11-26')))).toBeUndefined();
      expect(await h.code(() => c.query(...head(h.uid(), h.B.institutionId, '2026-11-26')))).toBe('42501');
      expect(await h.code(() => c.query(...head(h.uid(), null, '2026-11-26')))).toBe('42501');
      // Only its own chain is visible.
      expect((await c.query(`SELECT 1 FROM audit_head_hashes WHERE institution_id = $1`, [h.B.institutionId])).rowCount).toBe(0);
    });
    await h.asWorker({ 'app.is_platform_admin': 'true' }, async (c) => {
      expect(await h.code(() => c.query(...head(h.uid(), null, '2026-11-26')))).toBeUndefined();
    });
  });

  it('is idempotent per chain and day (unique constraint)', async () => {
    await h.asWorker({ 'app.institution_id': h.A.institutionId }, async (c) => {
      const ins = `INSERT INTO audit_head_hashes (id, institution_id, day, head_hash, signature, signer_kid)
                   VALUES ($1,$2,'2026-11-24','h','s','k') ON CONFLICT ON CONSTRAINT audit_head_hashes_chain_day_uniq DO NOTHING`;
      expect((await c.query(ins, [h.uid(), h.A.institutionId])).rowCount).toBe(0);
    });
  });

  it('igaro_worker cannot update, delete, or read key material, sessions or credentials', async () => {
    await h.asWorker({ 'app.is_platform_admin': 'true' }, async (c) => {
      expect(await h.code(() => c.query(`UPDATE audit_head_hashes SET head_hash = 'x'`))).toBe('42501');
      expect(await h.code(() => c.query(`DELETE FROM audit_head_hashes`))).toBe('42501');
      expect(await h.code(() => c.query(`UPDATE audit_head_timestamps SET state = 'COMPLETE'`))).toBe('42501');
      for (const t of ['institution_keys', 'sessions', 'users', 'invites', 'password_resets']) {
        expect(await h.code(() => c.query(`SELECT 1 FROM ${t}`)), t).toBe('42501');
      }
      // T-039 (ADR 0028): column-level read for cards only; secrets and writes stay refused.
      expect(await h.code(() => c.query(`SELECT id, payload, verification_token FROM credentials`))).toBeUndefined();
      for (const col of ['signature', 'data_hash', 'holder_token_hash']) {
        expect(await h.code(() => c.query(`SELECT ${col} FROM credentials`)), col).toBe('42501');
      }
      expect(await h.code(() => c.query(`SELECT email FROM credential_holders`))).toBe('42501');
      expect(await h.code(() => c.query(`UPDATE credentials SET status = 'ACTIVE'`))).toBe('42501');
      expect(await h.code(() => c.query(`INSERT INTO audit_logs (id, institution_id, seq, action, prev_hash, entry_hash) VALUES ($1,$2,9,'x','p','e')`, [h.uid(), h.A.institutionId]))).toBe('42501');
    });
  });

  it('a timestamp row must belong to the same chain as its head, and the head states are unique', async () => {
    await h.asWorker({ 'app.institution_id': h.A.institutionId }, async (c) => {
      const ins = `INSERT INTO audit_head_timestamps (id, head_id, institution_id, state, ots_proof) VALUES ($1,$2,$3,$4,'\\x00')`;
      expect(await h.code(() => c.query(ins, [h.uid(), h.A.headHashId, h.A.institutionId, 'COMPLETE']))).toBeUndefined();
      expect(await h.code(() => c.query(ins, [h.uid(), h.A.headHashId, h.A.institutionId, 'COMPLETE']))).toBe('23505');
      expect(await h.code(() => c.query(ins, [h.uid(), h.A.headHashId, h.A.institutionId, 'BOGUS']))).toBe('23514');
      // Pointing at tenant B's head is refused: B's head is invisible (and B is not our scope).
      expect(await h.code(() => c.query(ins, [h.uid(), h.B.headHashId, h.A.institutionId, 'COMPLETE']))).toBe('23503');
    });
  });
});
