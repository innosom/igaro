// Integration tests for the T-006 migration (lifecycle trigger, immutability, append-only tables).
// Skipped when DATABASE_URL is unset. Runs in a scratch schema that is dropped afterwards.
// "app" tests run as igaro_app (SET LOCAL ROLE) with the RLS settings the API uses; "owner" tests
// run as the connecting role, which proves the triggers (grants alone would not stop an owner).
// All values are test-only.
import { readdirSync, readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';

const url = process.env.DATABASE_URL;
const migrationsDir = new URL('../prisma/migrations/', import.meta.url);

const INST = '33333333-3333-4333-8333-333333333333';
const OTHER = '44444444-4444-4444-8444-444444444444';

let n = 0;
const uid = (): string => {
  n += 1;
  return `00000000-0000-4000-9000-${String(n).padStart(12, '0')}`;
};

type Status = 'DRAFT' | 'ACTIVE' | 'SUSPENDED' | 'REVOKED' | 'SUPERSEDED';
type EventType = 'ISSUED' | 'SUSPENDED' | 'REINSTATED' | 'REVOKED' | 'REISSUED';
const ALL_STATUSES: Status[] = ['DRAFT', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'SUPERSEDED'];
const ALL_EVENTS: EventType[] = ['ISSUED', 'SUSPENDED', 'REINSTATED', 'REVOKED', 'REISSUED'];

describe.skipIf(!url)('lifecycle and append-only triggers (needs Postgres at DATABASE_URL)', () => {
  const schema = `t006_${randomBytes(4).toString('hex')}`;
  let c: pg.Client;
  const f = { holder: uid(), type: uid(), staleCred: uid(), draftCred: uid(), auditId: uid(), headId: uid() };

  /** Run fn in a transaction (always rolled back) as igaro_app (tenant scope) or as the owner. */
  async function tx<T>(role: 'app' | 'owner', fn: () => Promise<T>): Promise<T> {
    await c.query('BEGIN');
    try {
      await c.query(`SELECT set_config('app.institution_id', $1, true)`, [INST]);
      if (role === 'owner') await c.query(`SELECT set_config('app.is_platform_admin', 'true', true)`);
      else await c.query('SET LOCAL ROLE igaro_app');
      return await fn();
    } finally {
      await c.query('ROLLBACK');
    }
  }
  const app = <T>(fn: () => Promise<T>) => tx('app', fn);
  const owner = <T>(fn: () => Promise<T>) => tx('owner', fn);

  async function code(fn: () => Promise<unknown>): Promise<string | undefined> {
    await c.query('SAVEPOINT s');
    try {
      await fn();
      await c.query('RELEASE SAVEPOINT s');
      return undefined;
    } catch (e) {
      await c.query('ROLLBACK TO SAVEPOINT s');
      return (e as { code?: string }).code ?? String(e);
    }
  }

  async function mkCredential(
    status: Status,
    opts: { id?: string; supersededBy?: string | null } = {},
  ): Promise<string> {
    const id = opts.id ?? uid();
    const num = `NUM-${id.slice(-6)}`;
    await c.query(
      `INSERT INTO credentials (id, institution_id, holder_id, type_id, credential_number, status,
         payload, data_hash, issuer_kid, signature, verification_token, holder_token_hash,
         superseded_by, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,'{"a":1}','hash','kid-t6','sig',$7,$8,$9, now())`,
      [id, INST, f.holder, f.type, num, status, `vt-${num}`, `ht-${num}`, opts.supersededBy ?? null],
    );
    return id;
  }
  const mkEvent = (cred: string, type: EventType, inst = INST) =>
    c.query(
      `INSERT INTO credential_events (id, institution_id, credential_id, type) VALUES ($1,$2,$3,$4)`,
      [uid(), inst, cred, type],
    );
  const setStatus = (id: string, status: Status, supersededBy: string | null = null) =>
    c.query(`UPDATE credentials SET status = $2, superseded_by = $3 WHERE id = $1`, [id, status, supersededBy]);
  // A credential changes status at most once per transaction (one event per credential per
  // transaction), so credentials in each state are committed in beforeAll, each step in its own
  // transaction, and tests (which always roll back) pick them from this pool. k = 0..2 gives
  // distinct credentials when one test needs several. Committing also exercises the deferred
  // constraint triggers for real.
  const pool: Record<Status, string[]> = { DRAFT: [], ACTIVE: [], SUSPENDED: [], REVOKED: [], SUPERSEDED: [] };
  const credIn = (status: Status, k = 0): Promise<string> => Promise.resolve(pool[status][k] as string);
  /** Committed transaction as platform scope + the test institution. */
  async function commit(fn: () => Promise<unknown>): Promise<void> {
    await c.query('BEGIN');
    await c.query(`SELECT set_config('app.is_platform_admin','true',true)`);
    await c.query(`SELECT set_config('app.institution_id',$1,true)`, [INST]);
    await fn();
    await c.query('COMMIT');
  }
  /** One committed transition: event + status change in the same transaction. */
  const transition = (id: string, ev: EventType, to: Status, supersededBy: string | null = null) =>
    commit(async () => {
      await mkEvent(id, ev);
      await setStatus(id, to, supersededBy);
    });
  async function buildActive(id?: string): Promise<string> {
    const cid = await mkCredentialCommitted(id);
    await transition(cid, 'ISSUED', 'ACTIVE');
    return cid;
  }
  async function mkCredentialCommitted(id?: string): Promise<string> {
    let out = '';
    await commit(async () => {
      out = await mkCredential('DRAFT', id ? { id } : {});
    });
    return out;
  }
  const checkNow = (trigger: string) => c.query(`SET CONSTRAINTS ${trigger} IMMEDIATE`);

  beforeAll(async () => {
    c = new pg.Client({ connectionString: url });
    await c.connect();
    await c.query(`CREATE SCHEMA "${schema}"`);
    await c.query(`SET search_path TO "${schema}"`);
    const dirs = readdirSync(migrationsDir, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => d.name)
      .sort();
    for (const d of dirs) {
      await c.query(readFileSync(new URL(`${d}/migration.sql`, migrationsDir), 'utf8'));
    }
    // Committed fixtures: institution, key, holder, type, a credential with a COMMITTED
    // SUSPENDED event (to prove an event from an earlier transaction does not count), and one
    // audit row, head hash and verification log.
    await c.query('BEGIN');
    await c.query(`SELECT set_config('app.is_platform_admin','true',true)`);
    await c.query(`SELECT set_config('app.institution_id',$1,true)`, [INST]);
    for (const [id, slug] of [[INST, 't6'], [OTHER, 't6-other']]) {
      await c.query(`INSERT INTO institutions (id, name, slug, updated_at) VALUES ($1,$2,$2, now())`, [id, slug]);
    }
    await c.query(
      `INSERT INTO institution_keys (id, institution_id, kid, public_key, encrypted_private_key)
       VALUES ($1,$2,'kid-t6','pub','enc')`,
      [uid(), INST],
    );
    await c.query(`INSERT INTO credential_holders (id, institution_id, full_name, updated_at) VALUES ($1,$2,'Test Holder', now())`, [f.holder, INST]);
    await c.query(`INSERT INTO credential_types (id, institution_id, code, name, kind, updated_at) VALUES ($1,$2,'T','T','ID_CARD', now())`, [f.type, INST]);
    await mkCredential('DRAFT', { id: f.draftCred });
    await c.query(
      `INSERT INTO audit_logs (id, institution_id, seq, action, prev_hash, entry_hash) VALUES ($1,$2,1,'t','genesis','e1')`,
      [f.auditId, INST],
    );
    await c.query(
      `INSERT INTO audit_head_hashes (id, institution_id, day, head_hash, signature, signer_kid) VALUES ($1,$2,'2026-11-24','h','s','kid-t6')`,
      [f.headId, INST],
    );
    await c.query(`INSERT INTO verification_logs (id, institution_id, result) VALUES ($1,$2,'VERIFIED')`, [uid(), INST]);
    await c.query('COMMIT');

    // Pool of committed credentials (each step is its own committed transaction).
    for (let k = 0; k < 3; k++) {
      pool.DRAFT.push(await mkCredentialCommitted());
      pool.ACTIVE.push(await buildActive());
      for (const s of ['SUSPENDED', 'REVOKED'] as const) {
        const id = await buildActive();
        await transition(id, s, s);
        pool[s].push(id);
      }
      const old = await buildActive();
      await transition(old, 'REISSUED', 'SUPERSEDED', await buildActive()); // fresh ACTIVE target
      pool.SUPERSEDED.push(old);
    }
    // staleCred: ACTIVE -> SUSPENDED -> ACTIVE across three transactions, so a committed
    // SUSPENDED event from an earlier transaction exists while the credential is ACTIVE again.
    await buildActive(f.staleCred);
    await transition(f.staleCred, 'SUSPENDED', 'SUSPENDED');
    await transition(f.staleCred, 'REINSTATED', 'ACTIVE');
  });

  afterAll(async () => {
    if (!c) return;
    await c.query('ROLLBACK').catch(() => undefined);
    await c.query('RESET search_path');
    await c.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    await c.end();
  });

  describe('lifecycle transitions (as igaro_app)', () => {
    const allowed: Array<[Status, Status, EventType]> = [
      ['DRAFT', 'ACTIVE', 'ISSUED'],
      ['ACTIVE', 'SUSPENDED', 'SUSPENDED'],
      ['SUSPENDED', 'ACTIVE', 'REINSTATED'],
      ['ACTIVE', 'REVOKED', 'REVOKED'],
    ];
    for (const [from, to, ev] of allowed) {
      it(`${from} -> ${to} is allowed with a ${ev} event in the same transaction`, async () => {
        await app(async () => {
          const id = await credIn(from);
          await mkEvent(id, ev);
          expect((await setStatus(id, to)).rowCount).toBe(1);
        });
      });
    }

    it('ACTIVE -> SUPERSEDED is allowed with a REISSUED event and superseded_by', async () => {
      await app(async () => {
        const old = await credIn('ACTIVE', 0);
        const next = await credIn('ACTIVE', 1);
        await mkEvent(old, 'REISSUED');
        expect((await setStatus(old, 'SUPERSEDED', next)).rowCount).toBe(1);
        expect(await code(() => checkNow('credentials_supersede_target_ctrg'))).toBeUndefined();
        expect(await code(() => checkNow('credential_events_status_ctrg'))).toBeUndefined();
      });
    });

    it('a status change without any event is refused', async () => {
      for (const [from, to] of [
        ['DRAFT', 'ACTIVE'],
        ['ACTIVE', 'SUSPENDED'],
        ['SUSPENDED', 'ACTIVE'],
        ['ACTIVE', 'REVOKED'],
      ] as const) {
        await app(async () => {
          const id = await credIn(from);
          expect(await code(() => setStatus(id, to)), `${from}->${to}`).toBe('23514');
        });
      }
    });

    it('an event of the wrong type does not authorise the transition', async () => {
      await app(async () => {
        const id = await credIn('ACTIVE');
        await mkEvent(id, 'SUSPENDED');
        expect(await code(() => setStatus(id, 'REVOKED'))).toBe('23514');
        expect(await code(() => setStatus(id, 'SUSPENDED'))).toBeUndefined();
      });
    });

    it('an event for a different credential does not authorise the transition', async () => {
      await app(async () => {
        const a = await credIn('ACTIVE', 0);
        const b = await credIn('ACTIVE', 1);
        await mkEvent(b, 'SUSPENDED');
        expect(await code(() => setStatus(a, 'SUSPENDED'))).toBe('23514');
      });
    });

    it('an event committed in an earlier transaction does not authorise a new status change', async () => {
      await app(async () => {
        expect(await code(() => setStatus(f.staleCred, 'SUSPENDED'))).toBe('23514');
      });
    });

    it('credential_events.txid is forced to the writing transaction (cannot be forged)', async () => {
      await app(async () => {
        const id = await credIn('ACTIVE');
        await c.query(
          `INSERT INTO credential_events (id, institution_id, credential_id, type, txid) VALUES ($1,$2,$3,'SUSPENDED', 1)`,
          [uid(), INST, id],
        );
        expect(await code(() => setStatus(id, 'SUSPENDED'))).toBeUndefined();
      });
    });

    it('every transition outside the lifecycle is refused whichever event accompanies it', async () => {
      const ok = new Set(['DRAFT>ACTIVE', 'ACTIVE>SUSPENDED', 'SUSPENDED>ACTIVE', 'ACTIVE>REVOKED', 'ACTIVE>SUPERSEDED']);
      for (const from of ALL_STATUSES) {
        for (const to of ALL_STATUSES) {
          if (from === to || ok.has(`${from}>${to}`)) continue;
          for (const ev of ALL_EVENTS) {
            await app(async () => {
              const id = await credIn(from);
              await mkEvent(id, ev); // one event per credential per transaction
              const next = to === 'SUPERSEDED' ? await credIn('ACTIVE', 1) : null;
              expect(await code(() => setStatus(id, to, next)), `${from}->${to} with ${ev}`).toBe('23514');
            });
          }
        }
      }
    });
  });

  describe('INSERT guard (H1)', () => {
    it('refuses to insert a credential directly as SUSPENDED, REVOKED or SUPERSEDED', async () => {
      for (const role of ['app', 'owner'] as const) {
        await tx(role, async () => {
          const target = await credIn('ACTIVE');
          for (const status of ['SUSPENDED', 'REVOKED'] as const) {
            expect(await code(() => mkCredential(status)), `${role} ${status}`).toBe('23514');
          }
          expect(await code(() => mkCredential('SUPERSEDED', { supersededBy: target })), `${role} SUPERSEDED`).toBe('23514');
        });
      }
    });

    it('allows DRAFT, and ACTIVE paired with an ISSUED event in the same transaction', async () => {
      await app(async () => {
        await mkCredential('DRAFT');
        const id = await mkCredential('ACTIVE');
        await mkEvent(id, 'ISSUED');
        expect(await code(() => checkNow('credentials_issued_event_ctrg'))).toBeUndefined();
        expect(await code(() => checkNow('credential_events_status_ctrg'))).toBeUndefined();
      });
    });

    it('an ACTIVE insert without an ISSUED event is refused when the deferred check runs', async () => {
      await app(async () => {
        await mkCredential('ACTIVE');
        expect(await code(() => checkNow('credentials_issued_event_ctrg'))).toBe('23514');
      });
      // an ISSUED event for a different credential, or of another type, does not count
      await app(async () => {
        const other = await credIn('ACTIVE');
        const id = await mkCredential('ACTIVE');
        await mkEvent(other, 'ISSUED');
        await mkEvent(id, 'SUSPENDED');
        expect(await code(() => checkNow('credentials_issued_event_ctrg'))).toBe('23514');
      });
    });

    it('an ACTIVE insert without an ISSUED event cannot COMMIT', async () => {
      await c.query('BEGIN');
      try {
        await c.query(`SELECT set_config('app.institution_id', $1, true)`, [INST]);
        await c.query('SET LOCAL ROLE igaro_app');
        await mkCredential('ACTIVE');
        let got: string | undefined;
        try {
          await c.query('COMMIT');
        } catch (e) {
          got = (e as { code?: string }).code;
        }
        expect(got).toBe('23514');
      } finally {
        await c.query('ROLLBACK');
      }
    });

    it('created_txid is forced and immutable', async () => {
      await owner(async () => {
        const id = uid();
        await c.query(
          `INSERT INTO credentials (id, institution_id, holder_id, type_id, credential_number, payload, data_hash,
             issuer_kid, signature, verification_token, holder_token_hash, created_txid, updated_at)
           VALUES ($1,$2,$3,$4,'N-forge','{}','h','kid-t6','s','vt-forge','ht-forge', 1, now())`,
          [id, INST, f.holder, f.type],
        );
        const r = await c.query(`SELECT created_txid = txid_current() AS ok FROM credentials WHERE id = $1`, [id]);
        expect(r.rows[0].ok).toBe(true);
        expect(await code(() => c.query(`UPDATE credentials SET created_txid = 1 WHERE id = $1`, [id]))).toBe('23514');
      });
    });
  });

  describe('event/status consistency at commit (M1)', () => {
    const check = () => checkNow('credential_events_status_ctrg');

    it('an event whose type does not match the credential status is refused', async () => {
      await app(async () => {
        const id = await credIn('DRAFT');
        await mkEvent(id, 'ISSUED'); // still DRAFT
        expect(await code(check)).toBe('23514');
      });
      await app(async () => {
        const id = await credIn('ACTIVE');
        await mkEvent(id, 'SUSPENDED'); // still ACTIVE
        expect(await code(check)).toBe('23514');
      });
      await app(async () => {
        const id = await credIn('ACTIVE');
        await mkEvent(id, 'REVOKED'); // still ACTIVE
        expect(await code(check)).toBe('23514');
      });
    });

    // H-A bypass 1: REVOKED event then REINSTATED event, no UPDATE. Previously only the latest
    // event (REINSTATED, matching the still-ACTIVE row) was checked.
    it('two events for one credential in one transaction are refused (unique credential_id, txid)', async () => {
      await app(async () => {
        const id = await credIn('ACTIVE');
        await mkEvent(id, 'REVOKED');
        expect(await code(() => mkEvent(id, 'REINSTATED'))).toBe('23505');
      });
      await owner(async () => {
        const id = await credIn('ACTIVE');
        await mkEvent(id, 'SUSPENDED');
        expect(await code(() => mkEvent(id, 'SUSPENDED'))).toBe('23505');
      });
    });

    // H-A bypass 2: no status change in this transaction, so a matching event must not pass just
    // because the status already had that value (or because a later event hides it).
    it('an event is refused when the status already had that value from an earlier transaction', async () => {
      await app(async () => {
        const id = await credIn('SUSPENDED');
        await mkEvent(id, 'SUSPENDED'); // status matches, but status_txid is an earlier transaction
        expect(await code(check)).toBe('23514');
      });
      await app(async () => {
        const id = await credIn('ACTIVE');
        await mkEvent(id, 'ISSUED');
        expect(await code(check)).toBe('23514');
      });
      await app(async () => {
        const id = await credIn('REVOKED');
        await mkEvent(id, 'REINSTATED'); // un-revoke attempt without an UPDATE
        expect(await code(check)).toBe('23514');
      });
    });

    it('a client-supplied seq or txid on an event changes nothing', async () => {
      await app(async () => {
        const id = await credIn('ACTIVE');
        await c.query(
          `INSERT INTO credential_events (id, institution_id, credential_id, type, seq, txid) VALUES ($1,$2,$3,'SUSPENDED', 0, 1)`,
          [uid(), INST, id],
        );
        expect(await code(check)).toBe('23514');
      });
    });

    it('status_txid follows status changes only and is not writable', async () => {
      await app(async () => {
        const id = await credIn('ACTIVE');
        expect(await code(() => c.query(`UPDATE credentials SET status_txid = txid_current() WHERE id = $1`, [id]))).toBe('42501');
      });
      await owner(async () => {
        const id = await credIn('ACTIVE');
        const read = async () =>
          (await c.query(`SELECT status_txid::text AS s, (status_txid = txid_current()) AS now FROM credentials WHERE id = $1`, [id])).rows[0];
        const before = await read();
        expect(before.now).toBe(false);
        await c.query(`UPDATE credentials SET status_txid = txid_current(), anchor_status = 'PENDING' WHERE id = $1`, [id]);
        expect(await read()).toEqual(before); // forced back to the old value
        await mkEvent(id, 'SUSPENDED');
        await setStatus(id, 'SUSPENDED');
        expect((await read()).now).toBe(true);
      });
    });

    it('a single status change with its event passes, including a reissue (two credentials)', async () => {
      await app(async () => {
        const id = await credIn('ACTIVE', 0);
        await mkEvent(id, 'SUSPENDED');
        await setStatus(id, 'SUSPENDED');
        expect(await code(check)).toBeUndefined();
      });
      await app(async () => {
        const old = await credIn('ACTIVE', 0);
        const replacement = await mkCredential('ACTIVE'); // new credential issued in this transaction
        await mkEvent(replacement, 'ISSUED');
        await mkEvent(old, 'REISSUED');
        await setStatus(old, 'SUPERSEDED', replacement);
        expect(await code(check)).toBeUndefined();
        expect(await code(() => checkNow('credentials_issued_event_ctrg'))).toBeUndefined();
        expect(await code(() => checkNow('credentials_supersede_target_ctrg'))).toBeUndefined();
      });
    });

    it('a transaction cannot change status twice (it would need two events for one credential)', async () => {
      await app(async () => {
        const id = await credIn('ACTIVE');
        await mkEvent(id, 'SUSPENDED');
        await setStatus(id, 'SUSPENDED');
        expect(await code(() => mkEvent(id, 'REINSTATED'))).toBe('23505');
        expect(await code(() => setStatus(id, 'ACTIVE'))).toBe('23514');
      });
    });

    it('a real COMMIT of an event without a status change fails', async () => {
      await c.query('BEGIN');
      try {
        await c.query(`SELECT set_config('app.institution_id', $1, true)`, [INST]);
        await c.query('SET LOCAL ROLE igaro_app');
        await mkEvent(await credIn('REVOKED'), 'REINSTATED');
        let got: string | undefined;
        try {
          await c.query('COMMIT');
        } catch (e) {
          got = (e as { code?: string }).code;
        }
        expect(got).toBe('23514');
      } finally {
        await c.query('ROLLBACK');
      }
    });
  });

  describe('reissue target (M2)', () => {
    async function reissue(target: string | null, source?: string): Promise<string | undefined> {
      const id = source ?? (await credIn('ACTIVE'));
      await mkEvent(id, 'REISSUED');
      return code(() => setStatus(id, 'SUPERSEDED', target));
    }

    it('accepts an ACTIVE target and a DRAFT created in the same transaction', async () => {
      await app(async () => {
        expect(await reissue(await credIn('ACTIVE', 1))).toBeUndefined();
      });
      await app(async () => {
        expect(await reissue(await mkCredential('DRAFT'))).toBeUndefined();
      });
    });

    // M-A: the target must be ACTIVE at COMMIT, not only when the UPDATE runs.
    it('requires the target to be ACTIVE at commit', async () => {
      const lateCheck = () => checkNow('credentials_supersede_target_ctrg');
      await app(async () => {
        // DRAFT replacement that is never issued
        expect(await reissue(await mkCredential('DRAFT'))).toBeUndefined();
        expect(await code(lateCheck)).toBe('23514');
      });
      await app(async () => {
        // DRAFT replacement issued before commit
        const target = await mkCredential('DRAFT');
        expect(await reissue(target)).toBeUndefined();
        await mkEvent(target, 'ISSUED');
        await setStatus(target, 'ACTIVE');
        expect(await code(lateCheck)).toBeUndefined();
      });
      await app(async () => {
        // ACTIVE target revoked later in the same transaction
        const target = await credIn('ACTIVE', 1);
        expect(await reissue(target)).toBeUndefined();
        await mkEvent(target, 'REVOKED');
        await setStatus(target, 'REVOKED');
        expect(await code(lateCheck)).toBe('23514');
      });
      await app(async () => {
        const target = await credIn('ACTIVE', 1);
        expect(await reissue(target)).toBeUndefined();
        expect(await code(lateCheck)).toBeUndefined();
      });
    });

    it('refuses SUSPENDED, REVOKED and already SUPERSEDED targets', async () => {
      for (const status of ['SUSPENDED', 'REVOKED', 'SUPERSEDED'] as const) {
        await app(async () => {
          expect(await reissue(await credIn(status)), status).toBe('23514');
        });
      }
    });

    it('refuses a DRAFT from an earlier transaction, itself, and an unknown credential', async () => {
      await app(async () => {
        expect(await reissue(f.draftCred)).toBe('23514');
      });
      await app(async () => {
        const id = await credIn('ACTIVE');
        expect(await reissue(id, id)).toBe('23514');
      });
      await app(async () => {
        expect(await reissue(uid())).toBe('23514');
      });
    });
  });

  describe('REVOKED is final', () => {
    it('cannot be un-revoked, even with a REINSTATED event', async () => {
      await app(async () => {
        const id = await credIn('REVOKED');
        await mkEvent(id, 'REINSTATED');
        expect(await code(() => setStatus(id, 'ACTIVE'))).toBe('23514');
        expect(await code(() => setStatus(id, 'SUSPENDED'))).toBe('23514');
      });
    });

    it('refuses a change to any column, as app and as owner', async () => {
      await app(async () => {
        const id = await credIn('REVOKED');
        expect(await code(() => c.query(`UPDATE credentials SET anchor_status = 'PENDING' WHERE id = $1`, [id]))).toBe('23514');
        expect(await code(() => c.query(`UPDATE credentials SET updated_at = now() + interval '1 day' WHERE id = $1`, [id]))).toBe('23514');
        expect(await code(() => c.query(`UPDATE credentials SET holder_token_hash = 'x' WHERE id = $1`, [id]))).toBe('23514');
      });
      await owner(async () => {
        const id = await credIn('REVOKED');
        for (const set of [
          `payload = '{"b":2}'`,
          `signature = 'x'`,
          `data_hash = 'x'`,
          `expires_at = now()`,
          `status = 'ACTIVE'`,
          `credential_number = 'x'`,
        ]) {
          expect(await code(() => c.query(`UPDATE credentials SET ${set} WHERE id = $1`, [id])), set).toBe('23514');
        }
      });
    });
  });

  describe('signed and identity columns', () => {
    it('are immutable once the credential is out of DRAFT (owner bypasses grants, not the trigger)', async () => {
      for (const status of ['ACTIVE', 'SUSPENDED', 'SUPERSEDED'] as const) {
        await owner(async () => {
          const id = await credIn(status);
          for (const set of [
            `payload = '{"b":2}'`,
            `data_hash = 'x'`,
            `signature = 'x'`,
            `issuer_kid = 'x'`,
            `issued_at = now()`,
            `expires_at = now()`,
            `type_id = '${uid()}'`,
            `credential_number = 'x'`,
            `verification_token = 'x'`,
            `institution_id = '${OTHER}'`,
          ]) {
            const got = await code(() => c.query(`UPDATE credentials SET ${set} WHERE id = $1`, [id]));
            // type_id of an unknown type fails the FK first only if the trigger allowed it
            expect(got, `${status}: ${set}`).toBe('23514');
          }
        });
      }
    });

    it('may still be set while DRAFT, but identity columns never', async () => {
      await owner(async () => {
        const id = await credIn('DRAFT');
        expect(await code(() => c.query(`UPDATE credentials SET payload = '{"b":2}', signature = 's2', data_hash = 'h2' WHERE id = $1`, [id]))).toBeUndefined();
        expect(await code(() => c.query(`UPDATE credentials SET credential_number = 'x' WHERE id = $1`, [id]))).toBe('23514');
        expect(await code(() => c.query(`UPDATE credentials SET verification_token = 'x' WHERE id = $1`, [id]))).toBe('23514');
      });
    });

    it('igaro_app has no UPDATE grant on signed columns', async () => {
      await app(async () => {
        const id = await credIn('ACTIVE');
        for (const col of ['payload', 'data_hash', 'signature', 'issuer_kid']) {
          const val = col === 'payload' ? `'{"b":2}'` : `'x'`;
          expect(await code(() => c.query(`UPDATE credentials SET ${col} = ${val} WHERE id = $1`, [id])), col).toBe('42501');
        }
      });
    });

    it('superseded_by cannot be rewritten on a SUPERSEDED credential', async () => {
      await owner(async () => {
        const id = await credIn('SUPERSEDED');
        const other = await credIn('ACTIVE');
        expect(await code(() => c.query(`UPDATE credentials SET superseded_by = $2 WHERE id = $1`, [id, other]))).toBe('23514');
      });
    });
  });

  describe('credentials are never deleted', () => {
    it('refuses DELETE and TRUNCATE for the app role (grant) and the owner (trigger)', async () => {
      await app(async () => {
        const id = await credIn('DRAFT');
        expect(await code(() => c.query('DELETE FROM credentials WHERE id = $1', [id]))).toBe('42501');
        expect(await code(() => c.query('TRUNCATE credentials'))).toBe('42501');
      });
      await owner(async () => {
        const id = await credIn('DRAFT');
        expect(await code(() => c.query('DELETE FROM credentials WHERE id = $1', [id]))).toBe('42501');
        const r = await c.query('SELECT 1 FROM credentials WHERE id = $1', [id]);
        expect(r.rowCount).toBe(1);
      });
      // separate transaction: with pending deferred triggers Postgres refuses TRUNCATE (55006) first
      await owner(async () => {
        expect(await code(() => c.query('TRUNCATE credentials CASCADE'))).toBe('42501');
      });
    });
  });

  describe('append-only tables', () => {
    const tables = ['audit_logs', 'audit_head_hashes', 'verification_logs', 'credential_events'];

    it('igaro_app holds no UPDATE, DELETE or TRUNCATE privilege', async () => {
      for (const t of tables) {
        for (const priv of ['UPDATE', 'DELETE', 'TRUNCATE']) {
          const r = await c.query(`SELECT has_table_privilege('igaro_app', $1::regclass, $2) AS ok`, [`"${schema}"."${t}"`, priv]);
          expect(r.rows[0].ok, `${t} ${priv}`).toBe(false);
        }
        const cols = await c.query(
          `SELECT column_name FROM information_schema.column_privileges
            WHERE grantee = 'igaro_app' AND table_schema = $1 AND table_name = $2 AND privilege_type = 'UPDATE'`,
          [schema, t],
        );
        // credential_events: only the anchoring marker (L1); the trigger limits it to one change.
        expect(cols.rows.map((r) => r.column_name), `${t} column UPDATE`).toEqual(
          t === 'credential_events' ? ['anchored_at'] : [],
        );
      }
      const cr = await c.query(`SELECT has_table_privilege('igaro_app', $1::regclass, 'DELETE') AS d, has_table_privilege('igaro_app', $1::regclass, 'TRUNCATE') AS t`, [`"${schema}"."credentials"`]);
      expect(cr.rows[0]).toEqual({ d: false, t: false });
    });

    it('audit_logs and audit_head_hashes refuse UPDATE, DELETE and TRUNCATE as app and as owner', async () => {
      const stmts: Array<[string, unknown[]]> = [
        [`UPDATE audit_logs SET action = 'x'`, []],
        [`UPDATE audit_logs SET entry_hash = 'x' WHERE id = $1`, [f.auditId]],
        ['DELETE FROM audit_logs', []],
        ['TRUNCATE audit_logs', []],
        [`UPDATE audit_head_hashes SET head_hash = 'x'`, []],
        [`UPDATE audit_head_hashes SET ots_proof = '\\x00'`, []],
        ['DELETE FROM audit_head_hashes', []],
        ['TRUNCATE audit_head_hashes', []],
      ];
      for (const role of ['app', 'owner'] as const) {
        await tx(role, async () => {
          for (const [sql, params] of stmts) {
            const got = await code(() => c.query(sql, params));
            // TRUNCATE of audit_head_hashes is also refused earlier (0A000) because audit_head_timestamps
            // references it (T-028); either way the statement fails.
            const accepted = sql === 'TRUNCATE audit_head_hashes' ? ['42501', '0A000'] : ['42501'];
            expect(accepted, `${role}: ${sql}`).toContain(got);
          }
        });
      }
    });

    it('verification_logs refuse UPDATE, DELETE and TRUNCATE as app and as owner', async () => {
      for (const role of ['app', 'owner'] as const) {
        await tx(role, async () => {
          for (const sql of [`UPDATE verification_logs SET result = 'NOT_FOUND'`, 'DELETE FROM verification_logs', 'TRUNCATE verification_logs']) {
            expect(await code(() => c.query(sql)), `${role}: ${sql}`).toBe('42501');
          }
        });
      }
    });

    it('the rows survive (nothing was modified by the refused statements)', async () => {
      await owner(async () => {
        expect((await c.query('SELECT action FROM audit_logs WHERE id = $1', [f.auditId])).rows[0].action).toBe('t');
        expect((await c.query('SELECT head_hash FROM audit_head_hashes WHERE id = $1', [f.headId])).rows[0].head_hash).toBe('h');
      });
    });

    it('credential_events: DELETE and TRUNCATE refused; only anchored_at may be updated, once', async () => {
      await app(async () => {
        expect(await code(() => c.query('DELETE FROM credential_events'))).toBe('42501');
        expect(await code(() => c.query('TRUNCATE credential_events'))).toBe('42501');
        // L1: the app may set anchored_at (once) but nothing else.
        const id = await credIn('ACTIVE');
        const upd = (set: string) => c.query(`UPDATE credential_events SET ${set} WHERE credential_id = $1`, [id]);
        for (const set of [`type = 'REVOKED'`, `payload = '{"x":1}'`, `txid = 1`, `seq = 0`, `created_at = now()`]) {
          expect(await code(() => upd(set)), set).toBe('42501');
        }
        expect((await upd('anchored_at = now()')).rowCount).toBe(1);
        expect(await code(() => upd(`anchored_at = now() + interval '1 day'`))).toBe('42501');
        expect(await code(() => upd('anchored_at = NULL'))).toBe('42501');
      });
      await owner(async () => {
        expect(await code(() => c.query('DELETE FROM credential_events'))).toBe('42501');
        expect(await code(() => c.query('TRUNCATE credential_events'))).toBe('42501');
        for (const set of [`type = 'REVOKED'`, `payload = '{"x":1}'`, `created_at = now()`, `credential_id = '${uid()}'`, `institution_id = '${OTHER}'`, `txid = 1`]) {
          expect(await code(() => c.query(`UPDATE credential_events SET ${set}`)), set).toBe('42501');
        }
        expect(await code(() => c.query(`UPDATE credential_events SET anchored_at = now()`))).toBeUndefined();
        expect(await code(() => c.query(`UPDATE credential_events SET anchored_at = now() + interval '1 day'`))).toBe('42501');
        expect(await code(() => c.query(`UPDATE credential_events SET anchored_at = NULL`))).toBe('42501');
      });
    });
  });

  describe('verification_logs credential/institution check (T-005 follow-up)', () => {
    it('refuses a credential_id without an institution_id', async () => {
      await app(async () => {
        const id = await credIn('ACTIVE');
        const ins = `INSERT INTO verification_logs (id, institution_id, credential_id, result) VALUES ($1,$2,$3,'VERIFIED')`;
        expect(await code(() => c.query(ins, [uid(), null, id]))).toBe('23514');
        expect(await code(() => c.query(ins, [uid(), INST, id]))).toBeUndefined();
        expect(await code(() => c.query(`INSERT INTO verification_logs (id, result) VALUES ($1,'NOT_FOUND')`, [uid()]))).toBeUndefined();
      });
    });
  });

  describe('trigger functions', () => {
    it('every igaro_* function has a fixed search_path that does not start with the caller path', async () => {
      const r = await c.query(
        `SELECT proname, proconfig FROM pg_proc WHERE pronamespace = $1::regnamespace AND proname LIKE 'igaro\\_%'`,
        [schema],
      );
      expect(r.rows.length).toBeGreaterThanOrEqual(7);
      for (const row of r.rows) {
        const cfg = (row.proconfig as string[] | null)?.find((x) => x.startsWith('search_path='));
        expect(cfg, row.proname).toBeDefined();
        expect(cfg, row.proname).toMatch(/search_path=pg_catalog, /);
        expect(cfg, row.proname).toMatch(/pg_temp$/);
      }
    });
  });
});
