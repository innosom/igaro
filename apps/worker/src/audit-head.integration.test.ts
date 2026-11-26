// Integration for audit.dailyHead (T-028): real Postgres at $DATABASE_URL (scratch schema from the shared
// harness, all migrations applied, run as the igaro_worker role) and a faked OpenTimestamps calendar.
// No network is used. Skipped without DATABASE_URL.
import { createHash, randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import { createTransport } from 'nodemailer';
import { generateSigningKey, parseMasterKey, publicKeyFromRaw, verifyAuditHeadSignature } from '@igaro/core';
import { createHarness, hasDatabase, type Harness } from '@igaro/db/testing';
import { headSignerFromEnvelope, runAuditDailyHead, AUDIT_DAILY_HEAD_QUEUE, type AuditHeadDeps } from './audit-head.js';
import { createLogger } from './logger.js';
import { CalendarTimestamper, NoopTimestamper, isCompleteProof, type FetchLike } from './ots.js';
import { startWorker } from './worker.js';

const url = process.env.DATABASE_URL;
const CAL = 'https://cal.test';
// The shared harness seeds one junk proof (\x00) per tenant; upgrading it always fails, which is correct.
const JUNK = 2;
const sleep =(ms: number) => new Promise((r) => setTimeout(r, ms));

const varuint = (n: number) => Buffer.from([n]); // all test lengths < 128
const varbytes = (b: Buffer) => Buffer.concat([varuint(b.length), b]);
const receipt = Buffer.concat([
  Buffer.from([0xf0]),
  varbytes(Buffer.from('nonce')),
  Buffer.from([0x08, 0x00]),
  Buffer.from('83dfe30d2ef90c8e', 'hex'),
  varbytes(varbytes(Buffer.from(CAL))),
]);
const confirmed = Buffer.concat([Buffer.from([0x08, 0x00]), Buffer.from('0588960d73d71901', 'hex'), varbytes(varuint(100))]);

function calendar(state: { confirmed: boolean; down: boolean }) {
  const calls: string[] = [];
  const fn: FetchLike = async (u, init) => {
    calls.push(`${init?.method} ${u}`);
    const mk = (status: number, body = Buffer.alloc(0)) => ({
      status,
      ok: status < 300,
      arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.length) as ArrayBuffer,
    });
    if (state.down) return mk(503);
    if (init?.method === 'POST') return mk(200, receipt);
    return state.confirmed ? mk(200, confirmed) : mk(404);
  };
  return { fn, calls };
}

describe.skipIf(!hasDatabase)('audit.dailyHead against Postgres', () => {
  let h: Harness;
  let pool: pg.Pool;
  const master = randomBytes(32).toString('base64');
  const key = generateSigningKey(parseMasterKey(master));
  const signer = headSignerFromEnvelope(key.encryptedPrivateKey, master, key.kid);
  const lines: string[] = [];
  const logger = createLogger('debug', { write: (s: string) => void lines.push(s) });
  const DAY = '2026-11-26';
  const at = (day: string) => () => new Date(`${day}T00:10:00Z`);
  const deps = (over: Partial<AuditHeadDeps> = {}): AuditHeadDeps => ({
    pool,
    signer,
    timestamper: new NoopTimestamper(),
    logger,
    assumeRole: 'igaro_worker',
    now: at(DAY),
    ...over,
  });

  const heads = async (inst: string | null) =>
    (
      await h.owner.query(
        `SELECT h.id, h.day::text AS day, h.head_hash, h.signature, h.signer_kid FROM audit_head_hashes h
          WHERE h.institution_id IS NOT DISTINCT FROM $1::uuid AND h.day = $2::date`,
        [inst, DAY],
      )
    ).rows;
  const stamps = async (headId: string) =>
    (await h.owner.query(`SELECT state, ots_proof FROM audit_head_timestamps WHERE head_id = $1 ORDER BY state`, [headId])).rows;
  const hex = (s: string) => createHash('sha256').update(s).digest('hex');

  beforeAll(async () => {
    h = await createHarness('t028w');
    pool = new pg.Pool({ connectionString: url, options: `-c search_path=${h.schema}`, max: 3 });
    // Real-looking chain heads: the latest entry of each chain (highest seq) is what must be signed.
    for (const t of [h.A, h.B]) {
      await h.owner.query(
        `INSERT INTO audit_logs (id, institution_id, seq, action, prev_hash, entry_hash) VALUES ($1,$2,2,'x',$3,$4)`,
        [h.uid(), t.institutionId, `test-entry-hash-${t.tag}`, hex(`head-${t.tag}`)],
      );
    }
    await h.owner.query(
      `INSERT INTO audit_logs (id, institution_id, seq, action, prev_hash, entry_hash) VALUES ($1,NULL,1,'platform.x','genesis',$2)`,
      [h.uid(), hex('head-platform')],
    );
  }, 60000);

  afterAll(async () => {
    await pool?.end();
    await h?.close();
  });

  it('signs each chain head with the platform key, domain separated, idempotent per day', async () => {
    const s1 = await runAuditDailyHead(deps());
    expect(s1).toMatchObject({ chains: 3, signed: 3, alreadyDone: 0, failures: 0 });

    // Verify with the published raw public key, exactly as an outside verifier would.
    const pub = publicKeyFromRaw(key.publicKey);
    for (const [inst, expected] of [
      [h.A.institutionId, hex('head-a')],
      [h.B.institutionId, hex('head-b')],
      [null, hex('head-platform')],
    ] as const) {
      const rows = await heads(inst);
      expect(rows).toHaveLength(1);
      expect(rows[0].head_hash).toBe(expected);
      expect(rows[0].signer_kid).toBe(key.kid);
      expect(verifyAuditHeadSignature({ institutionId: inst, day: DAY, headHash: expected }, rows[0].signature, pub)).toBe(true);
      // not valid for another chain or day
      expect(verifyAuditHeadSignature({ institutionId: inst, day: '2026-11-27', headHash: expected }, rows[0].signature, pub)).toBe(false);
      expect(verifyAuditHeadSignature({ institutionId: inst === null ? h.A.institutionId : null, day: DAY, headHash: expected }, rows[0].signature, pub)).toBe(false);
    }

    const s2 = await runAuditDailyHead(deps());
    expect(s2).toMatchObject({ signed: 0, alreadyDone: 3, failures: 0 });
    expect(await heads(h.A.institutionId)).toHaveLength(1);
  });

  it('with the noop timestamper no proof rows are written', async () => {
    const [a] = await heads(h.A.institutionId);
    expect(await stamps(a.id)).toHaveLength(0);
  });

  it('submits to the calendar, keeps the proof as PENDING, then upgrades it in a separate COMPLETE row', async () => {
    const cal = calendar({ confirmed: false, down: false });
    const ts = new CalendarTimestamper({ calendars: [CAL], fetch: cal.fn });
    const s1 = await runAuditDailyHead(deps({ timestamper: ts }));
    expect(s1).toMatchObject({ submitted: 3, signed: 0, upgraded: 0, failures: JUNK });
    const [a] = await heads(h.A.institutionId);
    const rows1 = await stamps(a.id);
    expect(rows1.map((r) => r.state)).toEqual(['PENDING']);
    expect(isCompleteProof(rows1[0].ots_proof)).toBe(false);
    // The proof commits to SHA-256 of the exact signed message.
    const msg = `igaro.audit.head.sig.v1:${h.A.institutionId}:${DAY}:${a.head_hash}`;
    expect((rows1[0].ots_proof as Buffer).includes(createHash('sha256').update(msg).digest())).toBe(true);

    // Calendar not confirmed yet: still pending, nothing new written.
    const s2 = await runAuditDailyHead(deps({ timestamper: ts }));
    expect(s2).toMatchObject({ submitted: 0, upgraded: 0, stillPending: 3, failures: JUNK });

    // Confirmed: COMPLETE rows are appended, the PENDING rows stay untouched.
    const cal2 = calendar({ confirmed: true, down: false });
    const s3 = await runAuditDailyHead(deps({ timestamper: new CalendarTimestamper({ calendars: [CAL], fetch: cal2.fn }) }));
    expect(s3).toMatchObject({ upgraded: 3, failures: JUNK });
    const rows3 = await stamps(a.id);
    expect(rows3.map((r) => r.state)).toEqual(['COMPLETE', 'PENDING']);
    expect(isCompleteProof(rows3[0].ots_proof)).toBe(true);
    expect(rows3[1].ots_proof).toEqual(rows1[0].ots_proof);

    // Nothing left to do.
    const cal3 = calendar({ confirmed: true, down: false });
    const s4 = await runAuditDailyHead(deps({ timestamper: new CalendarTimestamper({ calendars: [CAL], fetch: cal3.fn }) }));
    expect(s4).toMatchObject({ submitted: 0, upgraded: 0, stillPending: 0, failures: JUNK });
    expect(cal3.calls).toHaveLength(0);
  });

  it('calendar outage: head still signed, run reports failures, next run submits the missing proof', async () => {
    const day2 = '2026-11-27';
    const down = calendar({ confirmed: false, down: true });
    const s1 = await runAuditDailyHead(
      deps({ now: at(day2), timestamper: new CalendarTimestamper({ calendars: [CAL], fetch: down.fn }) }),
    );
    expect(s1.signed).toBe(3);
    expect(s1.failures).toBe(3 + JUNK); // 3 failed submits plus the junk rows
    const rows = (await h.owner.query(`SELECT id FROM audit_head_hashes WHERE day = $1::date`, [day2])).rows;
    expect(rows).toHaveLength(3);
    expect((await h.owner.query(`SELECT 1 FROM audit_head_timestamps WHERE head_id = ANY($1::uuid[])`, [rows.map((r) => r.id)])).rowCount).toBe(0);

    const up = calendar({ confirmed: false, down: false });
    const s2 = await runAuditDailyHead(
      deps({ now: at(day2), timestamper: new CalendarTimestamper({ calendars: [CAL], fetch: up.fn }) }),
    );
    expect(s2).toMatchObject({ signed: 0, submitted: 3, failures: JUNK });
  });

  it('an empty chain is skipped and a failing signer isolates cleanly (no head, failures counted)', async () => {
    const inst = h.uid();
    await h.owner.query(`INSERT INTO institutions (id, slug, name, updated_at) VALUES ($1,'empty-one','Empty',now())`, [inst]);
    const s = await runAuditDailyHead(deps({ now: at('2026-12-01') }));
    expect(s.empty).toBe(1);
    expect(s.signed).toBe(3);

    const bad = headSignerFromEnvelope(key.encryptedPrivateKey, master, 'wrong-kid');
    const f = await runAuditDailyHead(deps({ now: at('2026-12-02'), signer: bad }));
    expect(f.failures).toBe(3);
    expect(f.signed).toBe(0);
    expect((await h.owner.query(`SELECT 1 FROM audit_head_hashes WHERE day = '2026-12-02'`)).rowCount).toBe(0);
  });

  it('never logs key material, signatures, or the wrapped key', () => {
    const all = lines.join('\n');
    expect(all).not.toContain(key.encryptedPrivateKey);
    expect(all).not.toContain(master);
    expect(all).not.toContain('PRIVATE');
    expect(all).toContain('audit daily head run complete');
  });

  it('refuses to run with a role that cannot write heads (igaro_app)', async () => {
    const s = await runAuditDailyHead(deps({ now: at('2026-12-03'), assumeRole: 'igaro_app' }));
    expect(s.signed).toBe(0);
    expect(s.failures).toBeGreaterThan(0);
  });
});

describe.skipIf(!hasDatabase)('audit.dailyHead via pg-boss', () => {
  let h: Harness;
  let pool: pg.Pool;
  let admin: pg.Client;
  const bossSchema = `pgboss_t028_${randomBytes(4).toString('hex')}`;
  let worker: Awaited<ReturnType<typeof startWorker>> | undefined;

  afterAll(async () => {
    await worker?.stop();
    await admin?.query(`DROP SCHEMA IF EXISTS "${bossSchema}" CASCADE`);
    await admin?.end();
    await h?.close();
  }, 60000);

  it('registers the queue and a daily schedule and runs a manually enqueued job', async () => {
    h = await createHarness('t028b');
    const master = randomBytes(32).toString('base64');
    const key = generateSigningKey(parseMasterKey(master));
    await h.owner.query(
      `INSERT INTO audit_logs (id, institution_id, seq, action, prev_hash, entry_hash) VALUES ($1,$2,2,'x','p',$3)`,
      [h.uid(), h.A.institutionId, 'ab'.repeat(32)],
    );
    // Heads for other tenants stay unsigned-able: give B a valid head too so the run has no failures.
    await h.owner.query(
      `INSERT INTO audit_logs (id, institution_id, seq, action, prev_hash, entry_hash) VALUES ($1,$2,2,'x','p',$3)`,
      [h.uid(), h.B.institutionId, 'cd'.repeat(32)],
    );
    pool = new pg.Pool({ connectionString: url, options: `-c search_path=${h.schema}`, max: 2 });
    admin = new pg.Client({ connectionString: url });
    await admin.connect();
    worker = await startWorker({
      databaseUrl: url as string,
      schema: bossSchema,
      logger: createLogger('silent'),
      pollingIntervalSeconds: 0.5,
      mail: { transport: createTransport({ jsonTransport: true }), from: 'x@igaro.test', webBaseUrl: 'https://app.igaro.test' },
      auditHead: {
        pool,
        signer: headSignerFromEnvelope(key.encryptedPrivateKey, master, key.kid),
        timestamper: new NoopTimestamper(),
        assumeRole: 'igaro_worker',
        cron: '10 0 * * *',
      },
    });
    const sched = await worker.boss.getSchedules();
    expect(sched.some((s) => s.name === AUDIT_DAILY_HEAD_QUEUE && s.cron === '10 0 * * *')).toBe(true);

    await worker.boss.send(AUDIT_DAILY_HEAD_QUEUE, {});
    const today = new Date().toISOString().slice(0, 10);
    const end = Date.now() + 20000;
    let n = 0;
    while (Date.now() < end) {
      n = (await h.owner.query(`SELECT 1 FROM audit_head_hashes WHERE day = $1::date`, [today])).rowCount ?? 0;
      if (n >= 2) break;
      await sleep(200);
    }
    expect(n).toBeGreaterThanOrEqual(2);
  }, 60000);
});
