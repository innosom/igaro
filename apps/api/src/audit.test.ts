// Audit service tests (T-024). Needs Postgres; migrations go into a scratch schema and the service
// connects as the restricted igaro_app role so grants, RLS and triggers are real.
import { randomBytes, randomUUID } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import { appendAudit, normaliseMetadata, verifyAuditChain } from './audit.js';
import { Db } from './db.js';

const url = process.env.DATABASE_URL;
const migrationsDir = new URL('../../../packages/db/prisma/migrations/', import.meta.url);

describe('normaliseMetadata', () => {
  it('drops undefined and refuses secret-looking keys', () => {
    expect(normaliseMetadata({ a: 1, b: undefined })).toEqual({ a: 1 });
    expect(() => normaliseMetadata({ x: { verificationToken: 'a' } })).toThrow();
    expect(() => normaliseMetadata({ salt: 'a' })).toThrow();
    expect(() => normaliseMetadata({ list: [{ privateKey: 'a' }] })).toThrow();
  });
});

describe.skipIf(!url)('audit chain (needs Postgres)', () => {
  const schema = `t024_${randomBytes(4).toString('hex')}`;
  const A = randomUUID();
  const B = randomUUID();
  const ACTOR = randomUUID();
  let owner: pg.Client;
  let db: Db;
  const ten = (id: string) => ({ kind: 'tenant' as const, userId: ACTOR, institutionId: id });
  const platform = { kind: 'platform' as const, userId: ACTOR };

  beforeAll(async () => {
    owner = new pg.Client({ connectionString: url });
    await owner.connect();
    await owner.query(`CREATE SCHEMA "${schema}"`);
    await owner.query(`SET search_path TO "${schema}"`);
    const dirs = readdirSync(migrationsDir, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => d.name)
      .sort();
    for (const d of dirs) await owner.query(readFileSync(new URL(`${d}/migration.sql`, migrationsDir), 'utf8'));
    await owner.query(`GRANT USAGE ON SCHEMA "${schema}" TO igaro_app`);
    await owner.query('BEGIN');
    await owner.query(`SELECT set_config('app.is_platform_admin','true',true)`);
    for (const [id, slug] of [[A, 'aaa-inst'], [B, 'bbb-inst']] as const) {
      await owner.query(
        `INSERT INTO institutions (id, name, slug, updated_at) VALUES ($1,'N',$2,now())`,
        [id, slug],
      );
    }
    await owner.query('COMMIT');
    db = new Db({
      connectionString: url!,
      max: 12,
      poolConfig: { options: `-c search_path=${schema} -c role=igaro_app` },
    });
  });

  afterAll(async () => {
    await db?.close();
    if (!owner) return;
    await owner.query('ROLLBACK').catch(() => undefined);
    await owner.query('RESET search_path');
    await owner.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    await owner.end();
  });

  const add = (inst: string | null, action: string, metadata: Record<string, unknown> = {}) =>
    db.withTenant(inst ? ten(inst) : platform, (c) =>
      appendAudit(c, { institutionId: inst, actorId: ACTOR, action, metadata }),
    );

  it('chains entries from genesis and verifies after a DB round trip', async () => {
    const e1 = await add(A, 'one', { z: 1, a: { y: [1, 2], b: null } });
    const e2 = await add(A, 'two');
    expect(e1.seq).toBe('1');
    expect(e1.prevHash).toBe('0'.repeat(64));
    expect(e2.prevHash).toBe(e1.entryHash);
    const v = await db.withTenant(ten(A), (c) => verifyAuditChain(c, A));
    expect(v).toEqual({ ok: true, head: e2.entryHash, count: 2 });
  });

  it('serialises concurrent appends into one unbroken chain', async () => {
    await Promise.all(Array.from({ length: 20 }, (_, i) => add(B, 'c', { i })));
    const v = await db.withTenant(ten(B), (c) => verifyAuditChain(c, B));
    expect(v).toMatchObject({ ok: true, count: 20 });
  });

  it('keeps a separate platform chain, readable in platform scope only', async () => {
    await add(null, 'p1');
    await add(null, 'p2');
    expect(await db.withTenant(platform, (c) => verifyAuditChain(c, null))).toMatchObject({ ok: true, count: 2 });
    expect(await db.withTenant(ten(A), (c) => verifyAuditChain(c, null))).toMatchObject({ ok: true, count: 0 });
  });

  it('a tenant cannot append to another tenant chain (RLS)', async () => {
    await expect(
      db.withTenant(ten(A), (c) => appendAudit(c, { institutionId: B, actorId: ACTOR, action: 'x' })),
    ).rejects.toThrow();
  });

  it('is append-only for the app role', async () => {
    await expect(db.withTenant(ten(A), (c) => c.query(`UPDATE audit_logs SET action = 'x'`))).rejects.toThrow();
    await expect(db.withTenant(ten(A), (c) => c.query(`DELETE FROM audit_logs`))).rejects.toThrow();
  });

  it('rolls back with the surrounding transaction', async () => {
    const before = await db.withTenant(ten(A), (c) => verifyAuditChain(c, A));
    await expect(
      db.withTenant(ten(A), async (c) => {
        await appendAudit(c, { institutionId: A, actorId: ACTOR, action: 'doomed' });
        throw new Error('boom');
      }),
    ).rejects.toThrow('boom');
    expect(await db.withTenant(ten(A), (c) => verifyAuditChain(c, A))).toEqual(before);
  });

  it('detects tampering made by the table owner', async () => {
    await owner.query('BEGIN');
    await owner.query(`SELECT set_config('app.is_platform_admin','true',true)`);
    await owner.query(`ALTER TABLE audit_logs DISABLE TRIGGER USER`);
    await owner.query(`UPDATE audit_logs SET action = 'tampered' WHERE institution_id = $1 AND seq = 1`, [A]);
    await owner.query(`ALTER TABLE audit_logs ENABLE TRIGGER USER`);
    await owner.query('COMMIT');
    const v = await db.withTenant(ten(A), (c) => verifyAuditChain(c, A));
    expect(v).toMatchObject({ ok: false, brokenAtSeq: '1', reason: 'HASH_MISMATCH' });
  });
});
