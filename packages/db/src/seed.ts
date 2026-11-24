// Seed data (T-007). TEST-ONLY values: every email, name, ID and default password below is
// fictional and must never be used for a real account. Nothing here is a secret.
//
// What it creates (all idempotent, safe to re-run; existing rows are never modified, so a
// changed password env var does not rotate an existing password):
//   - platform admin (institution_id NULL)
//   - demo institution "East Africa University" (slug `eau`) and its institution admin
//   - credential types STUDENT_ID (ID_CARD) and CERTIFICATE
//   - a few demo holders
// It does NOT create signing keys (institution_keys): key generation belongs to the API
// (T-014/T-015) because the master key must wrap the private key.
//
// Connection: run as the migration/owner role (DATABASE_URL). Every statement runs in one
// transaction with the platform scope setting so it also works for a non-superuser owner
// (superusers bypass RLS entirely). The scope is set with set_config(..., true), i.e. SET LOCAL.
//
// Passwords come from env: SEED_ADMIN_PASSWORD (platform admin) and SEED_EAU_ADMIN_PASSWORD
// (EAU admin, falls back to SEED_ADMIN_PASSWORD). The well-known test-only default is an
// allowlist: it is used only when NODE_ENV is 'development' or 'test', or SEED_ALLOW_TEST_PASSWORD=1.
// In every other case (production, unset or unknown NODE_ENV) explicit passwords of at least 12
// characters that differ from the default are required. Hashes are Argon2id. Passwords and
// hashes are never logged.
//
// NODE_ENV=production seeds ONLY the platform admin. The demo institution, its admin, types and
// holders are skipped unless SEED_DEMO=1 (they exist for local development and demos).
import { hash } from '@node-rs/argon2';
import pg from 'pg';

export const TEST_ONLY_DEFAULT_PASSWORD = 'igaro-test-only-CHANGE-ME';
const MIN_PASSWORD_LENGTH = 12;

// Argon2id (algorithm 2), OWASP-recommended minimum: m=19 MiB, t=2, p=1.
export const ARGON2ID_PARAMS = {
  algorithm: 2,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
} as const;

export const DEMO_INSTITUTION = {
  name: 'East Africa University',
  slug: 'eau',
  cardTitle: 'EAU Student ID',
  primaryColor: '#1d4ed8',
  secondaryColor: '#0f172a',
  publicFields: ['fullName', 'credentialType', 'issuedAt', 'expiresAt'],
};

export interface AttributeDef {
  key: string;
  label: string;
  type: 'string' | 'date' | 'number';
  required: boolean;
}

export const CREDENTIAL_TYPES = [
  {
    code: 'STUDENT_ID',
    name: 'Student/Staff ID Card',
    kind: 'ID_CARD',
    validityDays: 365,
    attributes: [
      { key: 'program', label: 'Programme', type: 'string', required: true },
      { key: 'faculty', label: 'Faculty', type: 'string', required: false },
      { key: 'yearOfStudy', label: 'Year of study', type: 'number', required: false },
    ] satisfies AttributeDef[],
  },
  {
    code: 'CERTIFICATE',
    name: 'Certificate',
    kind: 'CERTIFICATE',
    validityDays: null,
    attributes: [
      { key: 'title', label: 'Certificate title', type: 'string', required: true },
      { key: 'program', label: 'Programme', type: 'string', required: true },
      { key: 'grade', label: 'Grade or classification', type: 'string', required: false },
      { key: 'awardDate', label: 'Award date', type: 'date', required: true },
    ] satisfies AttributeDef[],
  },
] as const;

export const DEMO_HOLDERS = [
  { fullName: 'Amina Test-Holder', externalId: 'EAU-TEST-0001', email: 'amina@example.test' },
  { fullName: 'Brian Test-Holder', externalId: 'EAU-TEST-0002', email: 'brian@example.test' },
  { fullName: 'Chipo Test-Holder', externalId: 'EAU-TEST-0003', email: null },
] as const;

export interface SeedConfig {
  production: boolean;
  /** Seed the demo institution, its admin, credential types and holders. */
  demo: boolean;
  platformAdminEmail: string;
  platformAdminPassword: string;
  eauAdminEmail: string;
  eauAdminPassword: string;
}

/** Reads and validates seed config from env. Throws (without echoing values) on unsafe input. */
export function loadSeedConfig(env: NodeJS.ProcessEnv = process.env): SeedConfig {
  const production = env.NODE_ENV === 'production';
  const demo = production ? env.SEED_DEMO === '1' : true;
  const allowDefault =
    env.NODE_ENV === 'development' ||
    env.NODE_ENV === 'test' ||
    env.SEED_ALLOW_TEST_PASSWORD === '1';
  const fallback = allowDefault ? TEST_ONLY_DEFAULT_PASSWORD : '';
  const platformAdminPassword = env.SEED_ADMIN_PASSWORD || fallback;
  const eauAdminPassword = env.SEED_EAU_ADMIN_PASSWORD || env.SEED_ADMIN_PASSWORD || fallback;

  const checks: (readonly [string, string])[] = [['SEED_ADMIN_PASSWORD', platformAdminPassword]];
  if (demo) checks.push(['SEED_EAU_ADMIN_PASSWORD', eauAdminPassword]);
  for (const [name, value] of checks) {
    if (value === TEST_ONLY_DEFAULT_PASSWORD && allowDefault && !production) continue;
    if (!value) throw new Error(`${name} must be set (the test-only default is not allowed here)`);
    if (value === TEST_ONLY_DEFAULT_PASSWORD)
      throw new Error(`${name} must not be the test-only default in this environment`);
    if (value.length < MIN_PASSWORD_LENGTH)
      throw new Error(`${name} must be at least ${MIN_PASSWORD_LENGTH} characters`);
  }

  const platformAdminEmail = (env.SEED_ADMIN_EMAIL || 'platform-admin@igaro.test').toLowerCase();
  const eauAdminEmail = (env.SEED_EAU_ADMIN_EMAIL || 'admin@eau.test').toLowerCase();
  if (demo && platformAdminEmail === eauAdminEmail)
    throw new Error('SEED_ADMIN_EMAIL and SEED_EAU_ADMIN_EMAIL must differ');

  return {
    production,
    demo,
    platformAdminEmail,
    platformAdminPassword,
    eauAdminEmail,
    eauAdminPassword,
  };
}

export interface SeedResult {
  /** Demo institution id, or null when the demo data was skipped. */
  institutionId: string | null;
  created: { users: number; institutions: number; credentialTypes: number; holders: number };
}

/** Seeds using an already-connected client. Runs in a single transaction. */
export async function runSeed(client: pg.ClientBase, config: SeedConfig): Promise<SeedResult> {
  // Hash before opening the transaction; hashing is slow and needs no DB.
  const platformHash = await hash(config.platformAdminPassword, ARGON2ID_PARAMS);
  const eauHash = config.demo ? await hash(config.eauAdminPassword, ARGON2ID_PARAMS) : '';
  const created = { users: 0, institutions: 0, credentialTypes: 0, holders: 0 };

  await client.query('BEGIN');
  try {
    await client.query("SELECT set_config('app.is_platform_admin', 'true', true)");

    const insertUser = async (
      institutionId: string | null,
      email: string,
      name: string,
      passwordHash: string,
      role: string,
    ): Promise<void> => {
      const r = await client.query(
        `INSERT INTO users (id, institution_id, email, name, password_hash, role, updated_at)
         VALUES (gen_random_uuid(), $1, $2, $3, $4, $5::user_role, now())
         ON CONFLICT (email) DO NOTHING`,
        [institutionId, email, name, passwordHash, role],
      );
      created.users += r.rowCount ?? 0;
    };

    await insertUser(
      null,
      config.platformAdminEmail,
      'Platform Admin',
      platformHash,
      'PLATFORM_ADMIN',
    );
    if (!config.demo) {
      await client.query('COMMIT');
      return { institutionId: null, created };
    }

    const inst = await client.query(
      `INSERT INTO institutions (id, name, slug, card_title, primary_color, secondary_color, public_fields, updated_at)
       VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6::jsonb, now())
       ON CONFLICT (slug) DO NOTHING RETURNING id`,
      [
        DEMO_INSTITUTION.name,
        DEMO_INSTITUTION.slug,
        DEMO_INSTITUTION.cardTitle,
        DEMO_INSTITUTION.primaryColor,
        DEMO_INSTITUTION.secondaryColor,
        JSON.stringify(DEMO_INSTITUTION.publicFields),
      ],
    );
    created.institutions = inst.rowCount ?? 0;
    const existing = await client.query<{ id: string }>(
      'SELECT id FROM institutions WHERE slug = $1',
      [DEMO_INSTITUTION.slug],
    );
    const institutionId = existing.rows[0]?.id;
    if (!institutionId) throw new Error('demo institution not found after upsert');

    // Platform scope can only read credential_types/credential_holders, so writes to them need
    // the tenant scope as well (RLS policy: institution_id = app.institution_id).
    await client.query("SELECT set_config('app.institution_id', $1, true)", [institutionId]);

    await insertUser(
      institutionId,
      config.eauAdminEmail,
      'EAU Admin',
      eauHash,
      'INSTITUTION_ADMIN',
    );

    for (const t of CREDENTIAL_TYPES) {
      const r = await client.query(
        `INSERT INTO credential_types (id, institution_id, code, name, kind, attribute_schema, validity_days, updated_at)
         VALUES (gen_random_uuid(), $1, $2, $3, $4::credential_kind, $5::jsonb, $6, now())
         ON CONFLICT (institution_id, code) DO NOTHING`,
        [institutionId, t.code, t.name, t.kind, JSON.stringify(t.attributes), t.validityDays],
      );
      created.credentialTypes += r.rowCount ?? 0;
    }

    for (const h of DEMO_HOLDERS) {
      const r = await client.query(
        `INSERT INTO credential_holders (id, institution_id, full_name, external_id, email, updated_at)
         VALUES (gen_random_uuid(), $1, $2, $3, $4, now())
         ON CONFLICT (institution_id, external_id) DO NOTHING`,
        [institutionId, h.fullName, h.externalId, h.email],
      );
      created.holders += r.rowCount ?? 0;
    }

    await client.query('COMMIT');
    return { institutionId, created };
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  }
}
