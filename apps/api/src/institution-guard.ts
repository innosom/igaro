// Shared guard for ADR 0012 decision 4: admins of a SUSPENDED institution may read but not issue,
// rotate keys or upload files. Same error as issuance. Call inside the tenant transaction.
import type { PoolClient } from 'pg';
import { AppError, NotFoundError } from './errors.js';

export async function assertInstitutionActive(c: PoolClient): Promise<void> {
  const r = await c.query<{ status: string }>(`SELECT status FROM institutions WHERE id = app_institution_id()`);
  if (!r.rows[0]) throw new NotFoundError();
  if (r.rows[0].status !== 'ACTIVE') {
    throw new AppError(409, 'INSTITUTION_SUSPENDED', 'This institution cannot issue credentials');
  }
}
