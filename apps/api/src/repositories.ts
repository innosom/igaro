// Example of the request-scoped repository pattern. A repository is constructed from a Session
// (never from request input) and every method runs through Db.withTenant. The institution is
// injected from the session; callers cannot pass one. Ids belonging to another tenant are invisible
// (RLS plus an explicit filter), so lookups miss with NotFoundError (404), never 403.
import type { Db, TenantSession } from './db.js';
import { isUuid } from './db.js';
import { NotFoundError } from './errors.js';

export interface Holder {
  id: string;
  institutionId: string;
  fullName: string;
  externalId: string | null;
  email: string | null;
  createdAt: Date;
}

interface HolderRow {
  id: string;
  institution_id: string;
  full_name: string;
  external_id: string | null;
  email: string | null;
  created_at: Date;
}

const toHolder = (r: HolderRow): Holder => ({
  id: r.id,
  institutionId: r.institution_id,
  fullName: r.full_name,
  externalId: r.external_id,
  email: r.email,
  createdAt: r.created_at,
});

const COLS = 'id, institution_id, full_name, external_id, email, created_at';

export class HolderRepository {
  constructor(
    private readonly db: Db,
    private readonly session: TenantSession,
  ) {}

  async list(limit = 50): Promise<Holder[]> {
    const lim = Math.min(Math.max(Math.trunc(limit) || 50, 1), 200);
    return this.db.withTenant(this.session, async (c) => {
      const r = await c.query<HolderRow>(
        `SELECT ${COLS} FROM credential_holders
          WHERE institution_id = app_institution_id()
          ORDER BY created_at, id LIMIT $1`,
        [lim],
      );
      return r.rows.map(toHolder);
    });
  }

  async getById(id: string): Promise<Holder> {
    if (!isUuid(id)) throw new NotFoundError();
    return this.db.withTenant(this.session, async (c) => {
      const r = await c.query<HolderRow>(
        `SELECT ${COLS} FROM credential_holders
          WHERE id = $1 AND institution_id = app_institution_id()`,
        [id],
      );
      const row = r.rows[0];
      if (!row) throw new NotFoundError();
      return toHolder(row);
    });
  }
}
