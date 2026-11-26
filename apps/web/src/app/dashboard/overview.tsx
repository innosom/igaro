'use client';

import Link from 'next/link';
import { api } from '@/lib/api';
import { buildQuery, STATUSES } from '@/lib/dashboard';
import type { Stats } from '@/lib/dash-types';
import { Card, Loading, PageTitle, StatusChip, useLoad } from '@/components/dash';
import { linkClass } from '@/components/ui';

const load = () => api.get<Stats>('/dashboard/stats');

export function Overview() {
  const { data, error, loading } = useLoad(load);
  return (
    <>
      <PageTitle>Overview</PageTitle>
      <Loading error={error} loading={loading} />
      {data && (
        <Card title={`Credentials: ${data.total} total`}>
          <ul className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            {STATUSES.map((s) => (
              <li key={s} className="rounded-md border border-slate-300 p-3">
                <StatusChip status={s} />
                <p className="mt-1 text-2xl font-bold">
                  <Link className={linkClass} href={`/dashboard/credentials${buildQuery({ status: s })}`}>
                    {data.byStatus[s] ?? 0}
                  </Link>
                </p>
              </li>
            ))}
          </ul>
        </Card>
      )}
      <p className="text-sm">
        <Link className={linkClass} href="/dashboard/credentials/new">
          Issue a credential
        </Link>
      </p>
    </>
  );
}
