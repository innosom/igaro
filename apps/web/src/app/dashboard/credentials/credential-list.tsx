'use client';

import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { useCallback, useEffect, useState } from 'react';
import { api, describeError } from '@/lib/api';
import { buildQuery, formatDate, STATUSES } from '@/lib/dashboard';
import type { CredentialRow, CredentialType } from '@/lib/dash-types';
import { Btn, Card, PageTitle, Select, StatusChip, tableCls, tdCls, thCls } from '@/components/dash';
import { Alert, Field, linkClass } from '@/components/ui';

interface Page {
  items: CredentialRow[];
  nextCursor: string | null;
}

export function CredentialList() {
  const params = useSearchParams();
  const [q, setQ] = useState('');
  const [status, setStatus] = useState(params.get('status') ?? '');
  const [type, setType] = useState('');
  const [applied, setApplied] = useState({ q: '', status: params.get('status') ?? '', type: '' });
  const [types, setTypes] = useState<CredentialType[]>([]);
  const [rows, setRows] = useState<CredentialRow[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);

  useEffect(() => {
    api
      .get<{ items: CredentialType[] }>('/credential-types')
      .then((r) => setTypes(r.items))
      .catch(() => undefined);
  }, []);

  const fetchPage = useCallback(
    async (after: string | null, f: typeof applied) => {
      setBusy(true);
      try {
        const page = await api.get<Page>(
          `/credentials${buildQuery({ q: f.q, status: f.status, type: f.type, limit: 50, cursor: after })}`,
        );
        setRows((prev) => (after ? [...prev, ...page.items] : page.items));
        setCursor(page.nextCursor);
        setError(null);
      } catch (e) {
        setError(describeError(e));
      } finally {
        setBusy(false);
      }
    },
    [],
  );

  useEffect(() => {
    void fetchPage(null, applied);
  }, [applied, fetchPage]);

  return (
    <>
      <PageTitle>Credentials</PageTitle>
      <Card>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            setApplied({ q, status, type });
          }}
          className="grid gap-x-4 sm:grid-cols-3"
        >
          <Field id="q" label="Search (number or holder name)" value={q} onChange={setQ} />
          <Select
            id="status"
            label="Status"
            value={status}
            onChange={setStatus}
            options={[{ value: '', label: 'All' }, ...STATUSES.map((s) => ({ value: s, label: s }))]}
          />
          <Select
            id="type"
            label="Type"
            value={type}
            onChange={setType}
            options={[{ value: '', label: 'All' }, ...types.map((t) => ({ value: t.code, label: t.name }))]}
          />
          <div>
            <Btn type="submit" kind="primary">
              Apply filters
            </Btn>
          </div>
        </form>
      </Card>
      {error && <Alert kind="error">{error}</Alert>}
      <div className="overflow-x-auto">
        <table className={tableCls}>
          <caption className="sr-only">Credentials</caption>
          <thead>
            <tr>
              <th className={thCls}>Number</th>
              <th className={thCls}>Holder</th>
              <th className={thCls}>Type</th>
              <th className={thCls}>Status</th>
              <th className={thCls}>Issued</th>
              <th className={thCls}>Expires</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td className={tdCls}>
                  {/* The number is a label only; the detail route uses the internal id. */}
                  <Link className={linkClass} href={`/dashboard/credentials/${r.id}`}>
                    {r.credentialNumber}
                  </Link>
                </td>
                <td className={tdCls}>{r.holder.fullName}</td>
                <td className={tdCls}>{r.type.name}</td>
                <td className={tdCls}>
                  <StatusChip status={r.status} />
                </td>
                <td className={tdCls}>{formatDate(r.issuedAt)}</td>
                <td className={tdCls}>{formatDate(r.expiresAt)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!busy && rows.length === 0 && !error && <p className="mt-3 text-sm">No credentials match.</p>}
      {busy && <p className="mt-3 text-sm">Loading...</p>}
      {cursor && !busy && (
        <div className="mt-3">
          <Btn onClick={() => void fetchPage(cursor, applied)}>Load more</Btn>
        </div>
      )}
    </>
  );
}
