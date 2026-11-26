'use client';

import { useCallback, useEffect, useState } from 'react';
import { api, describeError } from '@/lib/api';
import { buildQuery, formatDateTime } from '@/lib/dashboard';
import type { AuditEntry, ChainResult } from '@/lib/dash-types';
import { Btn, Card, PageTitle, tableCls, tdCls, thCls } from '@/components/dash';
import { Alert } from '@/components/ui';

interface Page {
  items: AuditEntry[];
  nextCursor: string | null;
}

export function AuditView() {
  const [rows, setRows] = useState<AuditEntry[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);
  const [chain, setChain] = useState<ChainResult | null>(null);
  const [verifying, setVerifying] = useState(false);

  const fetchPage = useCallback(async (after: string | null) => {
    setBusy(true);
    try {
      const page = await api.get<Page>(`/audit-logs${buildQuery({ limit: 50, cursor: after })}`);
      setRows((p) => (after ? [...p, ...page.items] : page.items));
      setCursor(page.nextCursor);
      setError(null);
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    void fetchPage(null);
  }, [fetchPage]);

  async function verify() {
    setVerifying(true);
    setChain(null);
    setError(null);
    try {
      setChain(await api.get<ChainResult>('/audit-logs/verify-chain'));
    } catch (e) {
      setError(describeError(e));
    } finally {
      setVerifying(false);
    }
  }

  return (
    <>
      <PageTitle>Audit log</PageTitle>
      <p className="mb-3">
        <Btn onClick={() => void verify()} disabled={verifying}>
          {verifying ? 'Verifying...' : 'Verify chain'}
        </Btn>
      </p>
      {chain && (
        <Card title="Chain verification">
          {chain.valid ? (
            <Alert kind="success">
              Chain intact: {chain.entries} entries.
              {chain.headsRecorded
                ? ` Signed daily heads: ${chain.signedHeads.matched} of ${chain.signedHeads.checked} match.`
                : ' No signed daily heads recorded yet.'}
            </Alert>
          ) : (
            <Alert kind="error">
              Chain is BROKEN at entry {String(chain.brokenAtSeq ?? 'unknown')}
              {chain.reason ? `: ${chain.reason}` : ''}. Contact support.
            </Alert>
          )}
          {chain.signedHeads.mismatchedDays.length > 0 && (
            <p className="text-sm font-medium text-red-800">
              Mismatched head days: {chain.signedHeads.mismatchedDays.join(', ')}
            </p>
          )}
          {chain.head && <p className="break-all text-xs">Head: {chain.head}</p>}
        </Card>
      )}
      {error && <Alert kind="error">{error}</Alert>}
      <div className="overflow-x-auto">
        <table className={tableCls}>
          <caption className="sr-only">Audit log</caption>
          <thead>
            <tr>
              <th className={thCls}>#</th>
              <th className={thCls}>When</th>
              <th className={thCls}>Action</th>
              <th className={thCls}>Target</th>
              <th className={thCls}>Reason</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td className={tdCls}>{String(r.seq)}</td>
                <td className={tdCls}>{formatDateTime(r.createdAt)}</td>
                <td className={tdCls}>{r.action}</td>
                <td className={`${tdCls} break-all`}>{r.targetType ? `${r.targetType} ${r.targetId ?? ''}` : ''}</td>
                <td className={tdCls}>{typeof r.metadata?.reason === 'string' ? r.metadata.reason : ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {busy && <p className="mt-3 text-sm">Loading...</p>}
      {cursor && !busy && (
        <div className="mt-3">
          <Btn onClick={() => void fetchPage(cursor)}>Load more</Btn>
        </div>
      )}
    </>
  );
}
