'use client';

import { useEffect, useState } from 'react';
import { ApiError, api, describeError } from '@/lib/api';
import {
  POLL_INTERVAL_MS,
  canStartImport,
  isTerminalStatus,
  previewErrorRows,
  previewFromErrorBody,
  validateCsvFile,
  validateZipFile,
  type ImportBatch,
  type ImportPreview,
} from '@/lib/import';
import { Btn, Card, FileInput, PageTitle, tableCls, tdCls, thCls } from '@/components/dash';
import { Alert } from '@/components/ui';

function buildForm(csv: File, zip: File | null): FormData {
  const form = new FormData();
  form.append('csv', csv);
  if (zip) form.append('photos', zip);
  return form;
}

export function ImportView() {
  const [csv, setCsv] = useState<File | null>(null);
  const [zip, setZip] = useState<File | null>(null);
  const [resetKey, setResetKey] = useState(0);
  const [csvError, setCsvError] = useState<string | undefined>();
  const [zipError, setZipError] = useState<string | undefined>();
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [batchId, setBatchId] = useState<string | null>(null);
  const [batch, setBatch] = useState<ImportBatch | null>(null);
  const [pollError, setPollError] = useState<string | null>(null);
  const [pollTick, setPollTick] = useState(0);

  // Poll the batch until it is terminal. A failed poll stops the loop; "Refresh" resumes it.
  useEffect(() => {
    if (!batchId) return;
    let live = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    async function poll() {
      try {
        const b = await api.get<ImportBatch>(`/credentials/import/${encodeURIComponent(batchId!)}`);
        if (!live) return;
        setBatch(b);
        setPollError(null);
        if (!isTerminalStatus(b.status)) timer = setTimeout(() => void poll(), POLL_INTERVAL_MS);
      } catch (e) {
        if (live) setPollError(describeError(e));
      }
    }
    void poll();
    return () => {
      live = false;
      if (timer) clearTimeout(timer);
    };
  }, [batchId, pollTick]);

  function pickCsv(f: File | null) {
    setCsv(f);
    setCsvError(f ? validateCsvFile(f) : undefined);
    setPreview(null);
    setError(null);
  }
  function pickZip(f: File | null) {
    setZip(f);
    setZipError(validateZipFile(f));
    setPreview(null);
    setError(null);
  }

  function reset() {
    setCsv(null);
    setZip(null);
    setPreview(null);
    setBatchId(null);
    setBatch(null);
    setError(null);
    setPollError(null);
    setCsvError(undefined);
    setZipError(undefined);
    setResetKey((k) => k + 1);
  }

  async function runPreview() {
    const ce = validateCsvFile(csv);
    const ze = validateZipFile(zip);
    setCsvError(ce);
    setZipError(ze);
    if (ce || ze || !csv) return;
    setBusy(true);
    setError(null);
    setPreview(null);
    try {
      setPreview(await api.upload<ImportPreview>('/credentials/import?dryRun=true', buildForm(csv, zip)));
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  async function start() {
    if (!csv || !canStartImport(preview, busy)) return;
    setBusy(true);
    setError(null);
    try {
      const res = await api.upload<{ batchId: string; status: string }>('/credentials/import', buildForm(csv, zip));
      setBatch(null);
      setBatchId(res.batchId);
    } catch (e) {
      if (e instanceof ApiError && e.code === 'IMPORT_VALIDATION_FAILED') {
        const p = previewFromErrorBody(e.body);
        if (p) setPreview(p);
      }
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  const started = batchId !== null;
  const errorRows = preview ? previewErrorRows(preview) : [];

  return (
    <>
      <PageTitle>Import credentials</PageTitle>
      {!started && (
        <Card title="1. Choose files">
          <p className="mb-3 text-sm">
            Upload a CSV with one row per credential. Optionally add a ZIP of JPEG photos named{' '}
            <code>externalId.jpg</code>. Nothing is saved until you start the import.
          </p>
          <FileInput
            id="import-csv"
            label="CSV file (required)"
            accept=".csv,text/csv"
            hint="Up to 2 MB and 1000 rows."
            error={csvError}
            resetKey={resetKey}
            disabled={busy}
            onFile={pickCsv}
          />
          <FileInput
            id="import-zip"
            label="Photos ZIP (optional)"
            accept=".zip,application/zip"
            hint="Up to 50 MB. JPEG photos only."
            error={zipError}
            resetKey={resetKey}
            disabled={busy}
            onFile={pickZip}
          />
          <Btn kind="primary" disabled={busy || !csv} onClick={() => void runPreview()}>
            {busy && !preview ? 'Checking...' : 'Check file'}
          </Btn>
        </Card>
      )}

      {error && <Alert kind="error">{error}</Alert>}

      {!started && preview && (
        <Card title="2. Preview">
          <dl className="mb-3 grid grid-cols-2 gap-2 text-sm sm:grid-cols-5">
            <Stat label="Rows" value={preview.totalRows} />
            <Stat label="Valid rows" value={preview.validRows} />
            <Stat label="Rows with errors" value={preview.errorRows} />
            <Stat label="Photos matched" value={preview.photos.provided ? preview.photos.matched : 'No ZIP'} />
            <Stat label="Photos unmatched" value={preview.photos.provided ? preview.photos.unmatched : 'No ZIP'} />
          </dl>
          {preview.errorRows === 0 ? (
            <Alert kind="success">All rows are valid. Starting the import issues {preview.totalRows} credentials.</Alert>
          ) : (
            <>
              <Alert kind="error">
                {preview.errorRows} row(s) have errors. Fix the file and check it again. Nothing is imported until every row is valid.
              </Alert>
              <div className="overflow-x-auto">
                <table className={tableCls}>
                  <caption className="sr-only">Row errors</caption>
                  <thead>
                    <tr>
                      <th className={thCls}>Row</th>
                      <th className={thCls}>Column</th>
                      <th className={thCls}>Code</th>
                      <th className={thCls}>Message</th>
                    </tr>
                  </thead>
                  <tbody>
                    {errorRows.map((r, i) => (
                      <tr key={`${r.row}-${i}`}>
                        <td className={tdCls}>{r.row}</td>
                        <td className={tdCls}>{r.column}</td>
                        <td className={tdCls}>{r.code}</td>
                        <td className={tdCls}>{r.message}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
          <div className="mt-4">
            <Btn kind="primary" disabled={!canStartImport(preview, busy)} onClick={() => void start()}>
              {busy ? 'Starting...' : 'Start import'}
            </Btn>
          </div>
        </Card>
      )}

      {started && (
        <Card title="Import progress">
          {pollError && <Alert kind="error">{pollError}</Alert>}
          {!batch && !pollError && <p className="text-sm">Loading...</p>}
          {batch && (
            <>
              <p className="mb-3 text-sm" aria-live="polite">
                Status: <strong>{batch.status}</strong>
                {!isTerminalStatus(batch.status) && ' (updates every few seconds)'}
              </p>
              <dl className="mb-3 grid grid-cols-2 gap-2 text-sm sm:grid-cols-4">
                <Stat label="Imported" value={batch.importedRows} />
                <Stat label="Errors" value={batch.errorRows} />
                <Stat label="Pending" value={batch.pendingRows} />
                <Stat label="Total" value={batch.totalRows} />
              </dl>
              {batch.status === 'COMPLETED' && batch.errorRows === 0 && (
                <Alert kind="success">Import finished. All credentials were issued.</Alert>
              )}
              {batch.status === 'COMPLETED' && batch.errorRows > 0 && (
                <Alert kind="error">Import finished with errors. Rows listed below were not issued.</Alert>
              )}
              {batch.status === 'FAILED' && <Alert kind="error">The import failed. Check the row errors below.</Alert>}
              {batch.errors.length > 0 && (
                <div className="overflow-x-auto">
                  <table className={tableCls}>
                    <caption className="sr-only">Row errors</caption>
                    <thead>
                      <tr>
                        <th className={thCls}>Row</th>
                        <th className={thCls}>Error</th>
                      </tr>
                    </thead>
                    <tbody>
                      {batch.errors.map((r, i) => (
                        <tr key={`${r.row}-${i}`}>
                          <td className={tdCls}>{r.row}</td>
                          <td className={tdCls}>{r.error}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
          <div className="mt-4 flex gap-2">
            {(pollError || !batch || !isTerminalStatus(batch.status)) && <Btn onClick={() => setPollTick((t) => t + 1)}>Refresh</Btn>}
            {batch && isTerminalStatus(batch.status) && <Btn onClick={reset}>Import another file</Btn>}
          </div>
        </Card>
      )}
    </>
  );
}

function Stat({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="rounded border border-slate-300 p-2">
      <dt className="text-xs text-slate-700">{label}</dt>
      <dd className="text-lg font-bold text-slate-900">{value}</dd>
    </div>
  );
}
