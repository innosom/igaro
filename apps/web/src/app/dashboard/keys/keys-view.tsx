'use client';

import { useState, type FormEvent } from 'react';
import { api, describeError } from '@/lib/api';
import { formatDate, validateReason } from '@/lib/dashboard';
import type { SigningKey } from '@/lib/dash-types';
import { Btn, Card, Loading, PageTitle, StatusChip, tableCls, tdCls, thCls, useLoad } from '@/components/dash';
import { Alert, Field } from '@/components/ui';

const load = () => api.get<{ items: SigningKey[] }>('/institution/keys');

type Mode = { kind: 'rotate' } | { kind: 'compromise'; kid: string } | null;

export function KeysView() {
  const { data, error, loading, reload } = useLoad(load);
  const [mode, setMode] = useState<Mode>(null);
  const [password, setPassword] = useState('');
  const [reason, setReason] = useState('');
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function open(m: Mode) {
    setMode(m);
    setPassword('');
    setReason('');
    setErrors({});
    setFormError(null);
    setNotice(null);
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!mode) return;
    const errs: Record<string, string> = {};
    if (!password) errs.password = 'Enter your password to confirm.';
    if (mode.kind === 'compromise') {
      const r = validateReason(reason);
      if (r) errs.reason = r;
    }
    setErrors(errs);
    if (Object.keys(errs).length) return;
    setBusy(true);
    setFormError(null);
    try {
      if (mode.kind === 'rotate') {
        await api.post('/institution/keys/rotate', { password });
        setNotice('Key rotated. New credentials are signed with the new key.');
      } else {
        await api.post(`/institution/keys/${encodeURIComponent(mode.kid)}/compromise`, {
          reason: reason.trim(),
          password,
        });
        setNotice('Key marked as compromised. Credentials signed with it now fail verification.');
      }
      setMode(null);
      reload();
    } catch (err) {
      setFormError(describeError(err));
    } finally {
      setPassword('');
      setBusy(false);
    }
  }

  return (
    <>
      <PageTitle>Signing keys</PageTitle>
      <p className="mb-3 text-sm">
        Private keys never leave the server. This page shows public key information only.
      </p>
      {notice && <Alert kind="success">{notice}</Alert>}
      <Loading error={error} loading={loading} />
      {!mode && (
        <p className="mb-4">
          <Btn onClick={() => open({ kind: 'rotate' })}>Rotate key</Btn>
        </p>
      )}
      {mode && (
        <Card title={mode.kind === 'rotate' ? 'Rotate signing key' : `Mark key ${mode.kid} as compromised`}>
          <form onSubmit={submit} noValidate>
            {formError && <Alert kind="error">{formError}</Alert>}
            {mode.kind === 'compromise' ? (
              <Alert kind="error">
                This is permanent. Every credential signed with this key will show VERIFICATION FAILED to the public.
                If it is the active key, a replacement is created.
              </Alert>
            ) : (
              <p className="mb-3 text-sm">A new key becomes active; the current key is retired but still verifies older credentials.</p>
            )}
            {mode.kind === 'compromise' && (
              <Field id="creason" label="Reason (required, recorded in the audit log)" value={reason} onChange={setReason} error={errors.reason} />
            )}
            <Field
              id="kpw"
              label="Your password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={setPassword}
              error={errors.password}
            />
            <div className="flex gap-2">
              <Btn type="submit" kind={mode.kind === 'compromise' ? 'danger' : 'primary'} disabled={busy}>
                {mode.kind === 'compromise' ? 'Mark as compromised' : 'Rotate key'}
              </Btn>
              <Btn onClick={() => setMode(null)}>Cancel</Btn>
            </div>
          </form>
        </Card>
      )}
      {data && (
        <div className="overflow-x-auto">
          <table className={tableCls}>
            <caption className="sr-only">Signing keys</caption>
            <thead>
              <tr>
                <th className={thCls}>Key ID</th>
                <th className={thCls}>Status</th>
                <th className={thCls}>Created</th>
                <th className={thCls}>Retired</th>
                <th className={thCls}>Public key</th>
                <th className={thCls}>
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((k) => (
                <tr key={k.kid}>
                  <td className={`${tdCls} break-all`}>{k.kid}</td>
                  <td className={tdCls}>
                    <StatusChip status={k.status} />
                  </td>
                  <td className={tdCls}>{formatDate(k.createdAt)}</td>
                  <td className={tdCls}>{formatDate(k.retiredAt)}</td>
                  <td className={`${tdCls} break-all font-mono text-xs`}>{k.publicKey}</td>
                  <td className={tdCls}>
                    {k.status !== 'COMPROMISED' && (
                      <Btn kind="danger" onClick={() => open({ kind: 'compromise', kid: k.kid })}>
                        Mark compromised
                      </Btn>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
