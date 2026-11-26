'use client';

import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import { useCallback, useState, type FormEvent } from 'react';
import { api, describeError } from '@/lib/api';
import {
  attributesToForm,
  buildAttributes,
  dateToIso,
  formatDate,
  formatDateTime,
  validateReason,
} from '@/lib/dashboard';
import type { CredentialDetail, CredentialType } from '@/lib/dash-types';
import { Btn, Card, Loading, PageTitle, StatusChip, useLoad } from '@/components/dash';
import { AttributeFields } from '@/components/attribute-fields';
import { Alert, Field, linkClass } from '@/components/ui';

type Action = 'suspend' | 'reinstate' | 'revoke' | 'reissue' | null;

export function CredentialDetailView() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const load = useCallback(() => api.get<CredentialDetail>(`/credentials/${encodeURIComponent(id)}`), [id]);
  const { data: c, error, loading, reload } = useLoad(load);
  const loadTypes = useCallback(() => api.get<{ items: CredentialType[] }>('/credential-types'), []);
  const types = useLoad(loadTypes);

  const [action, setAction] = useState<Action>(null);
  const [reason, setReason] = useState('');
  const [confirmFinal, setConfirmFinal] = useState(false);
  const [values, setValues] = useState<Record<string, string>>({});
  const [expires, setExpires] = useState('');
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const type = types.data?.items.find((t) => t.code === c?.type.code);

  function open(a: Action) {
    setAction(a);
    setReason('');
    setConfirmFinal(false);
    setErrors({});
    setFormError(null);
    setNotice(null);
    if (a === 'reissue' && c && type) setValues(attributesToForm(type.attributes, c.attributes));
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!c || !action) return;
    const errs: Record<string, string> = {};
    const needsReason = action === 'suspend' || action === 'revoke' || action === 'reissue';
    if (needsReason) {
      const r = validateReason(reason);
      if (r) errs.reason = r;
    }
    if (action === 'revoke' && !confirmFinal) errs.final = 'Confirm that revoking is final.';
    let body: Record<string, unknown> = { reason: reason.trim() };
    if (action === 'reinstate') body = reason.trim() ? { reason: reason.trim() } : {};
    if (action === 'reissue') {
      if (!type) errs.reason = errs.reason ?? 'Credential type not loaded.';
      else {
        const a = buildAttributes(type.attributes, values);
        Object.assign(errs, a.errors);
        const exp = dateToIso(expires);
        if (exp === null) errs.expires = 'Use a valid date.';
        body = { reason: reason.trim(), attributes: a.values, ...(exp ? { expiresAt: exp } : {}) };
      }
    }
    setErrors(errs);
    if (Object.keys(errs).length) return;
    setBusy(true);
    setFormError(null);
    try {
      const res = await api.post<{ credential?: { id: string } }>(`/credentials/${encodeURIComponent(c.id)}/${action}`, body);
      if (action === 'reissue' && res.credential?.id) {
        router.push(`/dashboard/credentials/${res.credential.id}`);
        return;
      }
      setAction(null);
      setNotice(`Credential ${{ suspend: 'suspended', reinstate: 'reinstated', revoke: 'revoked', reissue: 'reissued' }[action]}.`);
      reload();
    } catch (err) {
      setFormError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  const stored = c?.storedStatus;
  const canSuspend = stored === 'ACTIVE';
  const canReinstate = stored === 'SUSPENDED';
  const canRevoke = stored === 'ACTIVE';
  const canReissue = stored === 'ACTIVE' || stored === 'REVOKED';

  return (
    <>
      <p className="mb-2 text-sm">
        <Link className={linkClass} href="/dashboard/credentials">
          Back to credentials
        </Link>
      </p>
      <PageTitle>{c ? `Credential ${c.credentialNumber}` : 'Credential'}</PageTitle>
      <Loading error={error} loading={loading} />
      {notice && <Alert kind="success">{notice}</Alert>}
      {c && (
        <>
          <Card>
            <p className="mb-2">
              <StatusChip status={c.status} />
            </p>
            <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
              <dt className="font-semibold">Holder</dt>
              <dd>{c.holder.fullName}</dd>
              <dt className="font-semibold">Type</dt>
              <dd>{c.type.name}</dd>
              <dt className="font-semibold">Issued</dt>
              <dd>{formatDate(c.issuedAt)}</dd>
              <dt className="font-semibold">Expires</dt>
              <dd>{formatDate(c.expiresAt)}</dd>
              <dt className="font-semibold">Signing key</dt>
              <dd className="break-all">{c.issuerKeyId}</dd>
              <dt className="font-semibold">Data hash</dt>
              <dd className="break-all">{c.dataHash}</dd>
              <dt className="font-semibold">Anchor</dt>
              <dd>{c.anchorStatus}</dd>
              {Object.entries(c.attributes).map(([k, v]) => (
                <div key={k} className="contents">
                  <dt className="font-semibold">{k}</dt>
                  <dd>{String(v)}</dd>
                </div>
              ))}
            </dl>
            {c.supersededBy && <p className="mt-2 text-sm">This credential was superseded by a reissue.</p>}
            {stored === 'ACTIVE' && (
              <p className="mt-3 text-sm">
                Card download:{' '}
                <a className={linkClass} href={`/api/v1/credentials/${c.id}/card.png`}>
                  PNG
                </a>{' '}
                <a className={linkClass} href={`/api/v1/credentials/${c.id}/card.pdf`}>
                  PDF
                </a>{' '}
                (available once rendered)
              </p>
            )}
          </Card>

          <Card title="Actions">
            {!canSuspend && !canReinstate && !canRevoke && !canReissue && (
              <p className="text-sm">No actions are available for this credential.</p>
            )}
            <div className="flex flex-wrap gap-2">
              {canSuspend && <Btn onClick={() => open('suspend')}>Suspend</Btn>}
              {canReinstate && <Btn onClick={() => open('reinstate')}>Reinstate</Btn>}
              {canReissue && <Btn onClick={() => open('reissue')}>Reissue</Btn>}
              {canRevoke && (
                <Btn kind="danger" onClick={() => open('revoke')}>
                  Revoke
                </Btn>
              )}
            </div>
            {action && (
              <form onSubmit={submit} noValidate className="mt-4 border-t border-slate-300 pt-4">
                <h3 className="mb-2 font-semibold capitalize">{action}</h3>
                {formError && <Alert kind="error">{formError}</Alert>}
                {action === 'revoke' && (
                  <Alert kind="error">
                    Revoking is final. A revoked credential can never be reinstated; to correct it you must reissue.
                  </Alert>
                )}
                <Field
                  id="reason"
                  label={action === 'reinstate' ? 'Reason (optional)' : 'Reason (required, recorded in the audit log)'}
                  value={reason}
                  onChange={setReason}
                  error={errors.reason}
                />
                {action === 'reissue' && type && (
                  <>
                    <p className="mb-2 text-sm">Change attributes below. The old credential is superseded.</p>
                    <AttributeFields
                      defs={type.attributes}
                      values={values}
                      errors={errors}
                      onChange={(k, v) => setValues((p) => ({ ...p, [k]: v }))}
                    />
                    <Field
                      id="expires"
                      label="New expiry date (optional, otherwise inherited)"
                      type="date"
                      value={expires}
                      onChange={setExpires}
                      error={errors.expires}
                    />
                  </>
                )}
                {action === 'revoke' && (
                  <div className="mb-4">
                    <label className="flex items-start gap-2 text-sm font-medium">
                      <input
                        type="checkbox"
                        checked={confirmFinal}
                        onChange={(e) => setConfirmFinal(e.target.checked)}
                        className="mt-1"
                      />
                      I understand this is final and cannot be undone.
                    </label>
                    {errors.final && <p className="mt-1 text-sm font-medium text-red-800">! {errors.final}</p>}
                  </div>
                )}
                <div className="flex gap-2">
                  <Btn type="submit" kind={action === 'revoke' ? 'danger' : 'primary'} disabled={busy}>
                    {busy ? 'Please wait...' : `Confirm ${action}`}
                  </Btn>
                  <Btn onClick={() => setAction(null)}>Cancel</Btn>
                </div>
              </form>
            )}
          </Card>

          <Card title="History">
            <ul className="space-y-1 text-sm">
              {c.events.map((ev) => (
                <li key={ev.id}>
                  <span className="font-semibold">{ev.type}</span> - {formatDateTime(ev.createdAt)}
                </li>
              ))}
            </ul>
          </Card>
        </>
      )}
    </>
  );
}
