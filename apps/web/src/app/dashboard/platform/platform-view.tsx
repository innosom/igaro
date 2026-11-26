'use client';

import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { api, describeError } from '@/lib/api';
import { buildQuery, formatDate, validateReason } from '@/lib/dashboard';
import { validateInstitutionDraft, type PlatformInstitution } from '@/lib/platform';
import { Btn, Card, PageTitle, StatusChip, tableCls, tdCls, thCls } from '@/components/dash';
import { Alert, Field } from '@/components/ui';

interface Page {
  items: PlatformInstitution[];
  nextCursor: string | null;
}

export function PlatformView() {
  const [items, setItems] = useState<PlatformInstitution[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const loadPage = useCallback(async (cursor: string | null) => {
    setLoading(true);
    setError(null);
    try {
      const p = await api.get<Page>(`/institutions${buildQuery({ limit: 50, cursor })}`);
      setItems((prev) => (cursor ? [...prev, ...p.items] : p.items));
      setNextCursor(p.nextCursor);
    } catch (e) {
      setError(describeError(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadPage(null);
  }, [loadPage]);

  // create form
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState('');
  const [slug, setSlug] = useState('');
  const [adminEmail, setAdminEmail] = useState('');
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function create(e: FormEvent) {
    e.preventDefault();
    const draft = { name: name.trim(), slug: slug.trim(), adminEmail: adminEmail.trim() };
    const errs = validateInstitutionDraft(draft);
    setFieldErrors(errs);
    if (Object.keys(errs).length) return;
    setBusy(true);
    setFormError(null);
    try {
      const res = await api.post<{ institution: PlatformInstitution; inviteQueued: boolean }>('/institutions', draft);
      setNotice(
        res.inviteQueued
          ? `Institution ${res.institution.name} created. An invite was sent to its admin.`
          : `Institution ${res.institution.name} created, but the invite email is not queued yet.`,
      );
      setCreating(false);
      setName('');
      setSlug('');
      setAdminEmail('');
      void loadPage(null);
    } catch (err) {
      setFormError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  // suspend / reactivate
  const [suspending, setSuspending] = useState<string | null>(null);
  const [reason, setReason] = useState('');
  const [reasonError, setReasonError] = useState<string | undefined>();

  async function setStatus(inst: PlatformInstitution, status: 'ACTIVE' | 'SUSPENDED') {
    let body: { status: string; reason?: string } = { status };
    if (status === 'SUSPENDED') {
      const re = validateReason(reason);
      setReasonError(re);
      if (re) return;
      body = { status, reason: reason.trim() };
    }
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const updated = await api.patch<PlatformInstitution>(`/institutions/${encodeURIComponent(inst.id)}/status`, body);
      setItems((prev) => prev.map((i) => (i.id === inst.id ? { ...i, ...updated } : i)));
      setNotice(`${inst.name} is now ${status === 'ACTIVE' ? 'active' : 'suspended'}.`);
      setSuspending(null);
      setReason('');
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageTitle>Institutions</PageTitle>
      <div className="mb-4">
        <Btn
          kind="primary"
          onClick={() => {
            setCreating(true);
            setNotice(null);
            setFormError(null);
            setFieldErrors({});
          }}
        >
          New institution
        </Btn>
      </div>
      {notice && <Alert kind="success">{notice}</Alert>}
      {error && <Alert kind="error">{error}</Alert>}

      {creating && (
        <Card title="New institution">
          <form onSubmit={create} noValidate>
            {formError && <Alert kind="error">{formError}</Alert>}
            <Field id="inst-name" label="Name" value={name} onChange={setName} error={fieldErrors.name} />
            <Field
              id="inst-slug"
              label="Slug"
              value={slug}
              onChange={(v) => setSlug(v.toLowerCase())}
              error={fieldErrors.slug}
              hint="3-40 characters: lower-case letters, digits and hyphens, not starting or ending with a hyphen. Used in the public keys URL."
            />
            <Field
              id="inst-admin"
              label="First admin email"
              type="email"
              autoComplete="off"
              value={adminEmail}
              onChange={setAdminEmail}
              error={fieldErrors.adminEmail}
              hint="An invite to set a password is sent to this address."
            />
            <div className="flex gap-2">
              <Btn type="submit" kind="primary" disabled={busy}>
                Create and invite
              </Btn>
              <Btn onClick={() => setCreating(false)}>Cancel</Btn>
            </div>
          </form>
        </Card>
      )}

      <div className="overflow-x-auto">
        <table className={tableCls}>
          <caption className="sr-only">Institutions</caption>
          <thead>
            <tr>
              <th className={thCls}>Name</th>
              <th className={thCls}>Slug</th>
              <th className={thCls}>Status</th>
              <th className={thCls}>Active key</th>
              <th className={thCls}>Created</th>
              <th className={thCls}>
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {items.map((i) => (
              <tr key={i.id}>
                <td className={tdCls}>{i.name}</td>
                <td className={tdCls}>{i.slug}</td>
                <td className={tdCls}>
                  <StatusChip status={i.status} />
                </td>
                <td className={`${tdCls} break-all`}>{i.activeKid ?? 'None'}</td>
                <td className={tdCls}>{formatDate(i.createdAt)}</td>
                <td className={tdCls}>
                  {i.status === 'SUSPENDED' ? (
                    <Btn disabled={busy} onClick={() => void setStatus(i, 'ACTIVE')}>
                      Reactivate
                    </Btn>
                  ) : suspending === i.id ? (
                    <div className="min-w-56">
                      <Field
                        id={`reason-${i.id}`}
                        label={`Reason for suspending ${i.name}`}
                        value={reason}
                        onChange={setReason}
                        error={reasonError}
                      />
                      <div className="flex gap-2">
                        <Btn kind="danger" disabled={busy} onClick={() => void setStatus(i, 'SUSPENDED')}>
                          Confirm suspend
                        </Btn>
                        <Btn onClick={() => setSuspending(null)}>Cancel</Btn>
                      </div>
                    </div>
                  ) : (
                    <Btn
                      onClick={() => {
                        setSuspending(i.id);
                        setReason('');
                        setReasonError(undefined);
                      }}
                    >
                      Suspend
                    </Btn>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {loading && <p className="mt-3 text-sm">Loading...</p>}
        {!loading && items.length === 0 && !error && <p className="mt-3 text-sm">No institutions yet.</p>}
        {nextCursor && !loading && (
          <div className="mt-3">
            <Btn onClick={() => void loadPage(nextCursor)}>Load more</Btn>
          </div>
        )}
      </div>
    </>
  );
}
