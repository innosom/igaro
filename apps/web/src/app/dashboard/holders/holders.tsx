'use client';

import { useCallback, useState, type FormEvent } from 'react';
import { api, describeError } from '@/lib/api';
import { buildQuery, diffPatch, emptyToNull } from '@/lib/dashboard';
import type { Holder } from '@/lib/dash-types';
import { Btn, Card, FilePicker, Loading, PageTitle, tableCls, tdCls, thCls, useLoad } from '@/components/dash';
import { Alert, Field } from '@/components/ui';

interface HolderList {
  items: Holder[];
  total: number;
}

export function HoldersView() {
  const [search, setSearch] = useState('');
  const [applied, setApplied] = useState('');
  const load = useCallback(() => api.get<HolderList>(`/holders${buildQuery({ q: applied, limit: 100 })}`), [applied]);
  const { data, error, loading, reload } = useLoad(load);

  const [editing, setEditing] = useState<Holder | 'new' | null>(null);
  const [fullName, setFullName] = useState('');
  const [externalId, setExternalId] = useState('');
  const [email, setEmail] = useState('');
  const [formError, setFormError] = useState<string | null>(null);
  const [nameError, setNameError] = useState<string | undefined>();
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function startEdit(h: Holder | 'new') {
    setEditing(h);
    setFullName(h === 'new' ? '' : h.fullName);
    setExternalId(h === 'new' ? '' : (h.externalId ?? ''));
    setEmail(h === 'new' ? '' : (h.email ?? ''));
    setFormError(null);
    setNameError(undefined);
    setNotice(null);
  }

  async function save(e: FormEvent) {
    e.preventDefault();
    if (!fullName.trim()) {
      setNameError('Full name is required.');
      return;
    }
    setNameError(undefined);
    setBusy(true);
    setFormError(null);
    try {
      if (editing === 'new') {
        await api.post('/holders', {
          fullName: fullName.trim(),
          ...(externalId.trim() ? { externalId: externalId.trim() } : {}),
          ...(email.trim() ? { email: email.trim() } : {}),
        });
      } else if (editing) {
        const patch = diffPatch(
          { fullName: editing.fullName, externalId: editing.externalId, email: editing.email },
          { fullName: fullName.trim(), externalId: emptyToNull(externalId), email: emptyToNull(email) },
        );
        if (Object.keys(patch).length) await api.patch(`/holders/${editing.id}`, patch);
      }
      setEditing(null);
      reload();
    } catch (err) {
      setFormError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  async function uploadPhoto(h: Holder, file: File) {
    setBusy(true);
    setNotice(null);
    setFormError(null);
    try {
      const form = new FormData();
      form.append('file', file);
      await api.upload(`/holders/${h.id}/photo`, form);
      setNotice(`Photo saved for ${h.fullName}.`);
      reload();
    } catch (err) {
      setFormError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageTitle>Holders</PageTitle>
      <Card>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            setApplied(search);
          }}
          className="flex flex-wrap items-end gap-3"
        >
          <div className="min-w-48 flex-1">
            <Field id="hsearch" label="Search name, ID or email" value={search} onChange={setSearch} />
          </div>
          <div className="mb-4 flex gap-2">
            <Btn type="submit">Search</Btn>
            <Btn kind="primary" onClick={() => startEdit('new')}>
              New holder
            </Btn>
          </div>
        </form>
      </Card>
      {notice && <Alert kind="success">{notice}</Alert>}
      {!editing && formError && <Alert kind="error">{formError}</Alert>}
      {editing && (
        <Card title={editing === 'new' ? 'New holder' : `Edit ${editing.fullName}`}>
          <form onSubmit={save} noValidate>
            {formError && <Alert kind="error">{formError}</Alert>}
            <Field id="fullName" label="Full name" value={fullName} onChange={setFullName} error={nameError} />
            <Field id="externalId" label="External ID (optional)" value={externalId} onChange={setExternalId} />
            <Field id="hemail" label="Email (optional)" type="email" value={email} onChange={setEmail} />
            <div className="flex gap-2">
              <Btn type="submit" kind="primary" disabled={busy}>
                Save
              </Btn>
              <Btn onClick={() => setEditing(null)}>Cancel</Btn>
            </div>
          </form>
          {editing !== 'new' && (
            <div className="mt-4 border-t border-slate-300 pt-4">
              <FilePicker
                id="photo"
                label={editing.hasPhoto ? 'Replace photo (PNG or JPEG, max 2 MB)' : 'Upload photo (PNG or JPEG, max 2 MB)'}
                disabled={busy}
                onFile={(f) => void uploadPhoto(editing, f)}
              />
            </div>
          )}
        </Card>
      )}
      <Loading error={error} loading={loading} />
      {data && (
        <div className="overflow-x-auto">
          <table className={tableCls}>
            <caption className="sr-only">Holders</caption>
            <thead>
              <tr>
                <th className={thCls}>Name</th>
                <th className={thCls}>External ID</th>
                <th className={thCls}>Email</th>
                <th className={thCls}>Photo</th>
                <th className={thCls}>Credentials</th>
                <th className={thCls}>
                  <span className="sr-only">Edit</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((h) => (
                <tr key={h.id}>
                  <td className={tdCls}>{h.fullName}</td>
                  <td className={tdCls}>{h.externalId ?? ''}</td>
                  <td className={tdCls}>{h.email ?? ''}</td>
                  <td className={tdCls}>{h.hasPhoto ? 'Yes' : 'No'}</td>
                  <td className={tdCls}>{h.credentialCount}</td>
                  <td className={tdCls}>
                    <Btn onClick={() => startEdit(h)}>Edit</Btn>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {data.items.length === 0 && <p className="mt-3 text-sm">No holders found.</p>}
          {data.total > data.items.length && (
            <p className="mt-3 text-sm">Showing {data.items.length} of {data.total}. Use search to narrow.</p>
          )}
        </div>
      )}
    </>
  );
}
