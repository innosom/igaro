'use client';

import { useCallback, useState, type FormEvent } from 'react';
import { api, describeError } from '@/lib/api';
import { validateTypeDraft, type AttributeDef } from '@/lib/dashboard';
import type { CredentialType } from '@/lib/dash-types';
import { Btn, Card, Loading, PageTitle, Select, tableCls, tdCls, thCls, useLoad } from '@/components/dash';
import { Alert, Field } from '@/components/ui';

const emptyAttr = (): AttributeDef => ({ key: '', label: '', type: 'string', required: false });

export function TypesView() {
  const load = useCallback(() => api.get<{ items: CredentialType[] }>('/credential-types'), []);
  const { data, error, loading, reload } = useLoad(load);
  const [creating, setCreating] = useState(false);
  const [code, setCode] = useState('');
  const [name, setName] = useState('');
  const [kind, setKind] = useState('ID_CARD');
  const [validity, setValidity] = useState('');
  const [attrs, setAttrs] = useState<AttributeDef[]>([emptyAttr()]);
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function setAttr(i: number, patch: Partial<AttributeDef>) {
    setAttrs((a) => a.map((x, j) => (j === i ? { ...x, ...patch } : x)));
  }

  async function save(e: FormEvent) {
    e.preventDefault();
    const cleaned = attrs.filter((a) => a.key || a.label);
    const days = validity.trim() ? Number(validity) : null;
    const problem =
      validateTypeDraft({ code, name, attributes: cleaned }) ??
      (days !== null && (!Number.isInteger(days) || days < 1) ? 'Validity must be a whole number of days.' : undefined);
    if (problem) {
      setFormError(problem);
      return;
    }
    setBusy(true);
    setFormError(null);
    try {
      await api.post('/credential-types', { code, name: name.trim(), kind, attributes: cleaned, defaultValidityDays: days });
      setCreating(false);
      reload();
    } catch (err) {
      setFormError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  async function remove(t: CredentialType) {
    if (!window.confirm(`Delete credential type ${t.name}?`)) return;
    try {
      await api.del(`/credential-types/${t.id}`);
      reload();
    } catch (err) {
      setFormError(describeError(err));
    }
  }

  return (
    <>
      <PageTitle>Credential types</PageTitle>
      <p className="mb-3">
        <Btn
          kind="primary"
          onClick={() => {
            setCreating(true);
            setFormError(null);
          }}
        >
          New type
        </Btn>
      </p>
      {!creating && formError && <Alert kind="error">{formError}</Alert>}
      {creating && (
        <Card title="New credential type">
          <form onSubmit={save} noValidate>
            {formError && <Alert kind="error">{formError}</Alert>}
            <Field id="code" label="Code" value={code} onChange={(v) => setCode(v.toUpperCase())} hint="For example STUDENT_ID. Cannot be changed later." />
            <Field id="tname" label="Name" value={name} onChange={setName} />
            <Select
              id="kind"
              label="Kind"
              value={kind}
              onChange={setKind}
              options={[
                { value: 'ID_CARD', label: 'ID card' },
                { value: 'CERTIFICATE', label: 'Certificate' },
              ]}
            />
            <Field id="validity" label="Default validity in days (optional)" value={validity} onChange={setValidity} />
            <fieldset className="mb-4">
              <legend className="mb-1 text-sm font-medium">Attributes</legend>
              {attrs.map((a, i) => (
                <div key={i} className="mb-3 grid gap-2 rounded border border-slate-300 p-2 sm:grid-cols-4">
                  <Field id={`ak${i}`} label="Key" value={a.key} onChange={(v) => setAttr(i, { key: v })} />
                  <Field id={`al${i}`} label="Label" value={a.label} onChange={(v) => setAttr(i, { label: v })} />
                  <Select
                    id={`at${i}`}
                    label="Type"
                    value={a.type}
                    onChange={(v) => setAttr(i, { type: v as AttributeDef['type'] })}
                    options={[
                      { value: 'string', label: 'Text' },
                      { value: 'date', label: 'Date' },
                      { value: 'number', label: 'Number' },
                    ]}
                  />
                  <label className="flex items-center gap-2 text-sm">
                    <input type="checkbox" checked={a.required} onChange={(e) => setAttr(i, { required: e.target.checked })} />
                    Required
                  </label>
                </div>
              ))}
              <Btn onClick={() => setAttrs((a) => [...a, emptyAttr()])}>Add attribute</Btn>
            </fieldset>
            <div className="flex gap-2">
              <Btn type="submit" kind="primary" disabled={busy}>
                Create type
              </Btn>
              <Btn onClick={() => setCreating(false)}>Cancel</Btn>
            </div>
          </form>
        </Card>
      )}
      <Loading error={error} loading={loading} />
      {data && (
        <div className="overflow-x-auto">
          <table className={tableCls}>
            <caption className="sr-only">Credential types</caption>
            <thead>
              <tr>
                <th className={thCls}>Code</th>
                <th className={thCls}>Name</th>
                <th className={thCls}>Kind</th>
                <th className={thCls}>Attributes</th>
                <th className={thCls}>Issued</th>
                <th className={thCls}>
                  <span className="sr-only">Delete</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((t) => (
                <tr key={t.id}>
                  <td className={tdCls}>{t.code}</td>
                  <td className={tdCls}>{t.name}</td>
                  <td className={tdCls}>{t.kind === 'ID_CARD' ? 'ID card' : 'Certificate'}</td>
                  <td className={tdCls}>{t.attributes.map((a) => a.label).join(', ')}</td>
                  <td className={tdCls}>{t.credentialCount}</td>
                  <td className={tdCls}>
                    {t.credentialCount === 0 && <Btn onClick={() => void remove(t)}>Delete</Btn>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {data.items.length === 0 && <p className="mt-3 text-sm">No credential types yet.</p>}
        </div>
      )}
    </>
  );
}
