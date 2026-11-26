'use client';

import Link from 'next/link';
import { useCallback, useState, type FormEvent } from 'react';
import { api, describeError } from '@/lib/api';
import { buildAttributes, dateToIso } from '@/lib/dashboard';
import type { CredentialType, Holder, IssuedCredential } from '@/lib/dash-types';
import { Btn, Card, Loading, PageTitle, Select, useLoad } from '@/components/dash';
import { AttributeFields } from '@/components/attribute-fields';
import { Alert, Field, linkClass } from '@/components/ui';

export function IssueForm() {
  const loadTypes = useCallback(() => api.get<{ items: CredentialType[] }>('/credential-types'), []);
  const loadHolders = useCallback(() => api.get<{ items: Holder[] }>('/holders?limit=200'), []);
  const types = useLoad(loadTypes);
  const holders = useLoad(loadHolders);

  const [holderId, setHolderId] = useState('');
  const [typeCode, setTypeCode] = useState('');
  const [values, setValues] = useState<Record<string, string>>({});
  const [expires, setExpires] = useState('');
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [issued, setIssued] = useState<IssuedCredential | null>(null);

  const type = types.data?.items.find((t) => t.code === typeCode);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setFormError(null);
    const errs: Record<string, string> = {};
    if (!holderId) errs.holder = 'Choose a holder.';
    if (!type) errs.type = 'Choose a credential type.';
    const exp = dateToIso(expires);
    if (exp === null) errs.expires = 'Use a valid date.';
    const attrs = type ? buildAttributes(type.attributes, values) : { values: {}, errors: {} };
    Object.assign(errs, attrs.errors);
    setErrors(errs);
    if (Object.keys(errs).length || !type) return;
    setBusy(true);
    try {
      const res = await api.post<IssuedCredential>('/credentials', {
        holderId,
        credentialTypeCode: type.code,
        attributes: attrs.values,
        ...(exp ? { expiresAt: exp } : {}),
      });
      setIssued(res);
    } catch (err) {
      setFormError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  if (issued) {
    return (
      <>
        <PageTitle>Credential issued</PageTitle>
        <Alert kind="success">
          Credential {issued.credentialNumber} was signed and is active. The holder link below is shown only now.
        </Alert>
        <Card>
          <ul className="space-y-2 text-sm">
            <li>
              <Link className={linkClass} href={`/dashboard/credentials/${issued.id}`}>
                Open credential
              </Link>
            </li>
            <li>
              Public verification page:{' '}
              <a className={linkClass} href={`/v/${issued.verificationToken}`} target="_blank" rel="noreferrer">
                open
              </a>
            </li>
            <li>
              Holder page (private, share only with the holder):{' '}
              <a className={linkClass} href={`/h/${issued.holderToken}`} target="_blank" rel="noreferrer">
                open
              </a>
            </li>
          </ul>
        </Card>
        <Btn
          onClick={() => {
            setIssued(null);
            setValues({});
            setExpires('');
          }}
        >
          Issue another
        </Btn>
      </>
    );
  }

  return (
    <>
      <PageTitle>Issue a credential</PageTitle>
      <Loading error={types.error ?? holders.error} loading={types.loading || holders.loading} />
      {types.data && holders.data && (
        <Card>
          {types.data.items.length === 0 && (
            <Alert kind="info">
              Create a <Link className={linkClass} href="/dashboard/types">credential type</Link> first.
            </Alert>
          )}
          {holders.data.items.length === 0 && (
            <Alert kind="info">
              Add a <Link className={linkClass} href="/dashboard/holders">holder</Link> first. Holders need a photo
              before an ID can be issued.
            </Alert>
          )}
          <form onSubmit={submit} noValidate>
            {formError && <Alert kind="error">{formError}</Alert>}
            <Select
              id="holder"
              label="Holder"
              value={holderId}
              onChange={setHolderId}
              options={[
                { value: '', label: 'Choose...' },
                ...holders.data.items.map((h) => ({
                  value: h.id,
                  label: `${h.fullName}${h.externalId ? ` (${h.externalId})` : ''}${h.hasPhoto ? '' : ' - no photo'}`,
                })),
              ]}
            />
            {errors.holder && <p className="-mt-3 mb-3 text-sm font-medium text-red-800">! {errors.holder}</p>}
            <Select
              id="type"
              label="Credential type"
              value={typeCode}
              onChange={(v) => {
                setTypeCode(v);
                setValues({});
              }}
              options={[
                { value: '', label: 'Choose...' },
                ...types.data.items.map((t) => ({ value: t.code, label: t.name })),
              ]}
            />
            {errors.type && <p className="-mt-3 mb-3 text-sm font-medium text-red-800">! {errors.type}</p>}
            {type && (
              <>
                <AttributeFields
                  defs={type.attributes}
                  values={values}
                  errors={errors}
                  onChange={(k, v) => setValues((p) => ({ ...p, [k]: v }))}
                />
                <Field
                  id="expires"
                  label="Expiry date (optional)"
                  type="date"
                  value={expires}
                  onChange={setExpires}
                  error={errors.expires}
                  hint={
                    type.defaultValidityDays
                      ? `Leave empty for the default of ${type.defaultValidityDays} days.`
                      : 'Leave empty for no expiry.'
                  }
                />
              </>
            )}
            <Btn type="submit" kind="primary" disabled={busy}>
              {busy ? 'Signing...' : 'Issue credential'}
            </Btn>
          </form>
        </Card>
      )}
    </>
  );
}
