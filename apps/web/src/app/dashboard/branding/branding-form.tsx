'use client';

import { useEffect, useState, type FormEvent } from 'react';
import { api, describeError } from '@/lib/api';
import { diffPatch, emptyToNull, isHexColor, PUBLIC_FIELD_OPTIONS, togglePublicField } from '@/lib/dashboard';
import type { Profile } from '@/lib/dash-types';
import { Btn, Card, FilePicker, Loading, PageTitle, useLoad } from '@/components/dash';
import { Alert, Field } from '@/components/ui';

const load = () => api.get<Profile>('/institution');

export function BrandingForm() {
  const { data, error, loading, reload } = useLoad(load);
  const [cardTitle, setCardTitle] = useState('');
  const [primary, setPrimary] = useState('');
  const [secondary, setSecondary] = useState('');
  const [fields, setFields] = useState<string[]>([]);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!data) return;
    setCardTitle(data.cardTitle ?? '');
    setPrimary(data.primaryColor ?? '');
    setSecondary(data.secondaryColor ?? '');
    setFields(data.publicFields);
  }, [data]);

  async function save(e: FormEvent) {
    e.preventDefault();
    if (!data) return;
    const errs: Record<string, string> = {};
    if (primary.trim() && !isHexColor(primary.trim())) errs.primary = 'Use a colour like #1a2b3c.';
    if (secondary.trim() && !isHexColor(secondary.trim())) errs.secondary = 'Use a colour like #1a2b3c.';
    if (cardTitle.trim().length > 100) errs.title = 'Card title must be 100 characters or fewer.';
    setErrors(errs);
    if (Object.keys(errs).length) return;
    const patch = diffPatch(
      {
        cardTitle: data.cardTitle,
        primaryColor: data.primaryColor,
        secondaryColor: data.secondaryColor,
        publicFields: data.publicFields,
      },
      {
        cardTitle: emptyToNull(cardTitle),
        primaryColor: emptyToNull(primary),
        secondaryColor: emptyToNull(secondary),
        publicFields: fields,
      },
    );
    if (Object.keys(patch).length === 0) {
      setNotice('Nothing to save.');
      return;
    }
    setBusy(true);
    setFormError(null);
    setNotice(null);
    try {
      await api.patch<Profile>('/institution', patch);
      setNotice('Branding saved.');
      reload();
    } catch (err) {
      setFormError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  async function uploadLogo(file: File) {
    setBusy(true);
    setFormError(null);
    setNotice(null);
    try {
      const form = new FormData();
      form.append('file', file);
      await api.upload('/institution/logo', form);
      setNotice('Logo saved.');
      reload();
    } catch (err) {
      setFormError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageTitle>Branding</PageTitle>
      <Loading error={error} loading={loading} />
      {notice && <Alert kind="success">{notice}</Alert>}
      {formError && <Alert kind="error">{formError}</Alert>}
      {data && (
        <>
          <Card title="Logo">
            <p className="mb-3 text-sm">{data.hasLogo ? 'A logo is set.' : 'No logo yet.'}</p>
            <FilePicker id="logo" label="Upload logo (PNG or JPEG, max 1 MB)" disabled={busy} onFile={(f) => void uploadLogo(f)} />
          </Card>
          <Card title="Card and verification page">
            <form onSubmit={save} noValidate>
              <Field id="cardTitle" label="Card title" value={cardTitle} onChange={setCardTitle} error={errors.title} />
              <Field id="primary" label="Primary colour" value={primary} onChange={setPrimary} error={errors.primary} hint="Hex, for example #1a2b3c" />
              <Field id="secondary" label="Secondary colour" value={secondary} onChange={setSecondary} error={errors.secondary} hint="Hex, for example #f0f4f8" />
              <fieldset className="mb-4">
                <legend className="mb-1 text-sm font-medium">Fields shown on the public verification page</legend>
                <label className="flex items-center gap-2 py-1 text-sm">
                  <input type="checkbox" checked disabled /> Name (always shown)
                </label>
                <label className="flex items-center gap-2 py-1 text-sm">
                  <input type="checkbox" checked disabled /> Status (always shown)
                </label>
                {PUBLIC_FIELD_OPTIONS.map((o) => (
                  <label key={o.key} className="flex items-center gap-2 py-1 text-sm">
                    <input
                      type="checkbox"
                      checked={fields.includes(o.key)}
                      onChange={(e) => setFields((f) => togglePublicField(f, o.key, e.target.checked))}
                    />
                    {o.label}
                  </label>
                ))}
              </fieldset>
              <Btn type="submit" kind="primary" disabled={busy}>
                Save branding
              </Btn>
            </form>
          </Card>
        </>
      )}
    </>
  );
}
