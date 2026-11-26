'use client';

import Link from 'next/link';
import { useState, type FormEvent } from 'react';
import { api, describeError } from '@/lib/api';
import { hasErrors, validateName, validatePasswordSetup } from '@/lib/validation';
import { Alert, AuthShell, Field, linkClass, SubmitButton } from '@/components/ui';
import { useUrlToken } from '@/components/use-url-token';

export function AcceptInviteForm() {
  const { token, ready } = useUrlToken();
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [errors, setErrors] = useState<{ name?: string; password?: string; confirm?: string }>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (!token) return;
    setFormError(null);
    const v: typeof errors = validatePasswordSetup({ password, confirm });
    const n = validateName(name);
    if (n) v.name = n;
    setErrors(v);
    if (hasErrors(v)) return;
    setBusy(true);
    try {
      await api.acceptInvite(token, password, name.trim() || undefined);
      setPassword('');
      setConfirm('');
      setDone(true);
    } catch (err) {
      setFormError(describeError(err));
      setBusy(false);
    }
  }

  if (done) {
    return (
      <AuthShell title="Account ready">
        <Alert kind="success">Your password is set.</Alert>
        <Link href="/login" className={linkClass}>
          Continue to sign in
        </Link>
      </AuthShell>
    );
  }

  if (ready && !token) {
    return (
      <AuthShell title="Accept invitation">
        <Alert kind="error">
          This invitation link is missing or incomplete. Open the link from your invitation email
          again, or ask your administrator to send a new invitation.
        </Alert>
        <Link href="/login" className={linkClass}>
          Go to sign in
        </Link>
      </AuthShell>
    );
  }

  return (
    <AuthShell title="Accept invitation">
      <p className="mb-4 text-sm text-slate-800">Choose a password to finish setting up your account.</p>
      <form onSubmit={onSubmit} noValidate>
        {formError && <Alert kind="error">{formError}</Alert>}
        <Field
          id="name"
          label="Your name (optional)"
          autoComplete="name"
          value={name}
          onChange={setName}
          error={errors.name}
          disabled={busy || !ready}
        />
        <Field
          id="password"
          label="New password"
          type="password"
          autoComplete="new-password"
          hint="At least 12 characters."
          value={password}
          onChange={setPassword}
          error={errors.password}
          disabled={busy || !ready}
        />
        <Field
          id="confirm"
          label="Confirm password"
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={setConfirm}
          error={errors.confirm}
          disabled={busy || !ready}
        />
        <SubmitButton busy={busy || !ready}>Set password</SubmitButton>
      </form>
    </AuthShell>
  );
}
