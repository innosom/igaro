'use client';

import Link from 'next/link';
import { useState, type FormEvent } from 'react';
import { api, describeError } from '@/lib/api';
import { hasErrors, validateEmail, validatePasswordSetup } from '@/lib/validation';
import { Alert, AuthShell, Field, linkClass, SubmitButton } from '@/components/ui';
import { useUrlToken } from '@/components/use-url-token';

export const NEUTRAL_RESET_MESSAGE =
  'If an account exists for that email address, we have sent a link to reset the password.';

export function PasswordResetForm() {
  const { token, ready } = useUrlToken();
  if (!ready) return <AuthShell title="Reset password">{null}</AuthShell>;
  return token ? <ConfirmForm token={token} /> : <RequestForm />;
}

function RequestForm() {
  const [email, setEmail] = useState('');
  const [error, setError] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    const v = validateEmail(email);
    setError(v ?? undefined);
    if (v) return;
    setBusy(true);
    try {
      await api.requestPasswordReset(email.trim());
    } catch {
      // Deliberately identical outcome for every failure: nothing here may reveal whether an account exists.
    }
    setSent(true);
    setBusy(false);
  }

  return (
    <AuthShell title="Reset password">
      {sent ? (
        <Alert kind="info">{NEUTRAL_RESET_MESSAGE}</Alert>
      ) : (
        <form onSubmit={onSubmit} noValidate>
          <p className="mb-4 text-sm text-slate-800">
            Enter your email address and we will send you a reset link.
          </p>
          <Field
            id="email"
            label="Email"
            type="email"
            autoComplete="email"
            value={email}
            onChange={setEmail}
            error={error}
            disabled={busy}
          />
          <SubmitButton busy={busy}>Send reset link</SubmitButton>
        </form>
      )}
      <p className="mt-4 text-sm">
        <Link href="/login" className={linkClass}>
          Back to sign in
        </Link>
      </p>
    </AuthShell>
  );
}

function ConfirmForm({ token }: { token: string }) {
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [errors, setErrors] = useState<{ password?: string; confirm?: string }>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setFormError(null);
    const v = validatePasswordSetup({ password, confirm });
    setErrors(v);
    if (hasErrors(v)) return;
    setBusy(true);
    try {
      await api.confirmPasswordReset(token, password);
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
      <AuthShell title="Password changed">
        <Alert kind="success">Your password has been changed. Sign in with the new password.</Alert>
        <Link href="/login" className={linkClass}>
          Continue to sign in
        </Link>
      </AuthShell>
    );
  }

  return (
    <AuthShell title="Choose a new password">
      <form onSubmit={onSubmit} noValidate>
        {formError && <Alert kind="error">{formError}</Alert>}
        <Field
          id="password"
          label="New password"
          type="password"
          autoComplete="new-password"
          hint="At least 12 characters."
          value={password}
          onChange={setPassword}
          error={errors.password}
          disabled={busy}
        />
        <Field
          id="confirm"
          label="Confirm password"
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={setConfirm}
          error={errors.confirm}
          disabled={busy}
        />
        <SubmitButton busy={busy}>Change password</SubmitButton>
      </form>
      <p className="mt-4 text-sm">
        <Link href="/login" className={linkClass}>
          Back to sign in
        </Link>
      </p>
    </AuthShell>
  );
}
