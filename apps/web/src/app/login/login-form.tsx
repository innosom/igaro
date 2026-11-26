'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import { api, describeError } from '@/lib/api';
import { hasErrors, validateLogin } from '@/lib/validation';
import { Alert, AuthShell, Field, linkClass, SubmitButton } from '@/components/ui';

export function LoginForm() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [errors, setErrors] = useState<{ email?: string; password?: string }>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setFormError(null);
    const v = validateLogin({ email, password });
    setErrors(v);
    if (hasErrors(v)) return;
    setBusy(true);
    try {
      await api.login(email.trim(), password);
      setPassword('');
      router.push('/dashboard');
    } catch (err) {
      setFormError(describeError(err));
      setBusy(false);
    }
  }

  return (
    <AuthShell title="Sign in">
      <form onSubmit={onSubmit} noValidate>
        {formError && <Alert kind="error">{formError}</Alert>}
        <Field
          id="email"
          label="Email"
          type="email"
          autoComplete="username"
          value={email}
          onChange={setEmail}
          error={errors.email}
          disabled={busy}
        />
        <Field
          id="password"
          label="Password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={setPassword}
          error={errors.password}
          disabled={busy}
        />
        <SubmitButton busy={busy}>Sign in</SubmitButton>
      </form>
      <p className="mt-4 text-sm">
        <Link href="/password-reset" className={linkClass}>
          Forgot your password?
        </Link>
      </p>
    </AuthShell>
  );
}
