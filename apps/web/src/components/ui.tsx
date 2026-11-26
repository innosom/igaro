import type { ReactNode } from 'react';

export function AuthShell({ title, children }: { title: string; children: ReactNode }) {
  return (
    <main className="mx-auto flex min-h-screen w-full max-w-md flex-col justify-center px-4 py-8">
      <p className="mb-2 text-sm font-semibold tracking-widest text-slate-700">iGARO</p>
      <h1 className="mb-6 text-2xl font-bold text-slate-900">{title}</h1>
      <div className="rounded-lg border border-slate-300 bg-white p-5 shadow-sm">{children}</div>
    </main>
  );
}

export function Field(props: {
  id: string;
  label: string;
  type?: string;
  value: string;
  onChange: (v: string) => void;
  error?: string;
  hint?: string;
  autoComplete?: string;
  disabled?: boolean;
}) {
  const { id, label, error, hint } = props;
  const describedBy = [error ? `${id}-error` : null, hint ? `${id}-hint` : null]
    .filter(Boolean)
    .join(' ');
  return (
    <div className="mb-4">
      <label htmlFor={id} className="mb-1 block text-sm font-medium text-slate-900">
        {label}
      </label>
      <input
        id={id}
        name={id}
        type={props.type ?? 'text'}
        value={props.value}
        onChange={(e) => props.onChange(e.target.value)}
        autoComplete={props.autoComplete}
        disabled={props.disabled}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy || undefined}
        className={`block w-full rounded-md border bg-white px-3 py-2 text-base text-slate-900 ${
          error ? 'border-red-700' : 'border-slate-500'
        }`}
      />
      {hint && (
        <p id={`${id}-hint`} className="mt-1 text-sm text-slate-700">
          {hint}
        </p>
      )}
      {error && (
        <p id={`${id}-error`} className="mt-1 text-sm font-medium text-red-800">
          <span aria-hidden="true">! </span>
          {error}
        </p>
      )}
    </div>
  );
}

export function SubmitButton({ busy, children }: { busy: boolean; children: ReactNode }) {
  return (
    <button
      type="submit"
      disabled={busy}
      aria-disabled={busy}
      className="w-full rounded-md bg-blue-800 px-4 py-3 text-base font-semibold text-white hover:bg-blue-900 disabled:opacity-60"
    >
      {busy ? 'Please wait...' : children}
    </button>
  );
}

export function Alert({
  kind,
  children,
}: {
  kind: 'error' | 'success' | 'info';
  children: ReactNode;
}) {
  const styles = {
    error: 'border-red-800 bg-red-50 text-red-900',
    success: 'border-green-800 bg-green-50 text-green-900',
    info: 'border-slate-600 bg-slate-50 text-slate-900',
  }[kind];
  const prefix = { error: 'Error: ', success: 'Done: ', info: '' }[kind];
  return (
    <div role={kind === 'error' ? 'alert' : 'status'} className={`mb-4 rounded-md border-l-4 p-3 text-sm ${styles}`}>
      {prefix && <strong>{prefix}</strong>}
      {children}
    </div>
  );
}

export const linkClass = 'font-medium text-blue-800 underline underline-offset-2';
