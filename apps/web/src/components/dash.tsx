'use client';

import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { describeError } from '@/lib/api';
import { statusClass } from '@/lib/dashboard';
import { Alert } from './ui';

/** Loads data on mount and whenever `load` changes. `load` must be memoised by the caller. */
export function useLoad<T>(load: () => Promise<T>) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let live = true;
    setLoading(true);
    load()
      .then((d) => {
        if (live) {
          setData(d);
          setError(null);
        }
      })
      .catch((e) => live && setError(describeError(e)))
      .finally(() => live && setLoading(false));
    return () => {
      live = false;
    };
  }, [load, tick]);
  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { data, error, loading, reload };
}

export function PageTitle({ children }: { children: ReactNode }) {
  return <h1 className="mb-4 text-2xl font-bold text-slate-900">{children}</h1>;
}

export function Card({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <section className="mb-6 rounded-lg border border-slate-300 bg-white p-4 shadow-sm">
      {title && <h2 className="mb-3 text-lg font-semibold text-slate-900">{title}</h2>}
      {children}
    </section>
  );
}

export function StatusChip({ status }: { status: string }) {
  return (
    <span className={`inline-block rounded border px-2 py-0.5 text-xs font-bold ${statusClass(status)}`}>
      {status}
    </span>
  );
}

export function Btn(props: {
  children: ReactNode;
  onClick?: () => void;
  type?: 'button' | 'submit';
  kind?: 'primary' | 'secondary' | 'danger';
  disabled?: boolean;
}) {
  const kind = props.kind ?? 'secondary';
  const cls = {
    primary: 'bg-blue-800 text-white hover:bg-blue-900 border-blue-800',
    secondary: 'bg-white text-slate-900 border-slate-600 hover:bg-slate-100',
    danger: 'bg-red-800 text-white hover:bg-red-900 border-red-800',
  }[kind];
  return (
    <button
      type={props.type ?? 'button'}
      onClick={props.onClick}
      disabled={props.disabled}
      className={`rounded-md border px-3 py-2 text-sm font-semibold disabled:opacity-60 ${cls}`}
    >
      {props.children}
    </button>
  );
}

export function Select(props: {
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <div className="mb-4">
      <label htmlFor={props.id} className="mb-1 block text-sm font-medium text-slate-900">
        {props.label}
      </label>
      <select
        id={props.id}
        value={props.value}
        onChange={(e) => props.onChange(e.target.value)}
        className="block w-full rounded-md border border-slate-500 bg-white px-3 py-2 text-base text-slate-900"
      >
        {props.options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </div>
  );
}

export function Loading({ error, loading }: { error: string | null; loading: boolean }) {
  if (error) return <Alert kind="error">{error}</Alert>;
  if (loading) return <p className="text-sm text-slate-700">Loading...</p>;
  return null;
}

/** File picker that uploads immediately on selection. */
export function FilePicker(props: {
  id: string;
  label: string;
  onFile: (f: File) => void;
  disabled?: boolean;
}) {
  return (
    <div className="mb-4">
      <label htmlFor={props.id} className="mb-1 block text-sm font-medium text-slate-900">
        {props.label}
      </label>
      <input
        id={props.id}
        type="file"
        accept="image/png,image/jpeg"
        disabled={props.disabled}
        onChange={(e) => {
          const f = e.target.files?.[0];
          e.target.value = '';
          if (f) props.onFile(f);
        }}
        className="block w-full text-sm"
      />
    </div>
  );
}

/** Generic file input that only reports the selection (no upload); `accept` is a hint, callers validate. */
export function FileInput(props: {
  id: string;
  label: string;
  accept: string;
  hint?: string;
  error?: string;
  disabled?: boolean;
  /** Changing `resetKey` clears the native input. */
  resetKey?: number;
  onFile: (f: File | null) => void;
}) {
  const describedBy = [props.hint ? `${props.id}-hint` : null, props.error ? `${props.id}-error` : null]
    .filter(Boolean)
    .join(' ');
  return (
    <div className="mb-4">
      <label htmlFor={props.id} className="mb-1 block text-sm font-medium text-slate-900">
        {props.label}
      </label>
      <input
        key={props.resetKey}
        id={props.id}
        type="file"
        accept={props.accept}
        disabled={props.disabled}
        aria-invalid={props.error ? true : undefined}
        aria-describedby={describedBy || undefined}
        onChange={(e) => props.onFile(e.target.files?.[0] ?? null)}
        className="block w-full text-sm"
      />
      {props.hint && (
        <p id={`${props.id}-hint`} className="mt-1 text-sm text-slate-700">
          {props.hint}
        </p>
      )}
      {props.error && (
        <p id={`${props.id}-error`} className="mt-1 text-sm font-medium text-red-800">
          <span aria-hidden="true">! </span>
          {props.error}
        </p>
      )}
    </div>
  );
}

export const tableCls = 'w-full text-left text-sm';
export const thCls = 'border-b border-slate-400 px-2 py-2 font-semibold text-slate-900';
export const tdCls = 'border-b border-slate-200 px-2 py-2 align-top';
