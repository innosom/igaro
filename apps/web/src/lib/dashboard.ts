// Pure helpers for the institution dashboard (no React, no network).

export const STATUSES = ['ACTIVE', 'SUSPENDED', 'REVOKED', 'SUPERSEDED', 'EXPIRED', 'DRAFT'] as const;

export interface AttributeDef {
  key: string;
  label: string;
  type: 'string' | 'date' | 'number';
  required: boolean;
}

/** Status chips always carry the status text, so colour is never the only signal. */
export function statusClass(status: string): string {
  switch (status) {
    case 'ACTIVE':
      return 'border-green-800 bg-green-50 text-green-900';
    case 'SUSPENDED':
      return 'border-amber-800 bg-amber-50 text-amber-900';
    case 'REVOKED':
      return 'border-red-800 bg-red-50 text-red-900';
    default:
      return 'border-slate-600 bg-slate-50 text-slate-900';
  }
}

/** Builds a query string, skipping empty values. */
export function buildQuery(params: Record<string, string | number | undefined | null>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null) continue;
    const s = String(v).trim();
    if (s !== '') sp.set(k, s);
  }
  const q = sp.toString();
  return q ? `?${q}` : '';
}

/** `2027-01-31` (date input) to the API's `2027-01-31T00:00:00Z`; empty -> undefined; invalid -> null. */
export function dateToIso(value: string): string | undefined | null {
  const v = value.trim();
  if (!v) return undefined;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(v)) return null;
  const d = new Date(`${v}T00:00:00Z`);
  if (Number.isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== v) return null;
  return `${v}T00:00:00Z`;
}

export function isHexColor(v: string): boolean {
  return /^#[0-9a-fA-F]{6}$/.test(v);
}

/** Reason rules shared by suspend/revoke/compromise: 1-500 chars after trim. */
export function validateReason(reason: string): string | undefined {
  const r = reason.trim();
  if (!r) return 'A reason is required.';
  if (r.length > 500) return 'The reason must be 500 characters or fewer.';
  return undefined;
}

/**
 * Converts form strings into attribute values by schema. Empty optional values are omitted;
 * numbers become numbers. Errors are keyed by attribute key.
 */
export function buildAttributes(
  defs: AttributeDef[],
  raw: Record<string, string>,
): { values: Record<string, string | number>; errors: Record<string, string> } {
  const values: Record<string, string | number> = {};
  const errors: Record<string, string> = {};
  for (const d of defs) {
    const v = (raw[d.key] ?? '').trim();
    if (!v) {
      if (d.required) errors[d.key] = `${d.label} is required.`;
      continue;
    }
    if (d.type === 'number') {
      const n = Number(v);
      if (!Number.isFinite(n)) errors[d.key] = `${d.label} must be a number.`;
      else values[d.key] = n;
    } else if (d.type === 'date') {
      if (dateToIso(v) === null) errors[d.key] = `${d.label} must be a valid date.`;
      else values[d.key] = v;
    } else {
      values[d.key] = v;
    }
  }
  return { values, errors };
}

/** Prefill form strings from an existing attribute object. */
export function attributesToForm(
  defs: AttributeDef[],
  attrs: Record<string, unknown> | undefined,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const d of defs) {
    const v = attrs?.[d.key];
    out[d.key] = v === undefined || v === null ? '' : String(v);
  }
  return out;
}

export const PUBLIC_FIELD_OPTIONS = [
  { key: 'photo', label: 'Photo' },
  { key: 'idNumber', label: 'ID number' },
  { key: 'attributes', label: 'Credential attributes' },
] as const;

export function togglePublicField(current: string[], key: string, on: boolean): string[] {
  const set = new Set(current);
  if (on) set.add(key);
  else set.delete(key);
  return PUBLIC_FIELD_OPTIONS.map((o) => o.key).filter((k) => set.has(k));
}

/** Only send fields that changed (PATCH rejects empty bodies). */
export function diffPatch<T extends Record<string, unknown>>(before: T, after: T): Partial<T> {
  const out: Partial<T> = {};
  for (const k of Object.keys(after) as (keyof T)[]) {
    if (JSON.stringify(before[k]) !== JSON.stringify(after[k])) out[k] = after[k];
  }
  return out;
}

/** Empty string -> null (clears the field on PATCH) for optional holder fields. */
export function emptyToNull(v: string): string | null {
  const t = v.trim();
  return t === '' ? null : t;
}

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return 'None';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? 'Unknown' : d.toISOString().slice(0, 10);
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return 'None';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? 'Unknown' : `${d.toISOString().replace('T', ' ').slice(0, 19)} UTC`;
}

/** Client-side check of a new credential type before sending (the API is authoritative). */
export function validateTypeDraft(d: {
  code: string;
  name: string;
  attributes: AttributeDef[];
}): string | undefined {
  if (!/^[A-Z][A-Z0-9_]{1,39}$/.test(d.code)) {
    return 'Code must be 2-40 characters: capital letters, digits and underscores, starting with a letter.';
  }
  if (!d.name.trim()) return 'Name is required.';
  const seen = new Set<string>();
  for (const a of d.attributes) {
    if (!/^[a-z][A-Za-z0-9]{0,49}$/.test(a.key)) {
      return `Attribute key "${a.key}" must be camelCase (letters and digits, starting lower-case).`;
    }
    if (seen.has(a.key)) return `Attribute key "${a.key}" is used twice.`;
    seen.add(a.key);
    if (!a.label.trim()) return `Attribute "${a.key}" needs a label.`;
  }
  return undefined;
}
