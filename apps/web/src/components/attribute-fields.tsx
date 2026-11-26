'use client';

import type { AttributeDef } from '@/lib/dashboard';
import { Field } from './ui';

/** Renders inputs generated from a credential type's attribute schema. */
export function AttributeFields(props: {
  defs: AttributeDef[];
  values: Record<string, string>;
  errors: Record<string, string>;
  onChange: (key: string, v: string) => void;
}) {
  return (
    <>
      {props.defs.map((d) => (
        <Field
          key={d.key}
          id={`attr-${d.key}`}
          label={`${d.label}${d.required ? ' (required)' : ''}`}
          type={d.type === 'date' ? 'date' : d.type === 'number' ? 'text' : 'text'}
          value={props.values[d.key] ?? ''}
          onChange={(v) => props.onChange(d.key, v)}
          error={props.errors[d.key]}
          hint={d.type === 'number' ? 'A number' : undefined}
        />
      ))}
    </>
  );
}
