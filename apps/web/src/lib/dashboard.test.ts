import { describe, expect, it } from 'vitest';
import {
  buildAttributes,
  buildQuery,
  dateToIso,
  diffPatch,
  emptyToNull,
  formatDate,
  isHexColor,
  togglePublicField,
  validateReason,
  validateTypeDraft,
  type AttributeDef,
} from './dashboard';

const defs: AttributeDef[] = [
  { key: 'course', label: 'Course', type: 'string', required: true },
  { key: 'grade', label: 'Grade', type: 'number', required: false },
  { key: 'awardedOn', label: 'Awarded', type: 'date', required: false },
];

describe('dashboard helpers', () => {
  it('builds queries skipping blanks and encoding values', () => {
    expect(buildQuery({ q: ' a b ', status: '', type: undefined, limit: 50 })).toBe('?q=a+b&limit=50');
    expect(buildQuery({})).toBe('');
  });
  it('converts dates', () => {
    expect(dateToIso('2027-01-31')).toBe('2027-01-31T00:00:00Z');
    expect(dateToIso('')).toBeUndefined();
    expect(dateToIso('2027-02-31')).toBeNull();
    expect(dateToIso('31/01/2027')).toBeNull();
  });
  it('validates colours and reasons', () => {
    expect(isHexColor('#0a1B2c')).toBe(true);
    expect(isHexColor('#fff')).toBe(false);
    expect(validateReason('   ')).toBeDefined();
    expect(validateReason('x'.repeat(501))).toBeDefined();
    expect(validateReason('lost card')).toBeUndefined();
  });
  it('builds attributes by schema', () => {
    expect(buildAttributes(defs, { course: ' Math ', grade: '4.5', awardedOn: '2026-05-01' })).toEqual({
      values: { course: 'Math', grade: 4.5, awardedOn: '2026-05-01' },
      errors: {},
    });
    const bad = buildAttributes(defs, { course: '', grade: 'x', awardedOn: 'nope' });
    expect(Object.keys(bad.errors).sort()).toEqual(['awardedOn', 'course', 'grade']);
    expect(buildAttributes(defs, { course: 'a' }).values).toEqual({ course: 'a' });
  });
  it('toggles public fields in canonical order and never offers name/status', () => {
    expect(togglePublicField(['attributes'], 'photo', true)).toEqual(['photo', 'attributes']);
    expect(togglePublicField(['photo'], 'photo', false)).toEqual([]);
    expect(togglePublicField([], 'name', true)).toEqual([]);
  });
  it('diffs patches and nulls empties', () => {
    expect(diffPatch({ a: 1, b: [1] }, { a: 1, b: [2] })).toEqual({ b: [2] });
    expect(emptyToNull('  ')).toBeNull();
    expect(emptyToNull(' x ')).toBe('x');
  });
  it('formats dates safely', () => {
    expect(formatDate('2027-01-31T10:00:00Z')).toBe('2027-01-31');
    expect(formatDate(null)).toBe('None');
    expect(formatDate('garbage')).toBe('Unknown');
  });
  it('validates type drafts', () => {
    expect(validateTypeDraft({ code: 'ID', name: 'x', attributes: [] })).toBeUndefined();
    expect(validateTypeDraft({ code: 'id', name: 'x', attributes: [] })).toBeDefined();
    expect(validateTypeDraft({ code: 'ID', name: 'x', attributes: [defs[0]!, defs[0]!] })).toMatch(/twice/);
  });
});
