import { describe, expect, it } from 'vitest';
import { areaAllowed, validateInstitutionDraft, validateSlug } from './platform';

describe('validateSlug', () => {
  it('accepts valid slugs', () => {
    for (const s of ['abc', 'a-b', 'uni-2027', 'a'.repeat(40)]) expect(validateSlug(s)).toBeUndefined();
  });
  it('rejects invalid slugs', () => {
    for (const s of ['', 'ab', 'a'.repeat(41), 'Abc', 'a_b', 'a b', '-abc', 'abc-', 'abé']) {
      expect(validateSlug(s), s).toBeTruthy();
    }
  });
});

describe('validateInstitutionDraft', () => {
  it('reports every bad field', () => {
    expect(Object.keys(validateInstitutionDraft({ name: ' ', slug: '-x', adminEmail: 'nope' })).sort()).toEqual([
      'adminEmail',
      'name',
      'slug',
    ]);
  });
  it('passes a good draft', () => {
    expect(validateInstitutionDraft({ name: 'Uni', slug: 'uni', adminEmail: 'a@b.co' })).toEqual({});
  });
});

describe('areaAllowed', () => {
  it('separates the two roles', () => {
    expect(areaAllowed('PLATFORM_ADMIN', '/dashboard/platform')).toBe(true);
    expect(areaAllowed('PLATFORM_ADMIN', '/dashboard')).toBe(false);
    expect(areaAllowed('PLATFORM_ADMIN', '/dashboard/import')).toBe(false);
    expect(areaAllowed('INSTITUTION_ADMIN', '/dashboard/import')).toBe(true);
    expect(areaAllowed('INSTITUTION_ADMIN', '/dashboard/platform')).toBe(false);
    expect(areaAllowed('INSTITUTION_ADMIN', '/dashboard/platformx')).toBe(true);
  });
});
