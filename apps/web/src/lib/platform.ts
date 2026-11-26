// Pure helpers for the platform admin screens.

export interface PlatformInstitution {
  id: string;
  name: string;
  slug: string;
  status: string;
  createdAt: string;
  updatedAt: string;
  activeKid: string | null;
}

/** Slug: 3-40 chars of [a-z0-9-], no leading or trailing hyphen (same rule as the API). */
export function validateSlug(slug: string): string | undefined {
  if (!slug) return 'A slug is required.';
  if (slug.length < 3 || slug.length > 40) return 'The slug must be 3 to 40 characters.';
  if (!/^[a-z0-9-]+$/.test(slug)) return 'Use only lower-case letters, digits and hyphens.';
  if (slug.startsWith('-') || slug.endsWith('-')) return 'The slug cannot start or end with a hyphen.';
  return undefined;
}

export function validateEmail(email: string): string | undefined {
  const e = email.trim();
  if (!e) return 'An admin email is required.';
  if (e.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) return 'Enter a valid email address.';
  return undefined;
}

export function validateInstitutionDraft(d: { name: string; slug: string; adminEmail: string }): Record<string, string> {
  const errors: Record<string, string> = {};
  if (!d.name.trim()) errors.name = 'A name is required.';
  else if (d.name.trim().length > 200) errors.name = 'The name must be 200 characters or fewer.';
  const s = validateSlug(d.slug);
  if (s) errors.slug = s;
  const m = validateEmail(d.adminEmail);
  if (m) errors.adminEmail = m;
  return errors;
}

/** Which areas a role may see. Shell uses this to avoid rendering the other role's screens. */
export function areaAllowed(role: 'PLATFORM_ADMIN' | 'INSTITUTION_ADMIN', path: string): boolean {
  const platform = path === '/dashboard/platform' || path.startsWith('/dashboard/platform/');
  return role === 'PLATFORM_ADMIN' ? platform : !platform;
}
