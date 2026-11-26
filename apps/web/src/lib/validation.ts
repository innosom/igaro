// Pure form validation. Mirrors the API limits (apps/api/src/account.ts, auth-routes.ts); the API stays authoritative.
export const MIN_PASSWORD = 12;
export const MAX_PASSWORD = 256;
export const MAX_EMAIL = 254;
export const MAX_NAME = 200;

export type FieldErrors<K extends string> = Partial<Record<K, string>>;

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function validateEmail(email: string): string | null {
  const v = email.trim();
  if (!v) return 'Enter your email address.';
  if (v.length > MAX_EMAIL || !EMAIL_RE.test(v)) return 'Enter a valid email address.';
  return null;
}

export function validateNewPassword(password: string, email?: string): string | null {
  if (password.length < MIN_PASSWORD) return `Use at least ${MIN_PASSWORD} characters.`;
  if (password.length > MAX_PASSWORD) return `Use at most ${MAX_PASSWORD} characters.`;
  if (email && password.toLowerCase() === email.trim().toLowerCase()) {
    return 'The password must not be your email address.';
  }
  return null;
}

export function validateLogin(input: { email: string; password: string }): FieldErrors<'email' | 'password'> {
  const errors: FieldErrors<'email' | 'password'> = {};
  const e = validateEmail(input.email);
  if (e) errors.email = e;
  if (!input.password) errors.password = 'Enter your password.';
  else if (input.password.length > MAX_PASSWORD) errors.password = 'Password is too long.';
  return errors;
}

export function validatePasswordSetup(input: {
  password: string;
  confirm: string;
}): FieldErrors<'password' | 'confirm'> {
  const errors: FieldErrors<'password' | 'confirm'> = {};
  const p = validateNewPassword(input.password);
  if (p) errors.password = p;
  if (input.confirm !== input.password) errors.confirm = 'The passwords do not match.';
  return errors;
}

export function validateName(name: string): string | null {
  if (name.length > MAX_NAME) return `Use at most ${MAX_NAME} characters.`;
  return null;
}

export const hasErrors = (errors: object): boolean => Object.keys(errors).length > 0;
