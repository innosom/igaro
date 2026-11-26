import { describe, expect, it } from 'vitest';
import {
  hasErrors,
  validateEmail,
  validateLogin,
  validateName,
  validateNewPassword,
  validatePasswordSetup,
} from './validation';

describe('validation', () => {
  it('validates email', () => {
    expect(validateEmail('')).not.toBeNull();
    expect(validateEmail('nope')).not.toBeNull();
    expect(validateEmail('a b@c.de')).not.toBeNull();
    expect(validateEmail('a@' + 'x'.repeat(260) + '.com')).not.toBeNull();
    expect(validateEmail(' user@example.com ')).toBeNull();
  });

  it('enforces the API password length bounds', () => {
    expect(validateNewPassword('x'.repeat(11))).not.toBeNull();
    expect(validateNewPassword('x'.repeat(12))).toBeNull();
    expect(validateNewPassword('x'.repeat(256))).toBeNull();
    expect(validateNewPassword('x'.repeat(257))).not.toBeNull();
    expect(validateNewPassword('User@Example.com', 'user@example.com')).not.toBeNull();
  });

  it('validates login fields', () => {
    expect(hasErrors(validateLogin({ email: 'a@b.co', password: 'x' }))).toBe(false);
    expect(validateLogin({ email: '', password: '' })).toHaveProperty('email');
    expect(validateLogin({ email: '', password: '' })).toHaveProperty('password');
  });

  it('requires matching passwords on setup', () => {
    expect(hasErrors(validatePasswordSetup({ password: 'twelve chars!', confirm: 'twelve chars!' }))).toBe(false);
    expect(validatePasswordSetup({ password: 'twelve chars!', confirm: 'other' })).toHaveProperty('confirm');
    expect(validatePasswordSetup({ password: 'short', confirm: 'short' })).toHaveProperty('password');
  });

  it('bounds the name', () => {
    expect(validateName('x'.repeat(200))).toBeNull();
    expect(validateName('x'.repeat(201))).not.toBeNull();
  });
});
