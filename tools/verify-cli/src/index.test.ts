import { describe, expect, it } from 'vitest';
import { name } from './index.js';

describe('@igaro/verify-cli', () => {
  it('exports its name', () => {
    expect(name).toBe('@igaro/verify-cli');
  });
});
