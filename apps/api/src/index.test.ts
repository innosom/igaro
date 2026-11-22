import { describe, expect, it } from 'vitest';
import { name } from './index.js';

describe('@igaro/api', () => {
  it('exports its name', () => {
    expect(name).toBe('@igaro/api');
  });
});
