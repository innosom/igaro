import { describe, expect, it } from 'vitest';
import { canonicalize } from './canonicalize.js';

describe('canonicalize (RFC 8785)', () => {
  it('sorts keys by UTF-16 code units and strips whitespace', () => {
    expect(canonicalize({ b: 1, a: [true, null, 'x'], 'é': 2, z: { y: 1, x: 2 } })).toBe(
      '{"a":[true,null,"x"],"b":1,"z":{"x":2,"y":1},"é":2}',
    );
  });
  it('orders astral keys before U+FFFF by code unit', () => {
    expect(canonicalize({ '￿': 1, '\u{1F600}': 2 })).toBe('{"\u{1F600}":2,"￿":1}');
  });
  it('serializes numbers per ECMAScript', () => {
    expect(canonicalize([1e21, 0.000001, 1e-7, -0, 4.5, 100])).toBe('[1e+21,0.000001,1e-7,0,4.5,100]');
  });
  it('escapes strings per JSON', () => {
    expect(canonicalize('a"b\\c\n\u0001')).toBe('"a\\"b\\\\c\\n\\u0001"');
  });
  it('rejects values that cannot be canonicalized', () => {
    expect(() => canonicalize(undefined)).toThrow();
    expect(() => canonicalize({ a: undefined })).toThrow();
    expect(() => canonicalize(NaN)).toThrow();
    expect(() => canonicalize(new Date())).toThrow();
    expect(() => canonicalize(1n)).toThrow();
    expect(() => canonicalize('\ud800')).toThrow();
    expect(() => canonicalize({ '\udc00': 1 })).toThrow();
    // eslint-disable-next-line no-sparse-arrays
    expect(() => canonicalize([1, , 2])).toThrow();
  });
});
