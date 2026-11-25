/**
 * RFC 8785 JSON Canonicalization Scheme (JCS) for the JSON subset iGARO signs:
 * null, boolean, finite numbers, strings, arrays and plain objects.
 * Anything else (undefined, functions, bigint, NaN/Infinity, class instances) is rejected
 * rather than silently dropped, so two parties can never canonicalize different data.
 */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** JSON string encoding; lone surrogates are not I-JSON (RFC 8785 requires I-JSON input) so they are refused. */
function str(v: string): string {
  if (LONE_SURROGATE.test(v)) throw new Error('canonicalize: lone surrogate');
  return JSON.stringify(v);
}

export function canonicalize(value: unknown): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) throw new Error('canonicalize: non-finite number');
      // ECMAScript Number::toString, which RFC 8785 mandates (-0 serializes as "0").
      return JSON.stringify(value);
    case 'string':
      return str(value);
    case 'object': {
      if (Array.isArray(value)) {
        if (Object.keys(value).length !== value.length) throw new Error('canonicalize: sparse array');
        return '[' + value.map((v) => canonicalize(v)).join(',') + ']';
      }
      const proto = Object.getPrototypeOf(value) as unknown;
      if (proto !== Object.prototype && proto !== null) throw new Error('canonicalize: unsupported object type');
      const obj = value as Record<string, unknown>;
      // Default sort compares UTF-16 code units, exactly as RFC 8785 section 3.2.3 requires.
      const keys = Object.keys(obj).sort();
      return '{' + keys.map((k) => str(k) + ':' + canonicalize(obj[k])).join(',') + '}';
    }
    default:
      throw new Error('canonicalize: unsupported type ' + typeof value);
  }
}
