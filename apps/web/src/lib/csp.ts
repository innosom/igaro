/** Builds the strict per-request Content-Security-Policy (nonce based, no unsafe-inline scripts). */
export function buildCsp(nonce: string, dev = false): string {
  const directives = [
    `default-src 'self'`,
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${dev ? " 'unsafe-eval'" : ''}`,
    `style-src 'self' 'nonce-${nonce}'`,
    `img-src 'self' data: blob:`,
    `font-src 'self'`,
    `connect-src 'self'`,
    `object-src 'none'`,
    `base-uri 'none'`,
    `form-action 'self'`,
    `frame-ancestors 'none'`,
  ];
  if (!dev) directives.push('upgrade-insecure-requests');
  return directives.join('; ');
}
