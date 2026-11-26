// Same-origin proxy to the API (cookies stay first-party and httpOnly) plus security headers.
// The Content-Security-Policy is per-request (nonce) and set in src/proxy.ts.
import process from 'node:process';

const apiUrl = (process.env.API_URL ?? 'http://localhost:4000').replace(/\/+$/, '');

/** @type {import('next').NextConfig} */
const nextConfig = {
  poweredByHeader: false,
  reactStrictMode: true,
  async rewrites() {
    return [
      // /api/v1/internal/* (service-to-service, ADR 0035) is never proxied from the public origin.
      { source: '/api/v1/:path((?!internal(?:/|$)).*)', destination: `${apiUrl}/api/v1/:path*` },
      // Public institution keys (ADR 0023, 0026), linked from the verification page.
      { source: '/i/:slug/keys.json', destination: `${apiUrl}/i/:slug/keys.json` },
    ];
  },
  async headers() {
    return [
      { source: '/v/:path*', headers: [{ key: 'Cache-Control', value: 'no-store' }] },
      // Private holder pages (ADR 0032): the URL carries the holder token.
      { source: '/h/:path*', headers: [{ key: 'Cache-Control', value: 'no-store' }] },
      {
        source: '/:path*',
        headers: [
          { key: 'Referrer-Policy', value: 'no-referrer' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
          { key: 'X-Robots-Tag', value: 'noindex, nofollow' },
          // HSTS in production only: never pin localhost/dev to HTTPS.
          ...(process.env.NODE_ENV === 'production'
            ? [{ key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains' }]
            : []),
        ],
      },
    ];
  },
};

export default nextConfig;
