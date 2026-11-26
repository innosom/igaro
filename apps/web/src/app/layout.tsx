import type { Metadata, Viewport } from 'next';
import { connection } from 'next/server';
import './globals.css';

export const metadata: Metadata = {
  title: { default: 'iGARO', template: '%s | iGARO' },
  robots: { index: false, follow: false },
  referrer: 'no-referrer',
};

export const viewport: Viewport = { width: 'device-width', initialScale: 1 };

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // Render per request so Next can apply the nonce from the CSP set in src/proxy.ts.
  await connection();
  return (
    <html lang="en">
      <body className="min-h-screen antialiased">{children}</body>
    </html>
  );
}
