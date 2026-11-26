'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useState, type ReactNode } from 'react';
import { api, type AuthMe } from '@/lib/api';
import { Alert } from './ui';

const NAV = [
  { href: '/dashboard', label: 'Overview' },
  { href: '/dashboard/credentials', label: 'Credentials' },
  { href: '/dashboard/credentials/new', label: 'Issue' },
  { href: '/dashboard/holders', label: 'Holders' },
  { href: '/dashboard/types', label: 'Credential types' },
  { href: '/dashboard/branding', label: 'Branding' },
  { href: '/dashboard/keys', label: 'Signing keys' },
  { href: '/dashboard/audit', label: 'Audit log' },
];

/** Session gate + navigation. /auth/me refreshes the in-memory CSRF token after a full page load. */
export function DashboardShell({ children }: { children: ReactNode }) {
  const router = useRouter();
  const path = usePathname();
  const [me, setMe] = useState<AuthMe | null>(null);

  useEffect(() => {
    api
      .me()
      .then(setMe)
      .catch(() => router.replace('/login'));
  }, [router]);

  async function signOut() {
    await api.logout().catch(() => undefined);
    router.replace('/login');
  }

  if (!me) return <p className="p-6 text-sm">Loading...</p>;

  if (me.user.role !== 'INSTITUTION_ADMIN') {
    return (
      <main className="mx-auto max-w-xl p-6">
        <Alert kind="info">This area is for institution admins. Platform admin screens are not available yet.</Alert>
        <button type="button" onClick={signOut} className="rounded-md border border-slate-600 px-4 py-2 text-sm font-semibold">
          Sign out
        </button>
      </main>
    );
  }

  return (
    <div className="mx-auto max-w-6xl px-4 py-4 md:flex md:gap-6">
      <header className="mb-4 md:w-52 md:shrink-0">
        <p className="text-sm font-semibold tracking-widest text-slate-700">iGARO</p>
        <p className="mb-1 text-base font-bold text-slate-900">{me.institution?.name}</p>
        <p className="mb-3 break-all text-xs text-slate-700">{me.user.email}</p>
        <nav aria-label="Dashboard" className="flex flex-wrap gap-2 md:flex-col md:gap-1">
          {NAV.map((n) => {
            const current =
              n.href === '/dashboard' ? path === n.href : path === n.href || (path.startsWith(`${n.href}/`) && n.href !== '/dashboard/credentials');
            return (
              <Link
                key={n.href}
                href={n.href}
                aria-current={current ? 'page' : undefined}
                className={`rounded-md px-3 py-2 text-sm font-medium ${
                  current ? 'bg-blue-800 text-white' : 'text-blue-900 underline underline-offset-2'
                }`}
              >
                {n.label}
              </Link>
            );
          })}
        </nav>
        <button type="button" onClick={signOut} className="mt-3 rounded-md border border-slate-600 px-3 py-2 text-sm font-semibold">
          Sign out
        </button>
      </header>
      <main className="min-w-0 flex-1">
        {me.institution?.status === 'SUSPENDED' && (
          <Alert kind="error">This institution is suspended. Issuing is disabled.</Alert>
        )}
        {children}
      </main>
    </div>
  );
}
