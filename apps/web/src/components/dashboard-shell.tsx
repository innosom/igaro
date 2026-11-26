'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useState, type ReactNode } from 'react';
import { api, type AuthMe } from '@/lib/api';
import { areaAllowed } from '@/lib/platform';
import { Alert, linkClass } from './ui';

const PLATFORM_NAV = [{ href: '/dashboard/platform', label: 'Institutions' }];

const NAV = [
  { href: '/dashboard', label: 'Overview' },
  { href: '/dashboard/credentials', label: 'Credentials' },
  { href: '/dashboard/credentials/new', label: 'Issue' },
  { href: '/dashboard/holders', label: 'Holders' },
  { href: '/dashboard/import', label: 'Import' },
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

  // A platform admin landing on the institution overview goes straight to their own home.
  useEffect(() => {
    if (me?.user.role === 'PLATFORM_ADMIN' && path === '/dashboard') router.replace('/dashboard/platform');
  }, [me, path, router]);

  async function signOut() {
    await api.logout().catch(() => undefined);
    router.replace('/login');
  }

  if (!me) return <p className="p-6 text-sm">Loading...</p>;

  const isPlatform = me.user.role === 'PLATFORM_ADMIN';
  const nav = isPlatform ? PLATFORM_NAV : NAV;
  const allowed = areaAllowed(me.user.role, path);

  return (
    <div className="mx-auto max-w-6xl px-4 py-4 md:flex md:gap-6">
      <header className="mb-4 md:w-52 md:shrink-0">
        <p className="text-sm font-semibold tracking-widest text-slate-700">iGARO</p>
        <p className="mb-1 text-base font-bold text-slate-900">{isPlatform ? 'Platform administration' : me.institution?.name}</p>
        <p className="mb-3 break-all text-xs text-slate-700">{me.user.email}</p>
        <nav aria-label="Dashboard" className="flex flex-wrap gap-2 md:flex-col md:gap-1">
          {nav.map((n) => {
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
        {!isPlatform && me.institution?.status === 'SUSPENDED' && (
          <Alert kind="error">This institution is suspended. Issuing is disabled.</Alert>
        )}
        {allowed ? (
          children
        ) : (
          <Alert kind="info">
            {isPlatform
              ? 'This screen is for institution admins. '
              : 'This screen is for platform admins. '}
            <Link href={isPlatform ? '/dashboard/platform' : '/dashboard'} className={linkClass}>
              {isPlatform ? 'Go to institutions' : 'Go to the overview'}
            </Link>
          </Alert>
        )}
      </main>
    </div>
  );
}
