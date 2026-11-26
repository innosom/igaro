'use client';

import { useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import { api, type AuthMe } from '@/lib/api';
import { AuthShell } from '@/components/ui';

// Placeholder landing page after sign-in; the real dashboard arrives in later tasks.
export function DashboardStub() {
  const router = useRouter();
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

  return (
    <AuthShell title="Dashboard">
      {me ? (
        <>
          <p className="mb-4 text-sm">
            Signed in as <strong>{me.user.email}</strong>
            {me.institution ? ` (${me.institution.name})` : ' (platform admin)'}.
          </p>
          <button
            type="button"
            onClick={signOut}
            className="rounded-md border border-slate-600 px-4 py-2 text-sm font-semibold"
          >
            Sign out
          </button>
        </>
      ) : (
        <p className="text-sm">Loading...</p>
      )}
    </AuthShell>
  );
}
