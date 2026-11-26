'use client';

import { useEffect, useState } from 'react';
import { takeTokenFromUrl } from '@/lib/token-url';

/**
 * Reads ?token= once after mount, strips it from the URL, and keeps it in component state only.
 * `ready` is false until the URL has been read. Safe under React strict mode's double effect.
 */
export function useUrlToken(): { token: string | null; ready: boolean } {
  const [token, setToken] = useState<string | null>(null);
  const [ready, setReady] = useState(false);
  useEffect(() => {
    const t = takeTokenFromUrl(window.location, window.history);
    if (t) setToken(t);
    setReady(true);
  }, []);
  return { token, ready };
}
