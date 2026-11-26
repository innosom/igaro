/**
 * Reads a one-time token from the URL fragment (`#token=...`, the format the worker's account
 * mail uses: apps/worker/src/account-mail.ts, ADR 0006 section 9) and clears the fragment with
 * history.replaceState so it does not stay in the address bar or history. A `?token=` query
 * string is deliberately ignored: query strings reach servers and logs. The caller keeps the value
 * in memory only. Never log or persist it.
 */
export function takeTokenFromUrl(
  loc: { pathname: string; search: string; hash: string },
  history: { replaceState: (data: unknown, unused: string, url: string) => void },
  param = 'token',
): string | null {
  if (!loc.hash) return null;
  const params = new URLSearchParams(loc.hash.replace(/^#/, ''));
  const token = params.get(param);
  if (token === null) return null;
  history.replaceState(null, '', loc.pathname + loc.search);
  return token.trim() || null;
}
