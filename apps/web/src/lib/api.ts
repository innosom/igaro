// Same-origin client for /api/v1. JSON only. The CSRF token (from the login or /auth/me response)
// is held in this object's memory: never localStorage, sessionStorage, cookies or the URL.

export interface AuthMe {
  user: { id: string; email: string; name: string; role: 'PLATFORM_ADMIN' | 'INSTITUTION_ADMIN' };
  institution: { id: string; name: string; slug: string; status: string } | null;
}
export type AuthMeWithCsrf = AuthMe & { csrfToken: string };

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    /** Parsed JSON error body (e.g. the `preview` of a 422 import). Never logged. */
    readonly body?: unknown,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export interface ApiClientOptions {
  fetch?: typeof fetch;
  baseUrl?: string;
  /** Refuse to run without a window, so one user's CSRF token can never sit in server memory shared across requests. */
  browserOnly?: boolean;
}

const GENERIC = 'Something went wrong. Please try again.';
const NETWORK = 'Could not reach the server. Check your connection and try again.';

export function createApiClient(opts: ApiClientOptions = {}) {
  const base = (opts.baseUrl ?? '/api/v1').replace(/\/+$/, '');
  let csrfToken: string | null = null;

  async function request<T>(method: string, path: string, body?: unknown): Promise<T | undefined> {
    if (opts.browserOnly && typeof window === 'undefined') {
      throw new Error('The session API client must only be used in the browser');
    }
    const doFetch =opts.fetch ?? globalThis.fetch.bind(globalThis);
    const headers: Record<string, string> = { Accept: 'application/json' };
    const isForm = typeof FormData !== 'undefined' && body instanceof FormData;
    if (body !== undefined && !isForm) headers['Content-Type'] = 'application/json';
    if (method !== 'GET' && method !== 'HEAD' && csrfToken) headers['X-CSRF-Token'] = csrfToken;

    let res: Response;
    try {
      res = await doFetch(`${base}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : isForm ? (body as FormData) : JSON.stringify(body),
        credentials: 'same-origin',
        cache: 'no-store',
        referrerPolicy: 'no-referrer',
      });
    } catch {
      throw new ApiError(0, 'NETWORK_ERROR', NETWORK);
    }

    if (res.status === 204) return undefined;
    let data: unknown;
    try {
      data = await res.json();
    } catch {
      data = undefined;
    }
    if (!res.ok) throw toApiError(res.status, data);
    return data as T;
  }

  return {
    get csrfToken(): string | null {
      return csrfToken;
    },
    async login(email: string, password: string): Promise<AuthMe> {
      const me = (await request<AuthMeWithCsrf>('POST', '/auth/login', { email, password }))!;
      csrfToken = me.csrfToken;
      return stripCsrf(me);
    },
    async me(): Promise<AuthMe> {
      const me = (await request<AuthMeWithCsrf>('GET', '/auth/me'))!;
      csrfToken = me.csrfToken;
      return stripCsrf(me);
    },
    async logout(): Promise<void> {
      try {
        await request('POST', '/auth/logout', {});
      } finally {
        csrfToken = null;
      }
    },
    /** Generic same-origin calls for the dashboard. Paths are relative to /api/v1. */
    get: <T>(path: string) => request<T>('GET', path) as Promise<T>,
    post: <T>(path: string, body: unknown = {}) => request<T>('POST', path, body) as Promise<T>,
    patch: <T>(path: string, body: unknown) => request<T>('PATCH', path, body) as Promise<T>,
    del: (path: string) => request<undefined>('DELETE', path).then(() => undefined),
    /** Multipart upload; the browser sets the boundary, so no Content-Type is sent. */
    upload: <T>(path: string, form: FormData) => request<T>('POST', path, form) as Promise<T>,
    async acceptInvite(token: string, password: string, name?: string): Promise<void> {
      await request('POST', '/auth/invites/accept', {
        token,
        password,
        ...(name ? { name } : {}),
      });
    },
    /** Resolves on 202 and throws on any failure. The UI ignores the outcome and always shows the same neutral message. */
    async requestPasswordReset(email: string): Promise<void> {
      await request('POST', '/auth/password-reset', { email });
    },
    async confirmPasswordReset(token: string, password: string): Promise<void> {
      await request('POST', '/auth/password-reset', { token, password });
      csrfToken = null;
    },
  };
}

function stripCsrf(me: AuthMeWithCsrf): AuthMe {
  return { user: me.user, institution: me.institution };
}

export function toApiError(status: number, data: unknown): ApiError {
  const e = (data as { error?: { code?: unknown; message?: unknown } } | undefined)?.error;
  const code = typeof e?.code === 'string' ? e.code : 'UNKNOWN';
  const message = typeof e?.message === 'string' && e.message ? e.message : GENERIC;
  return new ApiError(status, code, message, data);
}

/** User-facing text for an error. Uses the API message, with friendlier wording for common codes. */
export function describeError(err: unknown): string {
  if (!(err instanceof ApiError)) return GENERIC;
  switch (err.code) {
    case 'RATE_LIMITED':
      return 'Too many attempts. Please wait a few minutes and try again.';
    case 'FORBIDDEN':
      return 'Your account is not allowed to use this area.';
    case 'PAYLOAD_TOO_LARGE':
      return 'The file is too large. Reduce its size and try again.';
    case 'INVALID_TOKEN':
      return 'This link is invalid or has expired. Ask for a new one.';
    case 'NETWORK_ERROR':
      return err.message;
    default:
      return err.status >= 500 ? GENERIC : err.message;
  }
}

/** Shared singleton for the browser app; the CSRF token lives in this module's memory. */
export const api = createApiClient({ browserOnly: true });
