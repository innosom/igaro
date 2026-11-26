import { describe, expect, it, vi } from 'vitest';
import { ApiError, createApiClient, describeError } from './api';

const me = {
  user: { id: 'u', email: 'a@b.co', name: 'A', role: 'INSTITUTION_ADMIN' as const },
  institution: null,
  csrfToken: 'csrf-1',
};

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

function setup(...responses: Response[]) {
  const fetchMock = vi.fn();
  for (const r of responses) fetchMock.mockResolvedValueOnce(r);
  return { fetchMock, client: createApiClient({ fetch: fetchMock as unknown as typeof fetch }) };
}

describe('api client', () => {
  it('logs in with JSON, keeps the CSRF token in memory and does not expose it in the result', async () => {
    const { fetchMock, client } = setup(json(200, me));
    const result = await client.login('a@b.co', 'pw');
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe('/api/v1/auth/login');
    expect(init.method).toBe('POST');
    expect(init.headers['Content-Type']).toBe('application/json');
    expect(init.credentials).toBe('same-origin');
    expect(JSON.parse(init.body)).toEqual({ email: 'a@b.co', password: 'pw' });
    expect(init.headers['X-CSRF-Token']).toBeUndefined();
    expect(client.csrfToken).toBe('csrf-1');
    expect(result).not.toHaveProperty('csrfToken');
  });

  it('sends X-CSRF-Token on mutating requests after login, never on GET', async () => {
    const { fetchMock, client } = setup(
      json(200, me),
      new Response(null, { status: 204 }),
      json(200, { ...me, csrfToken: 'csrf-2' }),
    );
    await client.login('a@b.co', 'pw');
    await client.logout();
    expect(fetchMock.mock.calls[1]![1].headers['X-CSRF-Token']).toBe('csrf-1');
    expect(client.csrfToken).toBeNull();
    await client.me();
    expect(fetchMock.mock.calls[2]![1].headers['X-CSRF-Token']).toBeUndefined();
    expect(client.csrfToken).toBe('csrf-2');
  });

  it('clears the CSRF token even when logout fails', async () => {
    const { client } = setup(json(200, me), json(403, { error: { code: 'CSRF_REQUIRED', message: 'x' } }));
    await client.login('a@b.co', 'pw');
    await expect(client.logout()).rejects.toBeInstanceOf(ApiError);
    expect(client.csrfToken).toBeNull();
  });

  it('never writes to web storage', async () => {
    const setItem = vi.fn();
    vi.stubGlobal('localStorage', { setItem });
    vi.stubGlobal('sessionStorage', { setItem });
    const { client } = setup(json(200, me));
    await client.login('a@b.co', 'pw');
    expect(setItem).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });

  it('maps the {error:{code,message}} shape to ApiError', async () => {
    const { client } = setup(json(401, { error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password' } }));
    const err = await client.login('a@b.co', 'bad').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ status: 401, code: 'INVALID_CREDENTIALS', message: 'Invalid email or password' });
    expect(client.csrfToken).toBeNull();
  });

  it('falls back to a generic message for non-JSON errors and network failures', async () => {
    const { client } = setup(new Response('<html>bad gateway</html>', { status: 502 }));
    const err = await client.me().catch((e: unknown) => e);
    expect(err).toMatchObject({ status: 502, code: 'UNKNOWN' });
    expect(describeError(err)).toBe('Something went wrong. Please try again.');

    const failing = createApiClient({ fetch: (() => Promise.reject(new Error('down'))) as unknown as typeof fetch });
    const net = await failing.me().catch((e: unknown) => e);
    expect(net).toMatchObject({ status: 0, code: 'NETWORK_ERROR' });
  });

  it('posts invite acceptance and both password-reset modes as JSON', async () => {
    const { fetchMock, client } = setup(
      new Response(null, { status: 204 }),
      json(202, { status: 'accepted' }),
      new Response(null, { status: 204 }),
    );
    await client.acceptInvite('tok', 'a-long-password', 'Ann');
    await client.requestPasswordReset('a@b.co');
    await client.confirmPasswordReset('tok2', 'a-long-password');
    const bodies = fetchMock.mock.calls.map((c) => JSON.parse(c[1].body));
    expect(bodies[0]).toEqual({ token: 'tok', password: 'a-long-password', name: 'Ann' });
    expect(bodies[1]).toEqual({ email: 'a@b.co' });
    expect(bodies[2]).toEqual({ token: 'tok2', password: 'a-long-password' });
    expect(fetchMock.mock.calls.map((c) => c[0])).toEqual([
      '/api/v1/auth/invites/accept',
      '/api/v1/auth/password-reset',
      '/api/v1/auth/password-reset',
    ]);
  });

  it('describes errors without leaking server detail on 5xx', () => {
    expect(describeError(new ApiError(429, 'RATE_LIMITED', 'Too many requests'))).toMatch(/wait/);
    expect(describeError(new ApiError(400, 'WEAK_PASSWORD', 'Password must be between 12 and 256 characters'))).toBe(
      'Password must be between 12 and 256 characters',
    );
    expect(describeError(new ApiError(500, 'INTERNAL', 'stack trace here'))).not.toMatch(/stack/);
    expect(describeError(new Error('x'))).toBe('Something went wrong. Please try again.');
  });
});
