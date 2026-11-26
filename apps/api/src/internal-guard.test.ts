// T-047 (ADR 0035): the internal import routes are reachable only from allowlisted peers. Test values only.
import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';
import { registerInternalImport } from './import-internal.js';

const TOKEN = 'a-test-only-internal-token-0123456789abcdef';
const ID = '11111111-1111-4111-8111-111111111111';

async function make(allowedCidrs?: string[]) {
  const app = Fastify();
  app.setErrorHandler((e: Error & { statusCode?: number }, _r, reply) => {
    void reply.status(e.statusCode ?? 500).send({ code: e.name });
  });
  registerInternalImport(app, {
    db: {} as never,
    token: TOKEN,
    allowedCidrs,
    storage: undefined,
    masterKey: undefined,
    maxPhotoBytes: 1000,
    log: app.log,
  });
  await app.ready();
  return app;
}
type App = Awaited<ReturnType<typeof make>>;
const call = (app: App, remoteAddress: string, headers: Record<string, string> = {}) =>
  app.inject({
    method: 'POST',
    url: '/internal/import/batches/' + ID + '/finish',
    remoteAddress,
    headers: { authorization: 'Bearer ' + TOKEN, ...headers },
    payload: {},
  });

describe('internal routes network guard (ADR 0035)', () => {
  it('answers 404 to peers outside the allowlist, even with a valid token', async () => {
    const app = await make(['10.0.0.0/8']);
    expect((await call(app, '192.168.1.5')).statusCode).toBe(404);
    expect((await call(app, '127.0.0.1')).statusCode).toBe(404);
    expect((await call(app, '10.1.2.3')).statusCode).not.toBe(404);
    await app.close();
  });
  it('defaults to loopback only', async () => {
    const app = await make();
    expect((await call(app, '203.0.113.9')).statusCode).toBe(404);
    expect((await call(app, '127.0.0.1')).statusCode).not.toBe(404);
    await app.close();
  });
  it('refuses requests that came through a proxy (forwarding headers)', async () => {
    const app = await make(['10.0.0.0/8']);
    expect((await call(app, '10.1.2.3', { 'x-forwarded-for': '203.0.113.9' })).statusCode).toBe(404);
    await app.close();
  });
});
