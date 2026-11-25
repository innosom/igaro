import { Writable } from 'node:stream';
import { afterEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from './app.js';
import { hashIp, sanitizeUrl } from './logging.js';

function capture(): { stream: Writable; text: () => string } {
  const chunks: string[] = [];
  const stream = new Writable({
    write(chunk: Buffer, _enc, cb) {
      chunks.push(chunk.toString());
      cb();
    },
  });
  return { stream, text: () => chunks.join('') };
}

describe('app scaffold', () => {
  let app: FastifyInstance | undefined;
  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  it('serves GET /api/v1/health', async () => {
    app = await buildApp({ config: { logLevel: 'silent' } });
    const res = await app.inject({ method: 'GET', url: '/api/v1/health' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: 'ok' });
  });

  it('returns the standard 404 shape for unknown routes', async () => {
    app = await buildApp({ config: { logLevel: 'silent' } });
    for (const url of ['/nope', '/api/v1/nope']) {
      const res = await app.inject({ method: 'GET', url });
      expect(res.statusCode).toBe(404);
      expect(res.json()).toEqual({ error: { code: 'NOT_FOUND', message: 'Not found' } });
    }
  });

  it('hides internals on unexpected errors', async () => {
    app = await buildApp({ config: { logLevel: 'silent' } });
    app.get('/boom', async () => {
      throw new Error('connection to db at 10.0.0.5 failed, password=hunter2');
    });
    const res = await app.inject({ method: 'GET', url: '/boom' });
    expect(res.statusCode).toBe(500);
    expect(res.json()).toEqual({
      error: { code: 'INTERNAL', message: 'Internal server error' },
    });
    expect(res.body).not.toContain('hunter2');
  });

  it('does not log raw error messages or stacks on the 500 path', async () => {
    const cap = capture();
    app = await buildApp({ config: { logLevel: 'trace' }, logStream: cap.stream });
    app.get('/boom', async () => {
      throw new Error('could not connect postgresql://u:SECRET-pw@10.0.0.5/db');
    });
    const res = await app.inject({ method: 'GET', url: '/boom' });
    expect(res.statusCode).toBe(500);
    const out = cap.text();
    expect(out).toContain('unhandled error');
    expect(out).not.toMatch(/SECRET|10\.0\.0\.5|postgresql:/);
    expect(out).not.toContain('"stack"');
  });

  it('maps malformed JSON to a fixed 400 without echoing the body', async () => {
    app = await buildApp({ config: { logLevel: 'silent' } });
    app.post('/echo', async () => ({}));
    const res = await app.inject({
      method: 'POST',
      url: '/echo',
      headers: { 'content-type': 'application/json' },
      payload: '{"password":"hunter2"',
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('BAD_REQUEST');
    expect(res.body).not.toContain('hunter2');
  });

  it('never logs secrets, headers or request bodies', async () => {
    const cap = capture();
    app = await buildApp({ config: { logLevel: 'trace' }, logStream: cap.stream });
    app.post('/login', async (req) => {
      // A careless handler logging objects must still be redacted.
      req.log.info(
        {
          password: 'pw-SECRET-1',
          salt: 'salt-SECRET-2',
          privateKey: 'pk-SECRET-3',
          nested: { token: 'tok-SECRET-4' },
          headers: { authorization: 'Bearer auth-SECRET-5', cookie: 'sid=cookie-SECRET-6' },
        },
        'handler log',
      );
      return {};
    });
    app.get('/verify/:t', async () => ({}));
    await app.inject({
      method: 'POST',
      url: '/login?token=query-SECRET-7',
      headers: {
        authorization: 'Bearer auth-SECRET-5',
        cookie: 'sid=cookie-SECRET-6',
        'x-csrf-token': 'csrf-SECRET-8',
      },
      payload: { password: 'body-SECRET-9', salt: 'body-SECRET-10' },
    });
    await app.inject({ method: 'GET', url: '/verify/verif-SECRET-11' });
    await app.inject({ method: 'GET', url: '/boom-missing' });
    const out = cap.text();
    expect(out).toContain('handler log');
    expect(out).toContain('[REDACTED]');
    expect(out).not.toMatch(/SECRET/);
  });

  it('masks token path segments in logged URLs', () => {
    expect(sanitizeUrl('/api/v1/verify/abc123?x=1')).toBe('/api/v1/verify/:token');
    expect(sanitizeUrl('/api/v1/holder/abc')).toBe('/api/v1/holder/:token');
    expect(sanitizeUrl('/API/V1/Verify/AbC')).toBe('/api/v1/verify/:token');
  });
  it('logs a keyed hash of the client IP, never the raw IP (ADR 0003)', async () => {
    const cap = capture();
    const ipHashKey = Buffer.alloc(32, 3);
    app = await buildApp({ config: { logLevel: 'info', ipHashKey }, logStream: cap.stream });
    await app.inject({ method: 'GET', url: '/api/v1/health', remoteAddress: '203.0.113.77' });
    const out = cap.text();
    expect(out).not.toContain('203.0.113.77');
    expect(out).not.toContain('remoteAddress');
    expect(out).toContain(hashIp('203.0.113.77', ipHashKey));
  });

  it('uses X-Forwarded-For only when TRUST_PROXY allows it', async () => {
    const seen: string[] = [];
    for (const trustProxy of [false, 1] as const) {
      app = await buildApp({ config: { logLevel: 'silent', trustProxy } });
      app.get('/ip', async (req) => ({ ip: req.ip }));
      const res = await app.inject({
        method: 'GET',
        url: '/ip',
        remoteAddress: '10.0.0.2',
        headers: { 'x-forwarded-for': '198.51.100.9' },
      });
      seen.push(res.json().ip);
      await app.close();
      app = undefined;
    }
    expect(seen).toEqual(['10.0.0.2', '198.51.100.9']);
  });
});
