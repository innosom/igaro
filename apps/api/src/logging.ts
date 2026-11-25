// Log redaction (invariant 9). Request bodies are never logged: the request serializer emits only
// method, a sanitised path and a keyed hash of the client IP (never the raw IP, ADR 0003). Header values are never logged at all; the
// redact paths below are a second line of defence if a handler logs an object by mistake.
// TODO: switch to the packages/core redact serializer once it exists (core is still a stub).
import { createHmac } from 'node:crypto';
import type { LoggerOptions } from 'pino';

/**
 * Keyed hash of a client IP (HMAC-SHA256, first 128 bits, hex). Used for every log line (ADR 0003);
 * verification logs (T-032) must use the same function and key so the two can be correlated.
 */
export function hashIp(ip: string | undefined, key: Buffer): string | undefined {
  if (!ip) return undefined;
  return createHmac('sha256', key).update(ip).digest('hex').slice(0, 32);
}

const SENSITIVE_KEYS = [
  'authorization',
  'cookie',
  'set-cookie',
  'x-csrf-token',
  'x-csrf',
  'x-xsrf-token',
  'password',
  'newPassword',
  'currentPassword',
  'token',
  'sessionToken',
  'verificationToken',
  'holderToken',
  'inviteToken',
  'resetToken',
  'csrfToken',
  'salt',
  'privateKey',
  'encryptedPrivateKey',
  'masterKey',
  'secret',
  'apiKey',
];

const accessor = (k: string): string => (/^[a-z_$][\w$]*$/i.test(k) ? `.${k}` : `["${k}"]`);

export const REDACT_PATHS: string[] = [
  ...SENSITIVE_KEYS.flatMap((k) => {
    const a = accessor(k);
    const top = a.startsWith('.') ? k : a;
    return [top, `*${a}`, `*.*${a}`, `req.headers${a}`, `res.headers${a}`, `headers${a}`];
  }),
  'req.body',
  'body',
  '*.body',
];

/** Strip query strings and mask token-bearing path segments (/verify/:token, /holder/:token, ...). */
export function sanitizeUrl(url: string | undefined): string {
  if (!url) return '';
  const path = (url.split('?')[0] ?? '').toLowerCase();
  return path
    .replace(/(\/(?:verify|holder)\/)[^/]+/g, '$1:token')
    .replace(/(\/auth\/(?:invites|password-reset)\/)[^/]+/g, '$1:token');
}

export function loggerOptions(level: string, ipHashKey: Buffer): LoggerOptions {
  return {
    level,
    redact: { paths: REDACT_PATHS, censor: '[REDACTED]' },
    serializers: {
      req(req: { method?: string; url?: string; id?: string; ip?: string }) {
        return {
          method: req.method,
          url: sanitizeUrl(req.url),
          id: req.id,
          ipHash: hashIp(req.ip, ipHashKey),
        };
      },
      res(res: { statusCode?: number }) {
        return { statusCode: res.statusCode };
      },
      err(err: Error & { code?: string }) {
        // Never emit message or stack: driver/library messages can embed secrets (connection
        // strings, bound values). Type, name and code are enough to triage.
        return { type: err.constructor?.name ?? 'Error', name: err.name, code: err.code };
      },
    },
  };
}
