// Worker logger. Job payloads hold raw tokens and recipient addresses, so we log by allow-list: call
// sites pass only ids, counts and codes. The redact list and err serializer are a second line of defence.
import pino, { type DestinationStream, type Logger } from 'pino';

const SENSITIVE = [
  'token',
  'to',
  'data',
  'payload',
  'link',
  'sealed',
  'holderToken',
  'text',
  'html',
  'password',
  'salt',
  'privateKey',
  'masterKey',
  'secret',
  'connectionString',
  'databaseUrl',
];

export const REDACT_PATHS = SENSITIVE.flatMap((k) => [k, `*.${k}`, `*.*.${k}`]);

export function createLogger(level: string, stream?: DestinationStream): Logger {
  return pino(
    {
      level,
      redact: { paths: REDACT_PATHS, censor: '[REDACTED]' },
      serializers: {
        // Never emit message or stack: library messages can embed addresses, URLs or tokens.
        err(err: Error & { code?: string }) {
          return { type: err.constructor?.name ?? 'Error', name: err.name, code: err.code };
        },
      },
    },
    stream,
  );
}
