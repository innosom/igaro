// Private object storage as the worker needs it (ADR 0028): read photos and logos, write rendered cards.
// Same bucket and S3_* variables as the API (ADR 0008). Buckets are private; nothing here makes a public URL.
// S3ObjectStorage is AWS Signature V4 with node:crypto and fetch (no SDK), the same approach as the API's
// storage.ts. TODO: move both into a shared package once a third consumer appears.
import { createHash, createHmac } from 'node:crypto';

export interface WorkerObjectStorage {
  /** Returns null when the object does not exist. */
  get(key: string, maxBytes: number): Promise<Buffer | null>;
  put(key: string, body: Buffer, contentType: string): Promise<void>;
}

export class StorageError extends Error {
  constructor(message = 'Object storage operation failed') {
    super(message);
    this.name = 'StorageError';
  }
}

export class MemoryWorkerStorage implements WorkerObjectStorage {
  readonly objects = new Map<string, { body: Buffer; contentType: string }>();
  get(key: string, maxBytes: number): Promise<Buffer | null> {
    const o = this.objects.get(key);
    if (!o) return Promise.resolve(null);
    if (o.body.length > maxBytes) return Promise.reject(new StorageError('object too large'));
    return Promise.resolve(Buffer.from(o.body));
  }
  put(key: string, body: Buffer, contentType: string): Promise<void> {
    this.objects.set(key, { body: Buffer.from(body), contentType });
    return Promise.resolve();
  }
}

export interface S3Config {
  endpoint: string;
  region: string;
  bucket: string;
  accessKey: string;
  secretKey: string;
  forcePathStyle: boolean;
}

const hex = (b: Buffer | string): string => createHash('sha256').update(b).digest('hex');
const hmac = (k: Buffer | string, d: string): Buffer => createHmac('sha256', k).update(d).digest();
const enc = (s: string): string =>
  encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
const encPath = (key: string): string => key.split('/').map(enc).join('/');

export class S3WorkerStorage implements WorkerObjectStorage {
  private readonly base: URL;
  constructor(
    private readonly cfg: S3Config,
    private readonly now: () => Date = () => new Date(),
  ) {
    this.base = new URL(cfg.endpoint);
  }

  private async send(method: 'GET' | 'PUT', key: string, body?: Buffer, contentType?: string): Promise<Response> {
    const path0 = this.cfg.forcePathStyle ? `/${enc(this.cfg.bucket)}/${encPath(key)}` : `/${encPath(key)}`;
    const u = new URL(this.base.origin);
    if (!this.cfg.forcePathStyle) u.hostname = `${this.cfg.bucket}.${this.base.hostname}`;
    const path = this.base.pathname.replace(/\/$/, '') + path0;
    u.pathname = path;
    const amz = this.now().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
    const date = amz.slice(0, 8);
    const payloadHash = hex(body ?? '');
    const headers: Record<string, string> = { host: u.host, 'x-amz-content-sha256': payloadHash, 'x-amz-date': amz };
    if (contentType) headers['content-type'] = contentType;
    const names = Object.keys(headers).sort();
    const canonical = [method, path, '', names.map((n) => `${n}:${headers[n]}\n`).join(''), names.join(';'), payloadHash].join('\n');
    const scope = `${date}/${this.cfg.region}/s3/aws4_request`;
    const sts = ['AWS4-HMAC-SHA256', amz, scope, hex(canonical)].join('\n');
    const k = hmac(hmac(hmac(hmac(`AWS4${this.cfg.secretKey}`, date), this.cfg.region), 's3'), 'aws4_request');
    const sig = createHmac('sha256', k).update(sts).digest('hex');
    const sendHeaders = Object.fromEntries(Object.entries(headers).filter(([n]) => n !== 'host'));
    sendHeaders.authorization = `AWS4-HMAC-SHA256 Credential=${this.cfg.accessKey}/${scope}, SignedHeaders=${names.join(';')}, Signature=${sig}`;
    try {
      return await fetch(u, {
        method,
        headers: sendHeaders,
        ...(body ? { body: new Uint8Array(body) } : {}),
        signal: AbortSignal.timeout(20_000),
      });
    } catch {
      throw new StorageError(); // never echo the URL, headers or the underlying error
    }
  }

  async get(key: string, maxBytes: number): Promise<Buffer | null> {
    const res = await this.send('GET', key);
    if (res.status === 404) {
      await res.arrayBuffer().catch(() => undefined);
      return null;
    }
    if (!res.ok) {
      await res.arrayBuffer().catch(() => undefined);
      throw new StorageError();
    }
    const len = Number(res.headers.get('content-length') ?? '0');
    if (len > maxBytes) {
      await res.body?.cancel().catch(() => undefined);
      throw new StorageError('object too large');
    }
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length > maxBytes) throw new StorageError('object too large');
    return buf;
  }

  async put(key: string, body: Buffer, contentType: string): Promise<void> {
    const res = await this.send('PUT', key, body, contentType);
    await res.arrayBuffer().catch(() => undefined);
    if (!res.ok) throw new StorageError();
  }
}
