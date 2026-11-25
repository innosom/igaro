// Private object storage (ADR 0008). Buckets are private: nothing here returns a public URL. Reads go
// through short-lived presigned URLs (used by later tasks: cards, photos, logos on the card).
//
// S3ObjectStorage speaks the S3 REST API with AWS Signature V4 using node:crypto and fetch, so no AWS SDK
// is needed for three operations. It works with MinIO (path-style) and AWS S3 (virtual-hosted style).
import { createHash, createHmac } from 'node:crypto';

export interface ObjectStorage {
  put(key: string, body: Buffer, contentType: string): Promise<void>;
  delete(key: string): Promise<void>;
  /** Short-lived GET URL for a private object. */
  signedGetUrl(key: string, expiresSeconds: number): Promise<string>;
}

export class StorageError extends Error {
  constructor(message = 'Object storage operation failed') {
    super(message);
    this.name = 'StorageError';
  }
}

/** In-memory implementation for tests. */
export class MemoryObjectStorage implements ObjectStorage {
  readonly objects = new Map<string, { body: Buffer; contentType: string }>();
  failPut = false;

  put(key: string, body: Buffer, contentType: string): Promise<void> {
    if (this.failPut) return Promise.reject(new StorageError());
    this.objects.set(key, { body: Buffer.from(body), contentType });
    return Promise.resolve();
  }
  delete(key: string): Promise<void> {
    this.objects.delete(key);
    return Promise.resolve();
  }
  signedGetUrl(key: string, expiresSeconds: number): Promise<string> {
    return Promise.resolve(`memory://${encodeURIComponent(key)}?expires=${expiresSeconds}`);
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
// RFC 3986 encoding as S3 requires (encodeURIComponent leaves !'()* alone).
const enc = (s: string): string =>
  encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
const encPath = (key: string): string => key.split('/').map(enc).join('/');

export class S3ObjectStorage implements ObjectStorage {
  private readonly base: URL;

  constructor(
    private readonly cfg: S3Config,
    private readonly now: () => Date = () => new Date(),
  ) {
    this.base = new URL(cfg.endpoint);
  }

  private target(key: string): { url: URL; host: string; path: string } {
    const path = this.cfg.forcePathStyle
      ? `/${enc(this.cfg.bucket)}/${encPath(key)}`
      : `/${encPath(key)}`;
    const u = new URL(this.base.origin);
    if (!this.cfg.forcePathStyle) u.hostname = `${this.cfg.bucket}.${this.base.hostname}`;
    const prefix = this.base.pathname.replace(/\/$/, '');
    u.pathname = prefix + path;
    return { url: u, host: u.host, path: prefix + path };
  }

  private signingKey(date: string): Buffer {
    return hmac(hmac(hmac(hmac(`AWS4${this.cfg.secretKey}`, date), this.cfg.region), 's3'), 'aws4_request');
  }

  private stamp(): { amz: string; date: string } {
    const amz = this.now().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
    return { amz, date: amz.slice(0, 8) };
  }

  private async send(
    method: 'PUT' | 'DELETE',
    key: string,
    body: Buffer | undefined,
    contentType?: string,
  ): Promise<void> {
    const { url, host, path } = this.target(key);
    const { amz, date } = this.stamp();
    const payloadHash = hex(body ?? '');
    const headers: Record<string, string> = {
      host,
      'x-amz-content-sha256': payloadHash,
      'x-amz-date': amz,
    };
    if (contentType) headers['content-type'] = contentType;
    const names = Object.keys(headers).sort();
    const canonical = [
      method,
      path,
      '',
      names.map((n) => `${n}:${headers[n]}\n`).join(''),
      names.join(';'),
      payloadHash,
    ].join('\n');
    const scope = `${date}/${this.cfg.region}/s3/aws4_request`;
    const sts = ['AWS4-HMAC-SHA256', amz, scope, hex(canonical)].join('\n');
    const sig = createHmac('sha256', this.signingKey(date)).update(sts).digest('hex');
    const sendHeaders = Object.fromEntries(Object.entries(headers).filter(([k]) => k !== 'host'));
    sendHeaders.authorization = `AWS4-HMAC-SHA256 Credential=${this.cfg.accessKey}/${scope}, SignedHeaders=${names.join(';')}, Signature=${sig}`;
    let res: Response;
    try {
      res = await fetch(url, {
        method,
        headers: sendHeaders,
        ...(body ? { body: new Uint8Array(body) } : {}),
        signal: AbortSignal.timeout(15_000),
      });
    } catch {
      throw new StorageError(); // never echo the URL, headers or underlying error
    }
    if (!res.ok) {
      await res.arrayBuffer().catch(() => undefined);
      throw new StorageError();
    }
    await res.arrayBuffer().catch(() => undefined);
  }

  put(key: string, body: Buffer, contentType: string): Promise<void> {
    return this.send('PUT', key, body, contentType);
  }

  delete(key: string): Promise<void> {
    return this.send('DELETE', key, undefined);
  }

  signedGetUrl(key: string, expiresSeconds: number): Promise<string> {
    const ttl = Math.min(Math.max(Math.trunc(expiresSeconds), 1), 604800); // S3 maximum is 7 days
    const { url, host, path } = this.target(key);
    const { amz, date } = this.stamp();
    const scope = `${date}/${this.cfg.region}/s3/aws4_request`;
    const q: [string, string][] = [
      ['X-Amz-Algorithm', 'AWS4-HMAC-SHA256'],
      ['X-Amz-Credential', `${this.cfg.accessKey}/${scope}`],
      ['X-Amz-Date', amz],
      ['X-Amz-Expires', String(ttl)],
      ['X-Amz-SignedHeaders', 'host'],
    ];
    const qs = q
      .map(([k, v]) => `${enc(k)}=${enc(v)}`)
      .sort()
      .join('&');
    const canonical = ['GET', path, qs, `host:${host}\n`, 'host', 'UNSIGNED-PAYLOAD'].join('\n');
    const sts = ['AWS4-HMAC-SHA256', amz, scope, hex(canonical)].join('\n');
    const sig = createHmac('sha256', this.signingKey(date)).update(sts).digest('hex');
    return Promise.resolve(`${url.origin}${path}?${qs}&X-Amz-Signature=${sig}`);
  }
}
