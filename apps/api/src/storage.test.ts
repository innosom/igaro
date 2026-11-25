import { createServer, type IncomingHttpHeaders } from 'node:http';
import type { AddressInfo } from 'node:net';
import { describe, expect, it } from 'vitest';
import { MemoryObjectStorage, S3ObjectStorage, StorageError } from './storage.js';
import { extensionOf, sniffImage, stripMetadata } from './image.js';

describe('S3ObjectStorage', () => {
  it('matches the AWS documented presigned GET example (SigV4 test vector)', async () => {
    const s = new S3ObjectStorage(
      {
        endpoint: 'https://s3.amazonaws.com',
        region: 'us-east-1',
        bucket: 'examplebucket',
        accessKey: 'AKIAIOSFODNN7EXAMPLE',
        secretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        forcePathStyle: false,
      },
      () => new Date('2013-05-24T00:00:00Z'),
    );
    const url = await s.signedGetUrl('test.txt', 86400);
    expect(url).toContain('https://examplebucket.s3.amazonaws.com/test.txt?');
    expect(url).toContain('X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404');
  });

  it('signs PUT and DELETE requests, path-style, without leaking the secret', async () => {
    const seen: { method?: string; url?: string; headers: IncomingHttpHeaders; body: Buffer }[] = [];
    const srv = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        seen.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks) });
        res.statusCode = req.url?.includes('fail') ? 403 : 200;
        res.end('<Error>secret-detail</Error>');
      });
    });
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
    try {
      const port = (srv.address() as AddressInfo).port;
      const s = new S3ObjectStorage({
        endpoint: `http://127.0.0.1:${port}`,
        region: 'us-east-1',
        bucket: 'igaro',
        accessKey: 'AK',
        secretKey: 'SUPERSECRET',
        forcePathStyle: true,
      });
      await s.put('institutions/a b/logo/x.png', Buffer.from('png-bytes'), 'image/png');
      await s.delete('institutions/a b/logo/x.png');
      expect(seen[0]!.method).toBe('PUT');
      expect(seen[0]!.url).toBe('/igaro/institutions/a%20b/logo/x.png');
      expect(seen[0]!.body.toString()).toBe('png-bytes');
      expect(seen[0]!.headers.authorization).toMatch(
        /^AWS4-HMAC-SHA256 Credential=AK\/\d{8}\/us-east-1\/s3\/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature=[0-9a-f]{64}$/,
      );
      expect(seen[1]!.method).toBe('DELETE');
      await expect(s.put('fail', Buffer.from('x'), 'image/png')).rejects.toSatisfy(
        (e: unknown) => e instanceof StorageError && !String((e as Error).message).includes('secret'),
      );
    } finally {
      await new Promise((r) => srv.close(r));
    }
  });
});

describe('MemoryObjectStorage', () => {
  it('stores, deletes and returns a signed url', async () => {
    const m = new MemoryObjectStorage();
    await m.put('k', Buffer.from('a'), 'image/png');
    expect(m.objects.has('k')).toBe(true);
    expect(await m.signedGetUrl('k', 60)).toContain('expires=60');
    await m.delete('k');
    expect(m.objects.size).toBe(0);
  });
});

const png = (...extra: [string, Buffer][]): Buffer => {
  const chunk = (type: string, data: Buffer) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    return Buffer.concat([len, Buffer.from(type, 'latin1'), data, Buffer.alloc(4)]);
  };
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', Buffer.alloc(13)),
    ...extra.map(([t, d]) => chunk(t, d)),
    chunk('IDAT', Buffer.from('pixels')),
    chunk('IEND', Buffer.alloc(0)),
  ]);
};

describe('image sniffing and metadata stripping', () => {
  it('detects type from magic bytes only', () => {
    expect(sniffImage(png())).toBe('image/png');
    expect(sniffImage(Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0, 0]))).toBe('image/jpeg');
    expect(sniffImage(Buffer.from('GIF89a......'))).toBeNull();
    expect(sniffImage(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"/>'))).toBeNull();
    expect(extensionOf('image/jpeg')).toBe('jpg');
  });

  it('drops PNG metadata chunks and keeps pixels', () => {
    const src = png(['eXIf', Buffer.from('GPS')], ['tEXt', Buffer.from('Author\0me')]);
    const out = stripMetadata(src, 'image/png')!;
    expect(out.includes('eXIf')).toBe(false);
    expect(out.includes('tEXt')).toBe(false);
    expect(out.includes('pixels')).toBe(true);
    expect(stripMetadata(png(), 'image/png')!.equals(png())).toBe(true);
  });

  it('rejects truncated or trailing-garbage PNG and chunk-less data', () => {
    expect(stripMetadata(png().subarray(0, 30), 'image/png')).toBeNull();
    expect(stripMetadata(Buffer.concat([png(), Buffer.from('zz')]), 'image/png')).toBeNull();
  });

  it('drops JPEG APP1/COM segments, keeps JFIF and scan data', () => {
    const seg = (m: number, d: Buffer) => {
      const h = Buffer.from([0xff, m, 0, 0]);
      h.writeUInt16BE(d.length + 2, 2);
      return Buffer.concat([h, d]);
    };
    const src = Buffer.concat([
      Buffer.from([0xff, 0xd8]),
      seg(0xe0, Buffer.from('JFIF\0')),
      seg(0xe1, Buffer.from('Exif\0\0GPS-DATA')),
      seg(0xfe, Buffer.from('comment')),
      seg(0xda, Buffer.from([1, 1, 0])),
      Buffer.from('scan-data'),
      Buffer.from([0xff, 0xd9]),
    ]);
    const out = stripMetadata(src, 'image/jpeg')!;
    expect(out.includes('GPS-DATA')).toBe(false);
    expect(out.includes('comment')).toBe(false);
    expect(out.includes('JFIF')).toBe(true);
    expect(out.includes('scan-data')).toBe(true);
    expect(stripMetadata(Buffer.from([0xff, 0xd8, 0xff, 0xe1, 0xff, 0xff]), 'image/jpeg')).toBeNull();
  });
});
