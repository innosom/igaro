import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  CalendarTimestamper,
  NoopTimestamper,
  OtsError,
  isCompleteProof,
  parseCalendarUrls,
  parseProof,
  type FetchLike,
} from './ots.js';

const CAL = 'https://cal.test';
const digest = createHash('sha256').update('head').digest();

const varuint = (n: number): Buffer => {
  const out: number[] = [];
  let v = n;
  while (v >= 0x80) {
    out.push((v & 0x7f) | 0x80);
    v = Math.floor(v / 128);
  }
  out.push(v);
  return Buffer.from(out);
};
const varbytes = (b: Buffer): Buffer => Buffer.concat([varuint(b.length), b]);
const append = (b: Buffer): Buffer => Buffer.concat([Buffer.from([0xf0]), varbytes(b)]);
const SHA256 = Buffer.from([0x08]);
const pendingAtt = (uri: string): Buffer =>
  Buffer.concat([Buffer.from([0x00]), Buffer.from('83dfe30d2ef90c8e', 'hex'), varbytes(varbytes(Buffer.from(uri)))]);
const bitcoinAtt = (height: number): Buffer =>
  Buffer.concat([Buffer.from([0x00]), Buffer.from('0588960d73d71901', 'hex'), varbytes(varuint(height))]);

// What a calendar returns for a submitted digest: ops then a pending attestation.
const receipt = Buffer.concat([append(Buffer.from('nonce')), SHA256, pendingAtt(CAL)]);
// Where the pending receipt's commitment ends up once Bitcoin confirms it.
const confirmed = Buffer.concat([append(Buffer.from('path')), SHA256, bitcoinAtt(800000)]);

function fakeFetch(handler: (url: string, init: Parameters<FetchLike>[1]) => { status: number; body?: Buffer }) {
  const calls: Array<{ url: string; method?: string; body?: Uint8Array }> = [];
  const fn: FetchLike = async (url, init) => {
    calls.push({ url, method: init?.method, body: init?.body });
    const r = handler(url, init);
    const body = r.body ?? Buffer.alloc(0);
    return {
      status: r.status,
      ok: r.status < 300,
      arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.length) as ArrayBuffer,
    };
  };
  return { fn, calls };
}

describe('NoopTimestamper', () => {
  it('is disabled and never produces a proof', async () => {
    const n = new NoopTimestamper();
    expect(n.enabled).toBe(false);
    await expect(n.submit()).rejects.toBeInstanceOf(OtsError);
    expect(await n.upgrade()).toEqual({ status: 'pending' });
  });
});

describe('CalendarTimestamper', () => {
  it('submits the digest only and builds a parseable pending proof', async () => {
    const { fn, calls } = fakeFetch(() => ({ status: 200, body: receipt }));
    const ts = new CalendarTimestamper({ calendars: [`${CAL}/`], fetch: fn });
    const proof = await ts.submit(digest);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe(`${CAL}/digest`);
    expect(calls[0]?.method).toBe('POST');
    expect(Buffer.from(calls[0]?.body ?? [])).toEqual(digest);
    const parsed = parseProof(proof);
    expect(parsed.digest).toEqual(digest);
    expect(parsed.attestations).toHaveLength(1);
    expect(isCompleteProof(proof)).toBe(false);
  });

  it('falls through to the next calendar on errors and garbage', async () => {
    const { fn, calls } = fakeFetch((url) =>
      url.startsWith('https://bad.test') ? { status: 500 } : url.startsWith('https://junk.test') ? { status: 200, body: Buffer.from('xx') } : { status: 200, body: receipt },
    );
    const ts = new CalendarTimestamper({ calendars: ['https://bad.test', 'https://junk.test', CAL], fetch: fn });
    expect(isCompleteProof(await ts.submit(digest))).toBe(false);
    expect(calls).toHaveLength(3);
  });

  it('throws when every calendar fails', async () => {
    const { fn } = fakeFetch(() => ({ status: 503 }));
    const ts = new CalendarTimestamper({ calendars: [CAL], fetch: fn });
    await expect(ts.submit(digest)).rejects.toBeInstanceOf(OtsError);
  });

  it('upgrade: stays pending on 404, completes on a Bitcoin attestation', async () => {
    const submit = fakeFetch(() => ({ status: 200, body: receipt }));
    const pending = await new CalendarTimestamper({ calendars: [CAL], fetch: submit.fn }).submit(digest);

    const notYet = fakeFetch(() => ({ status: 404 }));
    const ts1 = new CalendarTimestamper({ calendars: [CAL], fetch: notYet.fn });
    expect(await ts1.upgrade(pending)).toEqual({ status: 'pending' });
    // The commitment asked for is the message at the pending attestation: sha256(digest || "nonce").
    const commitment = createHash('sha256').update(Buffer.concat([digest, Buffer.from('nonce')])).digest('hex');
    expect(notYet.calls[0]?.url).toBe(`${CAL}/timestamp/${commitment}`);
    expect(notYet.calls[0]?.method).toBe('GET');

    const done = fakeFetch(() => ({ status: 200, body: confirmed }));
    const r = await new CalendarTimestamper({ calendars: [CAL], fetch: done.fn }).upgrade(pending);
    expect(r.status).toBe('complete');
    if (r.status === 'complete') {
      expect(isCompleteProof(r.proof)).toBe(true);
      expect(parseProof(r.proof).digest).toEqual(digest);
      // Upgrading a complete proof is a no-op that makes no request.
      const none = fakeFetch(() => ({ status: 500 }));
      expect(await new CalendarTimestamper({ calendars: [CAL], fetch: none.fn }).upgrade(r.proof)).toMatchObject({ status: 'complete' });
      expect(none.calls).toHaveLength(0);
    }
  });

  it('upgrade refuses to contact a calendar that is not configured (SSRF guard)', async () => {
    const submit = fakeFetch(() => ({ status: 200, body: receipt }));
    const pending = await new CalendarTimestamper({ calendars: [CAL], fetch: submit.fn }).submit(digest);
    const other = fakeFetch(() => ({ status: 200, body: confirmed }));
    const ts = new CalendarTimestamper({ calendars: ['https://other.test'], fetch: other.fn });
    await expect(ts.upgrade(pending)).rejects.toBeInstanceOf(OtsError);
    expect(other.calls).toHaveLength(0);
  });

  it('rejects an upgrade response without a Bitcoin attestation as still pending', async () => {
    const submit = fakeFetch(() => ({ status: 200, body: receipt }));
    const pending = await new CalendarTimestamper({ calendars: [CAL], fetch: submit.fn }).submit(digest);
    const again = fakeFetch(() => ({ status: 200, body: receipt }));
    expect(await new CalendarTimestamper({ calendars: [CAL], fetch: again.fn }).upgrade(pending)).toEqual({ status: 'pending' });
  });

  it('parseProof rejects malformed files', () => {
    expect(() => parseProof(Buffer.from('nope'))).toThrow(OtsError);
    const { fn } = fakeFetch(() => ({ status: 200, body: receipt }));
    return new CalendarTimestamper({ calendars: [CAL], fetch: fn }).submit(digest).then((p) => {
      expect(() => parseProof(p.subarray(0, p.length - 3))).toThrow(OtsError);
      expect(() => parseProof(Buffer.concat([p, Buffer.from([1])]))).toThrow(OtsError);
    });
  });
});

describe('malicious calendar responses (M3, L2)', () => {
  const submitWith = (body: Buffer) => {
    const { fn } = fakeFetch(() => ({ status: 200, body }));
    return new CalendarTimestamper({ calendars: [CAL], fetch: fn }).submit(digest);
  };

  it('rejects a hexlify-doubling chain that would grow the message without bound', async () => {
    const hexlify = Buffer.from([0xf3]);
    // 32 -> 64 -> ... -> 4096 is still allowed (7 doublings); the 8th would reach 8192.
    const ok = Buffer.concat([...Array(7).fill(hexlify), pendingAtt(CAL)]);
    await expect(submitWith(ok)).resolves.toBeInstanceOf(Buffer);
    const evil = Buffer.concat([...Array(8).fill(hexlify), pendingAtt(CAL)]);
    await expect(submitWith(evil)).rejects.toThrow(/too long/);
    const huge = Buffer.concat([...Array(200).fill(hexlify), pendingAtt(CAL)]);
    await expect(submitWith(huge)).rejects.toThrow(/too long/);
  });

  it('rejects an oversized varbytes operand and an append that grows past 4096 bytes', async () => {
    const bigAppend = Buffer.concat([append(Buffer.alloc(5000, 1)), pendingAtt(CAL)]);
    await expect(submitWith(bigAppend)).rejects.toThrow(/too long/);
    const grows = Buffer.concat([append(Buffer.alloc(4000, 1)), append(Buffer.alloc(200, 2)), pendingAtt(CAL)]);
    await expect(submitWith(grows)).rejects.toThrow(/too long/);
  });

  it('stops reading the response stream at the 256 KB cap', async () => {
    let chunks = 0;
    let cancelled = false;
    const chunk = new Uint8Array(64 * 1024);
    const fn: FetchLike = async () => ({
      status: 200,
      ok: true,
      arrayBuffer: async () => {
        throw new Error('must not buffer the whole body');
      },
      body: {
        getReader: () => ({
          read: async () => {
            chunks += 1;
            return chunks > 1000 ? { done: true } : { done: false, value: chunk };
          },
          cancel: async () => {
            cancelled = true;
          },
        }),
      },
    });
    await expect(new CalendarTimestamper({ calendars: [CAL], fetch: fn }).submit(digest)).rejects.toThrow(/too large/);
    expect(chunks).toBe(5);
    expect(cancelled).toBe(true);
  });
});

describe('parseCalendarUrls', () => {
  it('requires https when asked (production)', () => {
    expect(parseCalendarUrls('https://a.test', { requireHttps: true })).toEqual(['https://a.test']);
    expect(() => parseCalendarUrls('http://a.test', { requireHttps: true })).toThrow(/https/);
  });

  it('normalises and validates', () => {
    expect(parseCalendarUrls('https://a.test/, http://b.test')).toEqual(['https://a.test', 'http://b.test']);
    expect(() => parseCalendarUrls('ftp://a.test')).toThrow(OtsError);
    expect(() => parseCalendarUrls('https://user:pw@a.test')).toThrow(OtsError);
    expect(() => parseCalendarUrls('not a url')).toThrow(OtsError);
  });
});
