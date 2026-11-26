// OpenTimestamps client (T-028, ADR 0019): submit a SHA-256 digest to calendar servers, keep the
// resulting .ots proof, and upgrade it later once Bitcoin has confirmed it.
//
// The network is reached only through the injectable `fetch`; the Timestamper interface lets the
// job (and tests) use NoopTimestamper. Nothing here sees keys or tokens: only a 32-byte digest is sent.
// Proof file layout (public OpenTimestamps format): header magic, version 1, op SHA-256, the digest,
// then a timestamp tree of ops that ends in attestations (pending calendar URI, or Bitcoin block).
import { createHash } from 'node:crypto';

const MAGIC = Buffer.concat([
  Buffer.from([0x00]),
  Buffer.from('OpenTimestamps', 'ascii'),
  Buffer.from([0x00, 0x00]),
  Buffer.from('Proof', 'ascii'),
  Buffer.from([0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94]),
]);
const VERSION = 0x01;
const OP_SHA256 = 0x08;
const PENDING_TAG = '83dfe30d2ef90c8e';
const BITCOIN_TAG = '0588960d73d71901';
const MAX_RESPONSE_BYTES = 256 * 1024;
const MAX_DEPTH = 256;
/** OpenTimestamps itself limits operation messages to 4096 bytes; hexlify doubling must not grow it unboundedly. */
const MAX_MSG_BYTES = 4096;
const MAX_VARBYTES = 4096;
const ACCEPT = 'application/vnd.opentimestamps.v1';

export class OtsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'OtsError';
  }
}

export type UpgradeResult = { status: 'pending' } | { status: 'complete'; proof: Buffer };

export interface Timestamper {
  /** False for the noop implementation: the job then stores no proof rows at all. */
  readonly enabled: boolean;
  /** Submit a 32-byte SHA-256 digest. Returns a complete .ots file in PENDING state. */
  submit(digest: Buffer): Promise<Buffer>;
  /** Try to turn a pending proof into a Bitcoin-attested one. */
  upgrade(proof: Buffer): Promise<UpgradeResult>;
}

export class NoopTimestamper implements Timestamper {
  readonly enabled = false;
  submit(): Promise<Buffer> {
    return Promise.reject(new OtsError('timestamping is disabled'));
  }
  upgrade(): Promise<UpgradeResult> {
    return Promise.resolve({ status: 'pending' });
  }
}

// --- minimal .ots reader -------------------------------------------------------------------------

class Reader {
  pos = 0;
  constructor(readonly buf: Buffer, pos = 0) {
    this.pos = pos;
  }
  byte(): number {
    const b = this.buf[this.pos++];
    if (b === undefined) throw new OtsError('truncated proof');
    return b;
  }
  take(n: number): Buffer {
    if (n < 0 || this.pos + n > this.buf.length) throw new OtsError('truncated proof');
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  varuint(): number {
    let value = 0;
    let shift = 0;
    for (;;) {
      const b = this.byte();
      value += (b & 0x7f) * 2 ** shift;
      if ((b & 0x80) === 0) return value;
      shift += 7;
      if (shift > 35) throw new OtsError('varuint too large');
    }
  }
  varbytes(): Buffer {
    const n = this.varuint();
    if (n > MAX_VARBYTES) throw new OtsError('proof field too long');
    return this.take(n);
  }
  get done(): boolean {
    return this.pos >= this.buf.length;
  }
}

export interface Attestation {
  /** hex of the 8-byte attestation type tag */
  tag: string;
  payload: Buffer;
  /** the message committed to at this point of the tree */
  msg: Buffer;
  /** offset of the 0x00 attestation marker in the buffer */
  start: number;
}

interface ScanState {
  attestations: Attestation[];
  forks: number;
}

function applyOp(tag: number, r: Reader, msg: Buffer): Buffer {
  const out = applyOpUnchecked(tag, r, msg);
  if (out.length > MAX_MSG_BYTES) throw new OtsError('proof message too long');
  return out;
}

function applyOpUnchecked(tag: number, r: Reader, msg: Buffer): Buffer {
  // hexlify doubles the message: refuse before allocating when the result would exceed the cap.
  if (tag === 0xf3 && msg.length * 2 > MAX_MSG_BYTES) throw new OtsError('proof message too long');
  switch (tag) {
    case 0x08:
      return createHash('sha256').update(msg).digest();
    case 0x02:
      return createHash('sha1').update(msg).digest();
    case 0x03:
      try {
        return createHash('ripemd160').update(msg).digest();
      } catch {
        throw new OtsError('RIPEMD-160 is not available');
      }
    case 0xf0:
      return Buffer.concat([msg, r.varbytes()]);
    case 0xf1:
      return Buffer.concat([r.varbytes(), msg]);
    case 0xf2:
      return Buffer.from(msg).reverse();
    case 0xf3:
      return Buffer.from(msg.toString('hex'), 'ascii');
    default:
      throw new OtsError('unknown operation in proof');
  }
}

function readItem(r: Reader, tag: number, start: number, msg: Buffer, st: ScanState, depth: number): void {
  if (depth > MAX_DEPTH) throw new OtsError('proof too deep');
  if (tag === 0x00) {
    const type = r.take(8).toString('hex');
    st.attestations.push({ tag: type, payload: r.varbytes(), msg, start });
    return;
  }
  readTimestamp(r, applyOp(tag, r, msg), st, depth + 1);
}

function readTimestamp(r: Reader, msg: Buffer, st: ScanState, depth: number): void {
  for (;;) {
    const start = r.pos;
    const tag = r.byte();
    if (tag === 0xff) {
      st.forks += 1;
      readItem(r, r.byte(), start + 1, msg, st, depth);
      continue;
    }
    readItem(r, tag, start, msg, st, depth);
    return;
  }
}

/** Parse the timestamp tree that starts at `offset` for message `msg`. Throws OtsError on bad input. */
export function scanTimestamp(buf: Buffer, offset: number, msg: Buffer): { attestations: Attestation[]; forks: number } {
  const st: ScanState = { attestations: [], forks: 0 };
  const r = new Reader(buf, offset);
  readTimestamp(r, msg, st, 0);
  if (!r.done) throw new OtsError('trailing bytes after timestamp');
  if (st.attestations.length === 0) throw new OtsError('timestamp has no attestation');
  return st;
}

export interface ParsedProof {
  digest: Buffer;
  /** offset of the timestamp tree */
  treeOffset: number;
  attestations: Attestation[];
  forks: number;
}

export function parseProof(file: Buffer): ParsedProof {
  const r = new Reader(file);
  if (!r.take(MAGIC.length).equals(MAGIC)) throw new OtsError('not an OpenTimestamps proof');
  if (r.varuint() !== VERSION) throw new OtsError('unsupported proof version');
  if (r.byte() !== OP_SHA256) throw new OtsError('unsupported file hash operation');
  const digest = Buffer.from(r.take(32));
  const treeOffset = r.pos;
  const { attestations, forks } = scanTimestamp(file, treeOffset, digest);
  return { digest, treeOffset, attestations, forks };
}

export function proofDigest(file: Buffer): Buffer {
  return parseProof(file).digest;
}

/** True once the proof carries a Bitcoin block attestation. */
export function isCompleteProof(file: Buffer): boolean {
  return parseProof(file).attestations.some((a) => a.tag === BITCOIN_TAG);
}

function buildProof(digest: Buffer, tree: Buffer): Buffer {
  return Buffer.concat([MAGIC, Buffer.from([VERSION, OP_SHA256]), digest, tree]);
}

// --- calendar client -----------------------------------------------------------------------------

export type FetchLike = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: Uint8Array; signal?: AbortSignal; redirect?: 'error' | 'follow' | 'manual' },
) => Promise<{
  status: number;
  ok: boolean;
  arrayBuffer(): Promise<ArrayBuffer>;
  /** When present the body is read incrementally and abandoned at the size cap. */
  body?: { getReader(): { read(): Promise<{ done: boolean; value?: Uint8Array }>; cancel(): Promise<void> } } | null;
}>;

async function readCapped(res: Awaited<ReturnType<FetchLike>>): Promise<Buffer> {
  if (!res.body) {
    const all = Buffer.from(await res.arrayBuffer());
    if (all.length > MAX_RESPONSE_BYTES) throw new OtsError('calendar response too large');
    return all;
  }
  const reader = res.body.getReader();
  const parts: Buffer[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.length;
    if (total > MAX_RESPONSE_BYTES) {
      await reader.cancel().catch(() => undefined);
      throw new OtsError('calendar response too large');
    }
    parts.push(Buffer.from(value));
  }
  return Buffer.concat(parts);
}

export interface CalendarTimestamperOptions {
  calendars: readonly string[];
  fetch?: FetchLike;
  timeoutMs?: number;
}

const normaliseCalendar = (u: string): string => u.trim().replace(/\/+$/, '');

export function parseCalendarUrls(list: string, opts: { requireHttps?: boolean } = {}): string[] {
  const urls = list
    .split(',')
    .map(normaliseCalendar)
    .filter((s) => s.length > 0);
  for (const u of urls) {
    let p: URL;
    try {
      p = new URL(u);
    } catch {
      throw new OtsError('OTS calendar URL is not valid');
    }
    if ((p.protocol !== 'https:' && p.protocol !== 'http:') || p.username || p.password || p.search || p.hash) {
      throw new OtsError('OTS calendar URL must be http(s) without credentials, query or fragment');
    }
    if (opts.requireHttps && p.protocol !== 'https:') throw new OtsError('OTS calendar URL must be https in production');
  }
  return urls;
}

export class CalendarTimestamper implements Timestamper {
  readonly enabled = true;
  private readonly calendars: string[];
  private readonly doFetch: FetchLike;
  private readonly timeoutMs: number;

  constructor(opts: CalendarTimestamperOptions) {
    this.calendars = opts.calendars.map(normaliseCalendar);
    if (this.calendars.length === 0) throw new OtsError('at least one OTS calendar URL is required');
    this.doFetch = opts.fetch ?? ((url, init) => fetch(url, init as RequestInit));
    this.timeoutMs = opts.timeoutMs ?? 10000;
  }

  private async call(url: string, init: Parameters<FetchLike>[1]): Promise<{ status: number; body: Buffer }> {
    const res = await this.doFetch(url, {
      ...init,
      headers: { Accept: ACCEPT, 'User-Agent': 'igaro-worker', ...(init?.headers ?? {}) },
      signal: AbortSignal.timeout(this.timeoutMs),
      redirect: 'error',
    });
    const body = await readCapped(res);
    return { status: res.status, body };
  }

  /** Tries each calendar in order; the first valid receipt becomes the (single-calendar) pending proof. */
  async submit(digest: Buffer): Promise<Buffer> {
    if (digest.length !== 32) throw new OtsError('digest must be 32 bytes');
    let lastError = 'no calendar answered';
    for (const cal of this.calendars) {
      try {
        const { status, body } = await this.call(`${cal}/digest`, {
          method: 'POST',
          body: digest,
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        });
        if (status !== 200) {
          lastError = `calendar returned HTTP ${status}`;
          continue;
        }
        const { attestations } = scanTimestamp(body, 0, digest);
        // Only single-chain receipts that point at a pending calendar entry are kept (upgradable later).
        if (!attestations.some((a) => a.tag === PENDING_TAG || a.tag === BITCOIN_TAG)) {
          lastError = 'calendar receipt has no usable attestation';
          continue;
        }
        const proof = buildProof(digest, body);
        parseProof(proof);
        return proof;
      } catch (e) {
        lastError = e instanceof OtsError ? e.message : 'calendar request failed';
      }
    }
    throw new OtsError(lastError);
  }

  async upgrade(proof: Buffer): Promise<UpgradeResult> {
    const parsed = parseProof(proof);
    if (parsed.attestations.some((a) => a.tag === BITCOIN_TAG)) return { status: 'complete', proof };
    // Only the linear proofs this client creates are upgraded: a fork cannot be spliced safely.
    const pending = parsed.attestations;
    const only = pending[0];
    if (parsed.forks !== 0 || pending.length !== 1 || !only || only.tag !== PENDING_TAG) {
      throw new OtsError('proof shape not supported for upgrade');
    }
    const r = new Reader(only.payload);
    const uri = normaliseCalendar(r.varbytes().toString('utf8'));
    // The URI inside a proof is attacker-influenced data: only ever contact calendars we configured.
    if (!this.calendars.includes(uri)) throw new OtsError('pending calendar is not configured');
    const { status, body } = await this.call(`${uri}/timestamp/${only.msg.toString('hex')}`, { method: 'GET' });
    if (status === 404) return { status: 'pending' };
    if (status !== 200) throw new OtsError(`calendar returned HTTP ${status}`);
    const { attestations } = scanTimestamp(body, 0, only.msg);
    if (!attestations.some((a) => a.tag === BITCOIN_TAG)) return { status: 'pending' };
    const upgraded = Buffer.concat([proof.subarray(0, only.start), body]);
    parseProof(upgraded);
    return { status: 'complete', proof: upgraded };
  }
}
