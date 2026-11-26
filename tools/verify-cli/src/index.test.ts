import { readFileSync } from 'node:fs';
import { randomBytes, randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { generateSalt, generateSigningKey, signCredential, unwrapPrivateKey, type CredentialPayloadV1 } from '@igaro/core';
import { EXIT, main, name, type CliIo } from './index.js';

// Golden fixtures: the igaro.credential.v1 golden vector from packages/core/src/credential.test.ts (RFC 8032 test-1 key).
// These bytes must never change; a new schemaVersion gets new fixtures.
const FIX = new URL('../fixtures/', import.meta.url);
const GOLDEN_CRED = readFileSync(new URL('golden-credential.json', FIX), 'utf8');
const GOLDEN_KEYS = readFileSync(new URL('golden-keys.json', FIX), 'utf8');
const GOLDEN_SALT = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
const GOLDEN_SIG = 'FbZ_rBFekgcLk2W4F9aKA5JQUeU0o54xHvZrLTu-rRl1gDttlFLAAAL_ddofykiMMi_yGtxV2iltkNy7Qqs4CA';
const BEFORE_EXPIRY = '2027-01-01T00:00:00Z';

interface Run { code: number; out: string; err: string; fetched: string[]; fetchInit: RequestInit[] }

async function run(
  argv: string[],
  files: Record<string, string> = {},
  web: Record<string, { status: number; body: string } | Error> = {},
  now?: Date,
): Promise<Run> {
  let out = '';
  let err = '';
  const fetched: string[] = [];
  const fetchInit: RequestInit[] = [];
  const io: CliIo = {
    stdout: (s) => { out += s; },
    stderr: (s) => { err += s; },
    readFile: async (p) => {
      const f = files[p];
      if (f === undefined) throw new Error(`ENOENT: no such file ${p}`);
      return Buffer.from(f, 'utf8');
    },
    fetch: (async (input: string | URL | Request, init?: RequestInit) => {
      const u = String(input);
      fetched.push(u);
      fetchInit.push(init ?? {});
      const r = web[u];
      if (!r) throw new TypeError(`fetch failed for ${u}`);
      if (r instanceof Error) throw r;
      return new Response(r.body, { status: r.status, headers: { 'content-type': 'application/json' } });
    }) as typeof fetch,
    ...(now ? { now: () => now } : {}),
  };
  const code = await main(argv, io);
  return { code, out, err, fetched, fetchInit };
}

const golden = { 'cred.json': GOLDEN_CRED, 'keys.json': GOLDEN_KEYS };
const goldenArgs = ['cred.json', '--keys', 'keys.json', '--now', BEFORE_EXPIRY];

function expectNoSecrets(r: Run, secrets: string[]): void {
  for (const s of secrets) {
    expect(r.out).not.toContain(s);
    expect(r.err).not.toContain(s);
  }
}

describe('@igaro/verify-cli', () => {
  it('exports its name', () => {
    expect(name).toBe('@igaro/verify-cli');
  });
});

describe('golden fixtures (offline)', () => {
  it('reports VALID with exit 0 and prints no salt or signature', async () => {
    const r = await run(goldenArgs, golden);
    expect(r.code).toBe(EXIT.VALID);
    expect(r.out).toMatch(/^Result: VALID\n/);
    expect(r.out).toContain('397e4ed197807f27f2ef88940bdc860afed37b298d5164c1137063f8af8a13e9');
    expect(r.out).toContain('Ahmed Hassan');
    expect(r.out).toContain('cannot be checked offline');
    expect(r.fetched).toEqual([]); // fully offline
    expectNoSecrets(r, [GOLDEN_SALT, GOLDEN_SIG, 'EAU20260125']);
  });

  it('JSON output is machine-readable and also free of salt/signature', async () => {
    const r = await run([...goldenArgs, '--json'], golden);
    expect(r.code).toBe(0);
    const j = JSON.parse(r.out) as { result: string; exitCode: number; statusChecked: boolean; credential: { dataHash: string } };
    expect(j).toMatchObject({ result: 'VALID', exitCode: 0, statusChecked: false });
    expectNoSecrets(r, [GOLDEN_SALT, GOLDEN_SIG]);
  });

  it('after the signed expiry: EXPIRED, exit 2', async () => {
    const r = await run(['cred.json', '--keys', 'keys.json', '--now', '2027-08-13T00:00:00Z'], golden);
    expect(r.code).toBe(EXIT.EXPIRED);
    expect(r.out).toMatch(/^Result: EXPIRED/);
  });

  it('uses the injected clock when --now is absent', async () => {
    expect((await run(['cred.json', '--keys', 'keys.json'], golden, {}, new Date('2026-12-01T00:00:00Z'))).code).toBe(0);
    expect((await run(['cred.json', '--keys', 'keys.json'], golden, {}, new Date('2028-01-01T00:00:00Z'))).code).toBe(2);
  });

  it('RETIRED key: exit 0; COMPROMISED key: VERIFICATION FAILED, exit 1', async () => {
    const retired = GOLDEN_KEYS.replace('"ACTIVE"', '"RETIRED"');
    const compromised = GOLDEN_KEYS.replace('"ACTIVE"', '"COMPROMISED"');
    expect((await run(goldenArgs, { ...golden, 'keys.json': retired })).code).toBe(EXIT.VALID);
    const r = await run(goldenArgs, { ...golden, 'keys.json': compromised });
    expect(r.code).toBe(EXIT.VERIFICATION_FAILED);
    expect(r.out).toMatch(/^Result: VERIFICATION FAILED \(KEY_COMPROMISED\)/);
    expect(r.out).toContain('COMPROMISED');
  });

  it('every single-byte change to the signed parts of the file is detected (exit 1)', async () => {
    const bytes = Buffer.from(GOLDEN_CRED, 'utf8');
    // publicKeysUrl is an unsigned locator (the keys are supplied with --keys), so its line is excluded.
    const skipStart = GOLDEN_CRED.indexOf('  "publicKeysUrl"');
    const skipEnd = GOLDEN_CRED.indexOf('\n', skipStart);
    let tested = 0;
    for (let i = 0; i < bytes.length; i++) {
      if (i >= skipStart && i <= skipEnd) continue;
      for (const delta of [0x01, 0x20]) {
        const t = Buffer.from(bytes);
        t[i] = (t[i] ?? 0) ^ delta;
        const r = await run(goldenArgs, { ...golden, 'cred.json': t.toString('latin1') });
        if (r.code !== EXIT.VERIFICATION_FAILED) throw new Error(`byte ${i} ^ ${delta} not detected: exit ${r.code}`);
        tested++;
      }
    }
    expect(tested).toBeGreaterThan(1000);
  }, 60_000);

  it('a one-byte change to the published key is detected', async () => {
    const k = GOLDEN_KEYS.replace('11qYAYKx', '11qYAYKy');
    expect((await run(goldenArgs, { ...golden, 'keys.json': k })).code).toBe(EXIT.VERIFICATION_FAILED);
  });

  it('unparseable credential file: VERIFICATION FAILED (exit 1), not an input error', async () => {
    const r = await run(goldenArgs, { ...golden, 'cred.json': GOLDEN_CRED.slice(0, 100) });
    expect(r.code).toBe(EXIT.VERIFICATION_FAILED);
    expect(r.out).toContain('MALFORMED_FILE');
  });
});

describe('core-generated vectors through the CLI', () => {
  it('a freshly issued credential verifies; after rotation (key RETIRED) it still verifies', async () => {
    const master = randomBytes(32);
    const gen = generateSigningKey(master);
    const payload: CredentialPayloadV1 = {
      schemaVersion: 'igaro.credential.v1',
      credentialId: randomUUID(),
      credentialNumber: 'EAU-2026-ZZ99YY88',
      institutionId: randomUUID(),
      issuerKeyId: gen.kid,
      credentialType: 'CERTIFICATE',
      holder: { fullName: 'Juma Otieno', externalId: null, photoSha256: 'ef'.repeat(32) },
      attributes: {},
      issuedAt: '2026-11-01T10:00:00Z',
      expiresAt: null,
      salt: generateSalt(),
    };
    const s = signCredential(payload, unwrapPrivateKey(gen.encryptedPrivateKey, master, gen.kid));
    const cred = JSON.stringify({ payload, dataHash: s.dataHash, signature: s.signature, kid: gen.kid, publicKeysUrl: '/i/eau/keys.json' });
    const newKey = generateSigningKey(master);
    const keys = (status: string) => JSON.stringify({
      keys: [
        { kid: gen.kid, alg: 'Ed25519', publicKey: gen.publicKey, status, createdAt: '2026-01-01T00:00:00.000Z', retiredAt: null },
        { kid: newKey.kid, alg: 'Ed25519', publicKey: newKey.publicKey, status: 'ACTIVE', createdAt: '2026-11-20T00:00:00.000Z', retiredAt: null },
      ],
    });
    const files = { 'c.json': cred };
    const r = await run(['c.json', '--keys', 'k.json', '--json'], { ...files, 'k.json': keys('ACTIVE') });
    expect(r.code).toBe(0);
    expectNoSecrets(r, [payload.salt, s.signature]);
    expect((await run(['c.json', '--keys', 'k.json'], { ...files, 'k.json': keys('RETIRED') })).code).toBe(0);
    expect((await run(['c.json', '--keys', 'k.json'], { ...files, 'k.json': keys('COMPROMISED') })).code).toBe(1);
  });
});

describe('usage and input errors (exit 3)', () => {
  const cases: [string, string[], Record<string, string>][] = [
    ['no arguments', [], {}],
    ['two positionals', ['a', 'b', '--keys', 'k'], {}],
    ['unknown option', ['cred.json', '--keys', 'keys.json', '--api'], golden],
    ['both key options', ['cred.json', '--keys', 'keys.json', '--keys-url', 'https://x.example/i/eau/keys.json'], golden],
    ['local file without keys', ['cred.json'], golden],
    ['missing credential file', ['nope.json', '--keys', 'keys.json'], golden],
    ['missing keys file', ['cred.json', '--keys', 'nope.json'], golden],
    ['keys not JSON', ['cred.json', '--keys', 'bad.json'], { ...golden, 'bad.json': '{' }],
    ['keys wrong shape', ['cred.json', '--keys', 'bad.json'], { ...golden, 'bad.json': '{"keys":[{"kid":"x"}]}' }],
    ['bad --now', ['cred.json', '--keys', 'keys.json', '--now', 'tomorrow'], golden],
    ['--keys-url not a URL', ['cred.json', '--keys-url', 'keys.json'], golden],
  ];
  for (const [label, argv, files] of cases) {
    it(label, async () => {
      const r = await run(argv, files);
      expect(r.code).toBe(EXIT.INPUT_ERROR);
      expect(r.err).toMatch(/^igaro-verify: /);
    });
  }
  it('--help prints usage and exits 0', async () => {
    const r = await run(['--help']);
    expect(r.code).toBe(0);
    expect(r.out).toContain('Exit codes');
  });
});

describe('remote documents (optional network mode)', () => {
  const TOKEN = 'Q2xhdWRlVGVzdFRva2VuMQ';
  const CRED_URL = `https://igaro.example/api/v1/verify/${TOKEN}/credential.json`;
  const KEYS_URL = 'https://igaro.example/i/eau/keys.json';

  it('fetches only credential.json and the same-origin keys.json; never echoes the token', async () => {
    const r = await run([CRED_URL, '--now', BEFORE_EXPIRY], {}, {
      [CRED_URL]: { status: 200, body: GOLDEN_CRED },
      [KEYS_URL]: { status: 200, body: GOLDEN_KEYS },
    });
    expect(r.code).toBe(0);
    expect(r.fetched).toEqual([CRED_URL, KEYS_URL]);
    // Never the verify API itself (only public documents).
    expect(r.fetched.some((u) => /\/verify\/[^/]+$/.test(u))).toBe(false);
    for (const init of r.fetchInit) {
      expect(init.method).toBe('GET');
      expect(init.redirect).toBe('error');
    }
    expect(r.out).toContain('same server');
    expectNoSecrets(r, [TOKEN, GOLDEN_SALT, GOLDEN_SIG]);
  });

  it('--keys pins a local key file even for a remote credential', async () => {
    const r = await run([CRED_URL, '--keys', 'keys.json', '--now', BEFORE_EXPIRY], golden, { [CRED_URL]: { status: 200, body: GOLDEN_CRED } });
    expect(r.code).toBe(0);
    expect(r.fetched).toEqual([CRED_URL]);
    expect(r.out).not.toContain('same server');
  });

  it('--keys-url with a local credential', async () => {
    const r = await run(['cred.json', '--keys-url', KEYS_URL, '--now', BEFORE_EXPIRY], golden, { [KEYS_URL]: { status: 200, body: GOLDEN_KEYS } });
    expect(r.code).toBe(0);
    expect(r.fetched).toEqual([KEYS_URL]);
  });

  it('404 for the credential: NOT FOUND, exit 4, token not echoed', async () => {
    const r = await run([CRED_URL, '--json'], {}, { [CRED_URL]: { status: 404, body: '{}' } });
    expect(r.code).toBe(EXIT.NOT_FOUND);
    expect(JSON.parse(r.out)).toMatchObject({ result: 'NOT_FOUND', exitCode: 4 });
    expectNoSecrets(r, [TOKEN]);
  });

  it('network failure and HTTP errors are input errors and never echo the token', async () => {
    const webs: Record<string, { status: number; body: string }>[] = [
      {},
      { [CRED_URL]: { status: 500, body: '' } },
      { [CRED_URL]: { status: 429, body: '' } },
    ];
    for (const web of webs) {
      const r = await run([CRED_URL], {}, web);
      expect(r.code).toBe(EXIT.INPUT_ERROR);
      expectNoSecrets(r, [TOKEN]);
    }
  });

  it('refuses plain http (except localhost) and embedded credentials', async () => {
    const http = `http://igaro.example/api/v1/verify/${TOKEN}/credential.json`;
    const r = await run([http], {}, { [http]: { status: 200, body: GOLDEN_CRED } });
    expect(r.code).toBe(EXIT.INPUT_ERROR);
    expect(r.fetched).toEqual([]);
    expectNoSecrets(r, [TOKEN]);
    expect((await run(['https://u:p@igaro.example/x.json'])).code).toBe(EXIT.INPUT_ERROR);
    const local = 'http://localhost:3000/api/v1/verify/x/credential.json';
    const ok = await run([local, '--keys', 'keys.json', '--now', BEFORE_EXPIRY], golden, { [local]: { status: 200, body: GOLDEN_CRED } });
    expect(ok.code).toBe(0);
  });

  it('a credential file cannot redirect key lookup to another host', async () => {
    for (const publicKeysUrl of ['https://evil.example/i/eau/keys.json', '//evil.example/i/eau/keys.json', '/i/../keys.json', 42]) {
      const body = JSON.stringify({ ...JSON.parse(GOLDEN_CRED), publicKeysUrl });
      const r = await run([CRED_URL], {}, { [CRED_URL]: { status: 200, body } });
      expect(r.code).toBe(EXIT.INPUT_ERROR);
      expect(r.fetched).toEqual([CRED_URL]);
    }
  });

  it('oversized responses are refused', async () => {
    const r = await run([CRED_URL], {}, { [CRED_URL]: { status: 200, body: ' '.repeat(1024 * 1024 + 1) } });
    expect(r.code).toBe(EXIT.INPUT_ERROR);
  });
});
