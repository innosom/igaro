// igaro-verify: independent, open-source verifier for iGARO credential files (T-034).
//
//   igaro-verify <credential.json | https://.../credential.json> [--keys keys.json | --keys-url URL] [--json] [--now ISO]
//
// Exit codes (stable, for scripts):
//   0 VALID               authentic, unaltered, signed by an ACTIVE or RETIRED published key, not expired
//   1 VERIFICATION_FAILED tampered, bad signature, unknown key, COMPROMISED key, or not a credential file
//   2 EXPIRED             authentic but past its signed expiry
//   3 input error         bad arguments, unreadable file, malformed keys document, network error
//   4 NOT_FOUND           a remote credential.json answered 404
// Output never contains the salt, the signature, the verification/holder token or the credential URL.
import { parseArgs } from 'node:util';
import {
  KeysDocumentError,
  parseKeysDocument,
  verifyCredentialFile,
  type OfflineOutcome,
  type OfflineResult,
} from './offline-verify.js';
import {
  InputError,
  NotFoundError,
  describeSource,
  isUrlArg,
  loadText,
  resolvePublishedKeysUrl,
  tryParseJson,
  type SourceDeps,
} from './sources.js';

export const EXIT = { VALID: 0, VERIFICATION_FAILED: 1, EXPIRED: 2, INPUT_ERROR: 3, NOT_FOUND: 4 } as const;

const EXIT_FOR: Record<OfflineResult, number> = {
  VALID: EXIT.VALID,
  VERIFICATION_FAILED: EXIT.VERIFICATION_FAILED,
  EXPIRED: EXIT.EXPIRED,
};

export const USAGE = `Usage: igaro-verify <credential.json | URL> [options]

Checks an iGARO credential file offline: recomputes SHA-256 over the RFC 8785 canonical payload,
verifies the Ed25519 signature against the institution's published key, and refuses COMPROMISED keys.
It never calls the iGARO verify API.

Options:
  --keys <file>      published keys document (keys.json) on disk; fully offline
  --keys-url <url>   fetch keys.json from this URL (https)
  --json             machine-readable output
  --now <ISO-8601>   evaluate expiry at this instant instead of the current time
  -h, --help         show this help

If the credential is given as a URL and no keys option is passed, keys are fetched from the
publicKeysUrl in the file, on the same origin. Pin --keys for verification independent of that server.

Exit codes: 0 VALID, 1 VERIFICATION FAILED, 2 EXPIRED, 3 input error, 4 NOT FOUND.
Revocation and suspension are not part of the signed data and are not checked offline.
`;

export interface CliIo extends SourceDeps {
  stdout: (s: string) => void;
  stderr: (s: string) => void;
  now?: () => Date;
}

const LABEL: Record<OfflineResult, string> = {
  VALID: 'VALID',
  EXPIRED: 'EXPIRED',
  VERIFICATION_FAILED: 'VERIFICATION FAILED',
};

const MARK = { PASS: '[ok]  ', FAIL: '[FAIL]', NOT_CHECKED: '[--]  ' } as const;

export function formatHuman(outcome: OfflineOutcome, sources: { credential: string; keys: string; sameOriginKeys: boolean }): string {
  const lines: string[] = [];
  lines.push(`Result: ${LABEL[outcome.result]}${outcome.reason === 'OK' ? '' : ` (${outcome.reason})`}`);
  lines.push('');
  const c = outcome.credential;
  if (c) {
    lines.push(`  Holder:            ${c.holderName}`);
    lines.push(`  Credential number: ${c.credentialNumber}`);
    lines.push(`  Type:              ${c.credentialType}`);
    lines.push(`  Institution id:    ${c.institutionId}`);
    lines.push(`  Issued:            ${c.issuedAt}`);
    lines.push(`  Expires:           ${c.expiresAt ?? 'never'}`);
    lines.push(`  Signed with key:   ${c.kid}${outcome.key ? ` (${outcome.key.status})` : ''}`);
    lines.push(`  Data hash:         ${c.dataHash}`);
    lines.push('');
  }
  lines.push('Checks:');
  for (const ch of outcome.checks) lines.push(`  ${MARK[ch.outcome]} ${ch.detail}`);
  lines.push('');
  lines.push(`Credential: ${sources.credential}`);
  lines.push(`Keys:       ${sources.keys}`);
  if (sources.sameOriginKeys) {
    lines.push('Note: keys were fetched from the same server as the credential. Pin --keys for fully independent verification.');
  }
  if (outcome.result === 'VALID' || outcome.result === 'EXPIRED') {
    lines.push('Note: revocation and suspension cannot be checked offline; the verification page shows the current status.');
  }
  return lines.join('\n') + '\n';
}

/** Run the CLI. Returns the exit code; never throws. */
export async function main(argv: readonly string[], io: CliIo): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args: [...argv],
      allowPositionals: true,
      strict: true,
      options: {
        keys: { type: 'string' },
        'keys-url': { type: 'string' },
        json: { type: 'boolean', default: false },
        now: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
    });
  } catch (e) {
    io.stderr(`igaro-verify: ${e instanceof Error ? e.message : 'invalid arguments'}\n\n${USAGE}`);
    return EXIT.INPUT_ERROR;
  }
  const { values, positionals } = parsed;
  if (values.help) {
    io.stdout(USAGE);
    return EXIT.VALID;
  }
  const usageError = (msg: string): number => {
    io.stderr(`igaro-verify: ${msg}\n\n${USAGE}`);
    return EXIT.INPUT_ERROR;
  };
  if (positionals.length !== 1) return usageError('expected exactly one credential file or URL');
  const credentialSrc = positionals[0] as string;
  if (values.keys !== undefined && values['keys-url'] !== undefined) return usageError('use either --keys or --keys-url, not both');
  if (values['keys-url'] !== undefined && !isUrlArg(values['keys-url'])) return usageError('--keys-url must be an http(s) URL');

  let now: Date;
  if (values.now !== undefined) {
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(values.now) || Number.isNaN(Date.parse(values.now))) {
      return usageError('--now must be ISO-8601 UTC, e.g. 2027-01-01T00:00:00Z');
    }
    now = new Date(values.now);
  } else {
    now = io.now ? io.now() : new Date();
  }

  const fail = (code: number, msg: string): number => {
    if (values.json) io.stdout(JSON.stringify({ result: code === EXIT.NOT_FOUND ? 'NOT_FOUND' : 'INPUT_ERROR', error: msg, exitCode: code }) + '\n');
    io.stderr(`igaro-verify: ${msg}\n`);
    return code;
  };

  try {
    const credentialText = await loadText(credentialSrc, 'credential', true, io);
    const credentialDoc = tryParseJson(credentialText);

    let keysSrc: string;
    let sameOriginKeys = false;
    if (values.keys !== undefined) keysSrc = values.keys;
    else if (values['keys-url'] !== undefined) keysSrc = values['keys-url'];
    else if (isUrlArg(credentialSrc)) {
      const advertised = typeof credentialDoc === 'object' && credentialDoc !== null
        ? (credentialDoc as Record<string, unknown>).publicKeysUrl
        : undefined;
      keysSrc = resolvePublishedKeysUrl(credentialSrc, advertised);
      sameOriginKeys = true;
    } else {
      return usageError('a local credential file needs --keys <keys.json> or --keys-url <url>');
    }

    const keysDoc = tryParseJson(await loadText(keysSrc, 'keys', false, io));
    if (keysDoc === undefined) throw new InputError('keys: not valid JSON');
    const keys = parseKeysDocument(keysDoc);

    const outcome = verifyCredentialFile(credentialDoc, keys, now);
    const exitCode = EXIT_FOR[outcome.result];
    const sources = { credential: describeSource(credentialSrc, true), keys: describeSource(keysSrc, false), sameOriginKeys };
    if (values.json) io.stdout(JSON.stringify({ ...outcome, sources, exitCode }, null, 2) + '\n');
    else io.stdout(formatHuman(outcome, sources));
    return exitCode;
  } catch (e) {
    if (e instanceof NotFoundError) return fail(EXIT.NOT_FOUND, 'NOT FOUND: no credential exists at that address');
    if (e instanceof InputError) return fail(EXIT.INPUT_ERROR, e.message);
    if (e instanceof KeysDocumentError) return fail(EXIT.INPUT_ERROR, `keys: ${e.message}`);
    // Unexpected: keep it generic so nothing from the inputs can leak.
    return fail(EXIT.INPUT_ERROR, 'unexpected error while verifying');
  }
}
