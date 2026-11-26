export const name = '@igaro/verify-cli';
export {
  verifyCredentialFile,
  parseKeysDocument,
  KeysDocumentError,
  type OfflineOutcome,
  type OfflineResult,
  type OfflineReason,
  type PublishedKey,
  type CheckLine,
  type CredentialSummary,
} from './offline-verify.js';
export { main, formatHuman, EXIT, USAGE, type CliIo } from './cli.js';
export { InputError, NotFoundError, MAX_DOCUMENT_BYTES } from './sources.js';
