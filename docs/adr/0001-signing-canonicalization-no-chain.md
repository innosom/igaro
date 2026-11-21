# ADR 0001: Ed25519 signatures over JCS payload hash; no blockchain in the MVP

Status: Accepted (whitepaper v1.0, Architecture Review)

## Context
Verifiers need to know a credential exists, who issued it, whether it was altered and whether it is valid.
v0 used a blockchain for this. It adds smart-contract, wallet, gas and outage risk and ~2 weeks of work.

## Decision
1. Canonicalize the payload (`igaro.credential.v1`) with RFC 8785 JCS; `dataHash = SHA-256(canonical)`;
   `signature = Ed25519(institutionKey, "igaro.credential.sig.v1:" + dataHash)`. The domain prefix prevents cross-context reuse.
2. Payload contains credentialNumber, issuerKeyId, holder.photoSha256 and a 256-bit salt. Status, tokens, branding stay outside it.
3. One shared implementation in `packages/core` for API, worker and CLI, pinned by golden tests. Any change to canonical output needs a new `schemaVersion`.
4. One Ed25519 key per institution with a `kid`; private key AES-256-GCM encrypted under a master key outside the DB; public keys published at `/i/:slug/keys.json` as ACTIVE/RETIRED/COMPROMISED.
5. Trust is by signatures, published keys and a hash-chained append-only audit log whose daily head hash is signed and OpenTimestamps-stamped.
6. No blockchain in the MVP. Hooks only: `AnchorService` + `NoopAnchorService`, `credential_events` outbox, `anchor_status = NOT_ANCHORED`, data-driven proof panel. Nothing may depend on a chain.

## Consequences
- Authenticity is checkable offline by the CLI; revocation status still relies on iGARO servers, and external timestamps cover the audit log daily only. Phase 1 anchoring closes both.
- Corrections are reissues, never edits. Deleting the salt unlinks the hash from a person.
- Key compromise makes all credentials signed by that key fail verification.
