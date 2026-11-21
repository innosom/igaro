# iGARO MVP: Architecture Review and Revised Plan

Review of *iGARO MVP V.0 Technical White Paper* (26 pp.), written from a software architect and senior developer perspective.

**Revision 2: blockchain-free MVP.** The blockchain layer moves out of the MVP and becomes the first Phase 1 feature. The MVP instead uses **institution digital signatures** and a **tamper-evident audit log**. It is designed so blockchain anchoring can be added later as a plug-in, with a backfill of every credential issued before then.

---

## 1. Verdict

The product thesis is sound: *a credential management and verification platform*, with blockchain as an **optional trust layer underneath**, not the product itself. The white paper already says "the institution uses iGARO, not blockchain". This revision takes that one step further: **the MVP doesn't need blockchain to prove the product works.**

What a verifier needs to know is:

1. Does this credential exist?
2. Was it really issued by this institution?
3. Has it been altered?
4. Is it still valid, or revoked, suspended or expired?

A well-designed database plus **cryptographic signatures** answers all four. Blockchain adds one more property, *"you don't have to trust iGARO's servers"*, which matters at scale but not to a first set of pilot institutions.

Removing blockchain from the MVP:
- **Cuts about 2 weeks** (about 7 weeks → about 5).
- **Removes the riskiest parts:** smart contract, wallets, gas, testnet, transaction ordering, the blockchain event reader, and RPC outages.
- **Loses nothing permanently**, provided the extension points in §5 are built now.

The rest of the paper's design flaws (guessable IDs, PII leaking through hashes, the confused lifecycle, multi-tenancy gaps, no holder delivery, no bulk issuance) still apply and are fixed below.

---

## 2. What replaces blockchain in the MVP

| Blockchain was providing… | MVP replacement | Strength |
|---|---|---|
| Proof the data wasn't altered | **Ed25519 signature by the institution's key** over the salted canonical hash | Stronger: any byte change breaks the signature, and it can be checked offline |
| Proof of who issued it | **One signing key pair per institution.** The public key is published at `https://verify.igaro.app/i/{slug}/keys.json` | Equivalent: anyone can check that the signature comes from that institution's key |
| Revocation status | Status in Postgres, shown on the verify page | Weaker: you must trust iGARO for status (see §4) |
| Tamper-proof history | **Hash-chained, append-only audit log.** Each entry stores `prev_hash` and `entry_hash = SHA-256(prev_hash ‖ entry)` | Detects edits and deletions inside iGARO; the same core idea as a blockchain, kept internally |
| Independent checking | **Downloadable signed credential** plus an open-source `igaro-verify` CLI and an in-browser check | Equivalent for authenticity |

This is also how the **W3C Verifiable Credentials** standard works (an issuer signature plus a status mechanism), so the MVP is a step toward standards compliance, not away from it.

---

## 3. Critical design fixes (apply to the MVP)

### Fix 1: Signatures, so verification doesn't depend only on iGARO's word

**Problem in the paper:** the verifier scans the QR and iGARO's page shows data from iGARO's database. The verifier has no independent way to check it.

**MVP design:**
- When an institution is created, generate an **Ed25519 key pair** for it.
- Encrypt the private key with AES-256-GCM under a master key held **outside the database** (a cloud KMS or secret manager; for the demo, an environment secret that is never logged).
- Never store or log a private key in plaintext.
- On issue: `signature = Ed25519.sign(institutionKey, SHA-256(JCS(canonicalPayload)))`.
- The **verify page** shows "Signed by East Africa University ✓", the key ID, and a "Download credential" button (signed JSON).
- Anyone can check the signature against the published public key using the open-source `igaro-verify` CLI or the in-browser check.
- **Key rotation:** keys have a `kid` (key ID). Old public keys stay published as `retired` so old credentials stay verifiable. A compromised key can be marked `compromised`, which flags everything it signed.

### Fix 2: Don't make hashes of personal data guessable

**Problem in the paper:** `SHA256(name, ID, dates…)`. These fields have very little entropy, so the hash can be reversed by guessing. That's harmless while the hash is private, but it becomes a leak the moment it's published or anchored on-chain later. The photo isn't covered, so a photo swap goes undetected.

**MVP design:**
- Add a **random 256-bit `salt`** per credential, stored off-chain only.
- Include `photoSha256` (the hash of the photo bytes) in the hashed data.
- Canonicalize with **RFC 8785 (JSON Canonicalization Scheme)**.
- Add a `schemaVersion` field.
- Put the canonicalize, hash and sign code in **one shared package** used by issuance, verification and the CLI.

Canonical payload (v1):

```json
{
  "schemaVersion": "igaro.credential.v1",
  "credentialId": "<uuid v4>",
  "institutionId": "<uuid>",
  "issuerKeyId": "eau-2026-01",
  "credentialType": "STUDENT_ID",
  "holder": { "fullName": "…", "externalId": "EAU20260125", "photoSha256": "…" },
  "attributes": { "program": "Computer Science" },
  "issuedAt": "2026-08-13T00:00:00Z",
  "expiresAt": "2027-08-13T00:00:00Z",
  "salt": "<32 random bytes, base64url>"
}
```

Downloaded signed credential = `{ payload, proof: { type: "Ed25519Signature", kid, dataHash, signature } }`.

### Fix 3: Make credential IDs impossible to guess

**Problem in the paper:** `IGR-8F92A1` (about 16 million combinations) in a public URL that shows name and photo. A script can scrape every holder.

**MVP design:**
- Use three separate identifiers:
  - `id`: internal UUID.
  - `credential_number`: human-readable, printed on the card, **never used for lookup**.
  - `verification_token`: 128-bit random, base64url, **the only thing in the QR and URL** (`https://verify.igaro.app/v/{token}`).
- Add a separate `holder_token` for the holder's private card page.
- Rate-limit `/verify` and add basic bot protection.
- **Per-institution public-field settings** (for example name and status always; photo and program optional).

### Fix 4: A clear lifecycle where "revoked" is final

**Problem in the paper:** `REACTIVATED` is treated as a state, `ISSUED` and `ACTIVE` are redundant, and "un-revoking" means verifiers can never trust REVOKED as final.

**MVP state machine:**

```
DRAFT ──issue──▶ ACTIVE ◀──reinstate──┐
                   │                  │
                   ├──suspend──▶ SUSPENDED
                   │
                   ├──revoke───▶ REVOKED     (terminal)
                   │
                   └──reissue──▶ SUPERSEDED  (terminal, links to the new credential)

EXPIRED = computed at read time (now > expires_at), not stored
```

- **Suspend** is reversible (for example a student on leave). **Revoke** is permanent (for example fraud, or a degree rescinded).
- **Any change to signed fields is a reissue**: a new credential is created and the old one becomes `SUPERSEDED`. There is no in-place editing of signed data and no `credential_versions` table.
- Note: there's no `PENDING_ANCHOR` state in the MVP. Issuance is instant because nothing waits on a blockchain.

### Fix 5: Multi-tenancy enforced twice, not once

**Problem in the paper:** `institutionId` exists on rows, but nothing enforces it. `users.institution_id` and an `institution_users` table contradict each other.

**MVP design:**
- `users.institution_id` (null = platform admin). Drop `institution_users`.
- Enforce in **two layers**: a scoped data-access layer (every query gets `institution_id` from the session, never from the request) **and** Postgres **Row-Level Security**.
- Automated tests assert that every cross-tenant read or write returns 404.

### Fix 6: Holders actually receive their credential

**Problem in the paper:** "Ahmed receives digital ID", with no mechanism.

**MVP design:**
- Email the holder a private link (`/h/{holder_token}`) to view the branded card, with **PNG/PDF download** and the signed JSON.
- No holder accounts in the MVP.

---

## 4. What the MVP gives up, and how to be honest about it

| Lost (until Phase 1) | Impact | Mitigation in the MVP |
|---|---|---|
| **"Blockchain-verified" in the pitch** | Investors or institutions may expect it | Position as *"cryptographically signed today, blockchain-anchored in Phase 1"*. Show the anchoring design in the deck. |
| **Status that survives iGARO** | If iGARO is down or compromised, nobody can independently confirm revocation | Signatures still prove authenticity. Revocation status depends on iGARO for now; say so in the docs. |
| **An independent timestamp** | Can't prove to an outsider *when* something was issued | Optional, cheap: **RFC 3161 timestamps** or **OpenTimestamps** (free, Bitcoin-backed) on the daily audit-log head hash. Half a day of work and no wallet needed. Recommended as an "MVP+" item. |
| **Immutable external audit trail** | An insider with DB access could rewrite history | The hash-chained audit log detects it. Publishing the daily head hash (on the website, or timestamped as above) makes rewriting it detectable from outside too. |

None of these losses matter for proving the product with the first pilot institutions. All of them are recovered in Phase 1.

---

## 5. Building it so blockchain plugs in later

These extension points cost about 2–3 days in the MVP and save a rewrite later:

1. **Salted canonical hash and `data_hash` stored on every credential**, exactly as an on-chain anchor will need.
2. **An `AnchorService` interface** in `packages/core`:
   ```ts
   interface AnchorService {
     anchor(credentialId: string, dataHash: string): Promise<AnchorResult>;
     setStatus(credentialId: string, status: CredentialStatus): Promise<AnchorResult>;
     getProof(credentialId: string): Promise<AnchorProof | null>;
   }
   ```
   The MVP ships `NoopAnchorService`, which returns `{ status: "NOT_ANCHORED" }`. Phase 1 adds `EvmAnchorService`; nothing else changes.
3. **A `credential_events` outbox table.** Every issue, suspend, reinstate, revoke and reissue writes an event in the same DB transaction. The MVP uses it for the audit log and email. In Phase 1 a worker reads the same table to anchor events, and **backfills every credential issued during the pilot.**
4. **A background job queue from day one** (**pg-boss**, Postgres-backed, no Redis). The MVP uses it for emails, card rendering and CSV import. Phase 1 adds the anchoring worker to the same queue.
5. **A data-driven proof panel** on the verify page. It takes a list of proofs (`signature`, later `blockchain`, later `w3c-status-list`) and renders whatever is present.
6. **Keys per institution already exist.** In Phase 1 the same institution identity gets an EVM key (or the Ed25519 key signs EIP-712-style payloads for a relayer). The institution identity doesn't change.
7. **`anchor_status` column on credentials** (`NOT_ANCHORED` now, later `PENDING` / `ANCHORED` / `FAILED`), so the dashboard and verify page are ready.

---

## 6. MVP verification algorithm

```
verify(token):
  1. cred = db.findByVerificationToken(token)          → none: NOT_FOUND
  2. inst = cred.institution; key = inst.keys[cred.issuerKeyId]
  3. h = sha256(JCS(canonical(cred)))
     if h != cred.dataHash
        or !ed25519.verify(key.public, h, cred.signature)  → INTEGRITY_FAILED (alert ops; never VERIFIED)
  4. if key.status == COMPROMISED                      → ISSUER_KEY_COMPROMISED
  5. status: REVOKED / SUSPENDED / SUPERSEDED          → that result (+ link to replacement)
  6. if now > cred.expiresAt                           → EXPIRED
  7. if inst.status == SUSPENDED                       → VALID_WITH_WARNING
  8.                                                   → VERIFIED
  proofs = [signatureProof]  (+ anchorService.getProof() once Phase 1 is live)
  log every call to verification_logs (token hash, result, IP hash, UA, timestamp)
```

Integrity is checked **before** status, so a tampered record never shows as a clean "REVOKED".

The **independent check** (CLI or browser): given the downloaded signed JSON, fetch the institution's `keys.json`, recompute the hash, and verify the signature. Status still comes from the iGARO API in the MVP.

---

## 7. MVP architecture

```
                    ┌──────────────────────────────┐
  Institution  ───▶ │  Web app (Next.js)            │ ◀─── Verifier (public /v/:token)
  admin             │  dashboard + verify + holder  │ ◀─── Holder (private /h/:token)
                    └──────────────┬───────────────┘
                                   │ HTTPS /api/v1
                    ┌──────────────▼───────────────┐
                    │  API (Node/TS, Express or    │
                    │  Fastify)                     │
                    │  auth · tenancy · credentials │
                    │  signing · verify · audit     │
                    └───┬──────────┬───────────┬───┘
                        │          │           │
               ┌────────▼───┐ ┌────▼─────┐ ┌───▼──────────┐
               │ PostgreSQL │ │ Object   │ │ Email (SES/  │
               │ + RLS      │ │ storage  │ │ Resend)      │
               │ + pg-boss  │ │ (photos, │ └──────────────┘
               │ + outbox   │ │ logos,   │
               └────┬───────┘ │ cards)   │
                    │ jobs    └──────────┘
          ┌─────────▼────────────┐
          │ Worker                │   emails · card rendering · CSV import
          │ (pg-boss)             │   [Phase 1: + anchoring worker → blockchain]
          └──────────────────────┘
                    ▲
              ┌─────┴──────┐
              │ KMS/secret │  master key → decrypts per-institution signing keys
              └────────────┘

packages/core: canonicalize + hash + sign/verify + AnchorService interface,
               shared by API, worker and the open-source verify CLI
```

### Repo layout (monorepo)

```
igaro/
├── apps/
│   ├── web/            Next.js (dashboard, public verify page, holder page)
│   ├── api/            Node + TS REST API
│   └── worker/         background jobs (email, card render, CSV import; later anchoring)
├── packages/
│   ├── core/           RFC 8785 canonicalization, hashing, Ed25519 signing, AnchorService
│   └── db/             Prisma schema + migrations + RLS policies
├── tools/verify-cli/   open-source independent verifier
└── docs/               architecture.md, threat-model.md, api.md, adr/
                        (packages/contracts/ is added in Phase 1)
```

**Stack:** Next.js + React + TypeScript + Tailwind; Node + TypeScript (Express or Fastify); PostgreSQL + Prisma; pg-boss; `@noble/ed25519` (or Node's built-in `crypto`) for signatures; `canonicalize` (RFC 8785); a standard QR library; S3-compatible storage; Resend or SES for email.

### Core tables

```
institutions        id, name, slug, logo_key, primary_color, secondary_color,
                    public_fields jsonb, status, timestamps
institution_keys    id, institution_id, kid, algorithm, public_key, encrypted_private_key,
                    status (ACTIVE/RETIRED/COMPROMISED), created_at, retired_at
users               id, institution_id (null = platform admin), email, name, password_hash,
                    role, status, timestamps
invites             id, institution_id, email, role, token_hash, expires_at, used_at
credential_types    id, institution_id, code, name, attribute_schema jsonb, card_template, validity_days
credential_holders  id, institution_id, full_name, external_id, email, photo_key, photo_sha256, timestamps
credentials         id, institution_id, holder_id, type_id, credential_number, attributes jsonb,
                    status, issued_at, expires_at, salt, schema_version, data_hash,
                    issuer_kid, signature, anchor_status (NOT_ANCHORED), verification_token,
                    holder_token, superseded_by, timestamps
credential_events   id, credential_id, institution_id, type, payload jsonb, created_at,
                    anchored_at (null until Phase 1)                          ← outbox
verification_logs   id, credential_id, result, ip_hash, user_agent, created_at
audit_logs          id, institution_id, actor_id, action, target_type, target_id, metadata,
                    ip, created_at, prev_hash, entry_hash                     ← hash chain
```

(Phase 1 adds `chain_operations` and `anchors`.)

### API (v1)

```
Auth          POST /api/v1/auth/login · /logout · /password-reset · /invites/accept
              GET  /api/v1/auth/me
              (no public /register: platform admin creates institutions and invites admins)
Institutions  GET/POST /api/v1/institutions            (platform admin)
              GET/PATCH /api/v1/institutions/:id       (own institution only)
              POST /api/v1/institutions/:id/logo · /keys/rotate
Holders       GET/POST /api/v1/holders · GET/PATCH /api/v1/holders/:id · POST /:id/photo
Types         GET/POST /api/v1/credential-types
Credentials   GET/POST /api/v1/credentials · GET /api/v1/credentials/:id
              POST /api/v1/credentials/:id/suspend · /reinstate · /revoke · /reissue
              POST /api/v1/credentials/import          (CSV)
              GET  /api/v1/credentials/:id/card.pdf · card.png
Public        GET  /api/v1/verify/:verificationToken
              GET  /api/v1/verify/:verificationToken/credential.json
              GET  /i/:slug/keys.json                  (public keys)
Holder        GET  /api/v1/holder/:holderToken
Audit         GET  /api/v1/audit-logs · GET /api/v1/audit-logs/verify-chain
```

---

## 8. Scope: MVP versus later

### Narrow the wedge

**Education first** (universities, colleges, training centers). Ship **two templates: Student/Staff ID card and Certificate.** The credential-type engine stays generic (an attribute schema per type), so hospitals and companies later need configuration, not code.

### Phase 0: MVP, no blockchain (about 5 weeks, 1–2 developers)

| Module | Included |
|---|---|
| Auth | Email + password (Argon2id), httpOnly cookie sessions, invite flow, password reset, login rate limiting |
| Roles | Platform Admin, Institution Admin |
| Tenancy | Scoped data access + Postgres RLS + cross-tenant tests |
| Institutions | Create and suspend (platform admin), branding (logo, two colors, card title), public-field settings, signing key generated and rotatable |
| Holders | Create and edit, photo upload (private storage, EXIF stripped, signed URLs) |
| Credential types | Two templates (ID card, certificate) with attribute schema |
| Issuance | Single issue: salted canonical hash, **Ed25519 signature**, instantly ACTIVE |
| Bulk issuance | **CSV import** (validate, preview, issue batch as a background job) |
| Lifecycle | ACTIVE, SUSPENDED ↔ reinstate, REVOKED (terminal), reissue → SUPERSEDED, EXPIRED derived |
| Card | Branded card as PNG/PDF with QR (verification-token URL) and "Verify only at verify.igaro.app" |
| Holder delivery | Email with private holder link and downloads (card + signed JSON) |
| Public verification | Algorithm in §6, signature proof panel, signed JSON download, public keys endpoint, rate limiting |
| Independent verify | Open-source CLI + in-browser signature check |
| Audit | Hash-chained append-only audit log (with a chain-integrity check endpoint) + verification log; activity view |
| Dashboard | Counts (total, active, suspended, revoked, expired), credentials list with search and filter |
| Blockchain-ready | `AnchorService` (no-op), `credential_events` outbox, `anchor_status`, data-driven proof panel |
| Ops | Docker Compose, CI (lint, type-check, tests), seed data, `.env.example`, staging deploy |

**MVP+ (optional, about half a day):** daily OpenTimestamps or RFC 3161 timestamp of the audit-log head hash.

**MVP exit criteria** (the paper's §35, minus the blockchain lines, plus these):
- Demo flow: create institution → log in → brand → create holder → issue → QR → verify → suspend → verify shows SUSPENDED → reinstate → verify VERIFIED → revoke → verify REVOKED (and cannot be reinstated).
- Editing any signed field directly in the DB makes verification return **INTEGRITY_FAILED**.
- Editing or deleting an audit-log row is detected by the chain-integrity check.
- The open-source CLI verifies a downloaded credential's signature **without calling the iGARO API**.
- CSV import of 500 holders completes and each holder receives an email.
- Verification p95 under 300 ms; enumerating verify URLs is impractical.
- Cross-tenant tests pass; no private key, salt or token appears in logs.

### Phase 1: Blockchain layer + pilot-ready (about 3–4 weeks for the blockchain part)

**Blockchain anchoring, plugged into the existing design:**
- `packages/contracts`: a minimal `CredentialRegistry` (issuer allowlist, `register(key, dataHash)`, `setStatus(key, status)`, no transition out of REVOKED, events for history).
- An L2 network: **Base** or **Polygon PoS** (testnet first, then mainnet). Never Ethereum L1.
- `EvmAnchorService` replaces the no-op, with an **anchoring worker** reading `credential_events` and a single writer for the relayer wallet to keep transactions in order.
- **Merkle-batch anchoring:** one transaction per batch (for example every 10 minutes or every 500 credentials). This brings cost per credential to fractions of a cent.
- A **gasless relayer**: institution keys sign, one iGARO wallet pays gas.
- A **backfill job** that anchors every credential issued during the MVP.
- A blockchain event reader, plus an `anchors` cache table. The verify page adds an "Anchored on blockchain ✓" proof with a block-explorer link. The independent CLI checks the chain too.
- Verification falls back gracefully: "Signed ✓, blockchain proof temporarily unavailable". Never a false result.

**Pilot readiness:**
- More roles (Credential Manager, Viewer), two-factor login for admins
- KMS-backed key custody
- Apple Wallet and Google Wallet passes for ID cards
- Custom verification subdomains per institution
- Data-protection tooling (consent records, erasure through salt deletion, export, retention)
- Production monitoring, backups, incident runbook, billing and plan limits

### Phase 2: Standards and scale

- **W3C Verifiable Credentials 2.0** export (the Ed25519 signing maps onto `Ed25519Signature2020` / `eddsa-rdfc-2022` or a JWT-VC)
- **Bitstring Status List** for privacy-preserving status checks that can be verified independently
- `did:web` identifiers for institutions (the published `keys.json` is already most of the way there)
- Signed QR payloads for **offline verification**, plus a verifier mobile app
- Holder accounts and a wallet, selective disclosure, verifier API (a likely revenue line), SSO, SIS/HR integrations, analytics

### Phase 3: Ecosystem (only if the market asks)

- Multi-chain anchoring, ZK proofs or selective disclosure (SD-JWT, BBS+), a cross-institution trust registry
- **Keep off the roadmap:** a native token, NFTs, a DAO.

---

## 9. Process

1. **Write a one-page threat model before coding.** Cover forged cards, a malicious insider editing the DB, a compromised iGARO server, ID enumeration, phishing QR codes, stolen admin accounts and stolen signing keys. Note which threats the MVP covers and which wait for Phase 1 (blockchain).
2. **Record each decision as an ADR** (Architecture Decision Record). The first one: *"Blockchain deferred to Phase 1; Ed25519 institution signatures plus a hash-chained audit log in the MVP; extension points defined."*
3. **Give every module testable acceptance criteria** (Given / When / Then).
4. **Tests:** golden-file tests for canonicalization, hashing and signing (the same input must give byte-identical output forever, because Phase 1 anchoring depends on it); cross-tenant security tests; audit-chain tamper tests; an end-to-end demo-script test.
5. **Sprint plan (about 5 weeks):**
   - **W1:** monorepo, CI, Docker Compose, DB schema + RLS, auth and invites, threat model, ADRs
   - **W2:** institutions, branding, signing keys, holders, photo storage, credential types
   - **W3:** `packages/core` (canonicalize, hash, sign, golden tests), issuance, lifecycle, outbox, hash-chained audit log
   - **W4:** public verification page, proof panel, keys endpoint, signed JSON download, verify CLI, rate limiting
   - **W5:** card rendering (PNG/PDF + QR), holder email and link, CSV bulk import, dashboard metrics, hardening, staging, demo script
6. **Automate the demo script as a test** so the demo never breaks the day before a meeting.

---

## 10. Corrected one-sentence definition

**For the MVP:**
> iGARO is a multi-tenant SaaS platform that lets institutions issue, manage, suspend, revoke and publicly verify digital credentials. Every credential is cryptographically signed by its issuing institution, so anyone can confirm its authenticity and status in seconds by scanning a QR code.

**Product vision (Phase 1 onward):**
> … with institution-signed proofs and status anchored on a public blockchain, so credentials can be verified independently, without having to trust iGARO alone.
