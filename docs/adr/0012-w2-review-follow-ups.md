# ADR 0012: W2 review follow-ups and decisions

Status: accepted (recommended option taken under the owner's standing permission)

Source: T-021 W2 security review (0 Critical, 0 High, 3 Medium, 10 Low).

## Decisions
1. **Holder photo vs issued credentials (M1).** Safest option taken: at issuance (T-025) the
   credential row snapshots the holder's `photo_key`/`photo_sha256`, and photo objects referenced by an
   issued credential are never deleted. Replacing a holder photo creates a new object only. Verification
   (T-031/T-032) shows a photo only if SHA-256 of the fetched bytes equals `payload.holder.photoSha256`,
   otherwise no photo plus a warning. QA adds a photo-swap tamper test (T-029/T-037).
2. **JPEG cleaner (M2).** Move to a strict allow-list (DQT, DHT, DAC, DRI, DNL, one SOF, SOS, allowed APPn);
   reject reserved/JPGn/extension markers. Owner igaro-api, before T-025.
3. **Key compromise (M3).** Require password re-entry for `/institution/keys/:kid/compromise`, rate-limit
   rotate/compromise per institution, audit both in the same transaction (T-024). No MFA (out of scope).
4. **Suspended institutions (L4).** Admins of a SUSPENDED institution may read but not issue, rotate keys or
   upload; enforce before T-025.

## Tracked Low items
L1 reuse CONTROL_RE for name fields; L2 `retired_at` only on non-ACTIVE keys; L3 bind institution_id and
algorithm in key envelope AAD under a new prefix; L5 platform-admin compromise endpoint (deferred, not
MVP-blocking); L6 PNG bit-depth/ICC checks, renderer treats images as untrusted; L7 upload/rotation rate
limits; L8 fix `db.ts` platform-scope comment; L9 least-privilege S3 credential in production docs;
L10 reasons only in logs until T-024.
