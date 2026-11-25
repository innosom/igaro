# ADR 0013: igaro.credential.v1 encoding details

Status: Accepted (recommended option taken under the owner's standing permission)

The white paper fixes the payload fields but not these encodings. Chosen (strictest, privacy-preserving):

- `dataHash` is lowercase hex SHA-256 of the UTF-8 JCS string; the signed message is `"igaro.credential.sig.v1:" + dataHash` (hex text); signature is base64url (86 chars, no padding).
- `holder.externalId` and `expiresAt` are always present, `null` when absent (no omitted keys), so the shape is fixed.
- `attributes` values are strings only; unknown fields are rejected at issuance and verification.
- Timestamps are `YYYY-MM-DDTHH:MM:SSZ` and must round-trip (no Feb 30, no T24). UUIDs lowercase only.
- Strings with lone surrogates are refused (RFC 8785 requires I-JSON); sparse arrays refused.
- Sign/verify refuse non-Ed25519 keys. No Unicode normalization in core: issuance/import must NFC-normalize input before building the payload (follow-up for T-025/T-044).
- Verification callers must look the key up by (institution, `payload.issuerKeyId`) and check `payload.institutionId` (follow-up for T-031/T-032/T-034).

Golden values in `packages/core/src/credential.test.ts` are frozen; any change needs a new `schemaVersion`.
