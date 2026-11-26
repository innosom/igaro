# ADR 0024: verify-cli offline trust model

Status: accepted (recommended option taken under the owner's standing permission)

- Offline result is VALID (not VERIFIED); revocation/suspension are reported "not checked".
- Keys fetched from the credential's origin are flagged same-origin; `--keys` pins keys.
- https only (http for loopback), no redirects, 10 s timeout, 1 MiB cap; tokens never printed.
- Core rejects non-canonical base64url signature encodings. Golden bytes unchanged.
- `@igaro/core` has an `igaro-dist` export condition so the built CLI runs under plain Node.
