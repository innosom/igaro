# ADR 0036: Verified page shows the signed credential type code

Status: accepted (recommended option taken under the owner's standing permission). Source: T-049 review finding H1.

## Context
`credential_types.name` is editable and outside the signed payload, yet the VERIFIED page displayed it. A rename
(or a DB edit) changed what a VERIFIED credential appeared to be without failing verification.

## Decision
- `GET /verify/:token` returns `type.code` and `type.name` both set to the signed `payload.credentialType`; `kind` stays informational.
- `PATCH /credential-types/:id` refuses to rename a type that has credentials (409 `TYPE_HAS_CREDENTIALS`).
- Adding the display name to the payload would need a new `schemaVersion`; deferred.
- The private holder page (not a verification result) still shows the type name; the rename block protects it.
