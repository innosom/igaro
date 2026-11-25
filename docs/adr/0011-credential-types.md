# ADR 0011: Credential types and templates (T-019)

Status: accepted. Every choice below is the recommended option, taken under the owner's standing permission.

## Decisions
1. **`code` and `kind` are immutable**, enforced by the API (unknown property) and by the DB column grants. Issued credentials reference the type; renaming its code would change what the public page and payloads say.
2. **Attributes are editable at any time.** Signed payloads carry their own attribute values, so edits cannot alter issued credentials. Issuance (T-025) validates against the current list and should re-validate stored schemas with `parseAttributes`.
3. **Templates are built-in constants** (`STUDENT_ID`, `CERTIFICATE`, same as the seed) exposed at `GET /credential-types/templates`. `POST` with `template` copies one into an ordinary editable type; the choice is explicit, nothing is auto-created.
4. **Strict attribute keys**: camelCase letters and digits, max 50 chars, unique, max 30 per type; `Object.prototype` names reserved. Types limited to string, date, number.
5. **Names and labels reject control, bidi and other format characters** (C0, C1, `\p{Cf}`) so they cannot be spoofed on public pages or cards.
6. **Delete only when unused**: row lock + count, FK RESTRICT as backstop (409 `TYPE_HAS_CREDENTIALS`). Credentials are never deleted.
7. **Audit**: create/update/delete are logged (ids, code, field names only) with `TODO(T-024)` to write audit_logs in the same transaction.
