Fixed test vectors for igaro-verify. They reuse the igaro.credential.v1 golden vector from
`packages/core/src/credential.test.ts` (RFC 8032 test-1 key, a public test key; the salt is a fixed test value, not a secret).
These bytes must never change; a new schemaVersion gets new fixtures.

    pnpm --filter @igaro/verify-cli build
    node --conditions=igaro-dist tools/verify-cli/dist/bin.js tools/verify-cli/fixtures/golden-credential.json \
      --keys tools/verify-cli/fixtures/golden-keys.json --now 2027-01-01T00:00:00Z
