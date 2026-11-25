# ADR 0003: Client IPs are hashed in every log; proxy trust is configured, never assumed

Status: Accepted (owner decision on PR #9, 2026-11-25)

## Context
The white paper requires hashed IPs for verification-check logs only. The T-008 API scaffold logged raw client IPs in its
general access logs, including on the public verification routes. The API also hard-coded `trustProxy: false`, so behind
a load balancer every client would appear to have the proxy's IP. That would break the per-IP rate limits in T-010 and T-032.

## Decision
1. **No raw client IP in any log.** Every access-log line carries `ipHash = HMAC-SHA256(IP_HASH_KEY, ip)`, truncated to
   128 bits in hex, and never `remoteAddress`. Verification logs (T-032, `verification_logs.ip_hash`) use the same function
   (`hashIp` in `apps/api/src/logging.ts`, to move to `packages/core` later) and the same key, so abuse can be correlated
   across the two. `IP_HASH_KEY` is at least 32 random bytes, base64-encoded, held outside the database like `MASTER_KEY`,
   and required in production. In development and tests it defaults to a random key per process.
2. **`TRUST_PROXY` env var:** `false` (the default: clients connect directly), a hop count from 1 to 10, or a
   comma-separated list of trusted proxy IPs/CIDRs. `true` (trust anyone) is refused, because it would let any client
   spoof `X-Forwarded-For` and evade rate limits. The real deployment topology is set at staging (T-047).

## Consequences
- Logs contain no raw IPs of verifiers or admins. Per-IP rate limiting still works on the real IP in memory.
- Without the key, a hashed IP can't be reversed. Rotating `IP_HASH_KEY` breaks correlation with older logs.
- A misconfigured `TRUST_PROXY` on staging would make every client share the proxy's rate-limit bucket. T-047 must set it.
