# ADR 0042: Local S3 storage is Versity S3 Gateway (T-056)

Status: accepted (recommended option taken under the owner's standing permission)

## Context
`minio/minio` and `minio/mc` can no longer be pulled, so `docker compose up` failed. The app only needs
path-style S3 (PUT/GET/presign) against a private bucket (`apps/api/src/storage.ts`).

## Decision
Use `versity/versitygw` pinned to an exact tag (`v1.0.18`), POSIX backend, same access/secret env vars and
port 9000 (container 7070), so app configuration is unchanged. The bucket is a top-level directory of the
data volume, created by a one-shot `busybox` container (`s3-init`), so neither `minio` nor `mc` is needed.
The bucket is private (no anonymous policy exists in the gateway). There is no console.

## Consequences
- `S3_CONSOLE_PORT` removed. Volume renamed `miniodata` to `s3data`; reset with `docker compose down -v`.
- Production is unaffected: any S3-compatible store works.
- The image tag and the gateway flags were NOT verified by pulling in the unattended run (Docker pulls were not
  permitted). A human must run `docker compose up -d` once and check card render, photo upload and the holder
  card proxy before relying on this.
