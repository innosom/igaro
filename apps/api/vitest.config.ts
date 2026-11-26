import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

// Only tenancy.test.ts touches Postgres; keep files serial anyway so migrations never race on CREATE ROLE.
// The worker's entries resolve to dist at runtime; tests use its source so no build is needed first.
// (The import end-to-end test drives the real worker consumer, `@igaro/worker`, against this API: T-044.)
export default defineConfig({
  resolve: {
    alias: [
      { find: '@igaro/worker/producer', replacement: fileURLToPath(new URL('../worker/src/producer.ts', import.meta.url)) },
      { find: /^@igaro\/worker$/, replacement: fileURLToPath(new URL('../worker/src/index.ts', import.meta.url)) },
    ],
  },
  test: { fileParallelism: false },
});
