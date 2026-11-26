import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

// Only tenancy.test.ts touches Postgres; keep files serial anyway so migrations never race on CREATE ROLE.
// The worker's producer entry resolves to dist at runtime; tests use its source so no build is needed first.
export default defineConfig({
  resolve: {
    alias: { '@igaro/worker/producer': fileURLToPath(new URL('../worker/src/producer.ts', import.meta.url)) },
  },
  test: { fileParallelism: false },
});
