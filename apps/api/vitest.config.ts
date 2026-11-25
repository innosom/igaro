import { defineConfig } from 'vitest/config';

// Only tenancy.test.ts touches Postgres; keep files serial anyway so migrations never race on CREATE ROLE.
export default defineConfig({ test: { fileParallelism: false } });
