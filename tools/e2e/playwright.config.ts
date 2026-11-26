import { defineConfig } from '@playwright/test';

// The demo script drives an already running stack (web, API, worker, Postgres, MinIO, Mailpit); see README.md.
// It is one ordered story, so: one worker, no parallelism, no retries (a retry would repeat side effects).
export default defineConfig({
  testDir: './tests',
  testMatch: /.*\.spec\.ts/,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 5 * 60_000,
  expect: { timeout: 15_000 },
  reporter: [['list']],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? 'http://127.0.0.1:3000',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    // Traces and screenshots can contain tokens in URLs; they stay local (test-results/ is git-ignored). Never upload them as CI artefacts.
  },
});
