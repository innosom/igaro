import { defineConfig } from 'vitest/config';

// DB test files each apply every migration into their own scratch schema, and the migration
// creates the cluster-global role igaro_app (check-then-create). Run files one at a time so two
// files never race on CREATE ROLE.
export default defineConfig({
  test: { fileParallelism: false },
});
