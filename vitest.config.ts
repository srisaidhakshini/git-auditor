import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    globals: false,
    environment: 'node',
    // Integration tests can be slow (gitleaks scan)
    testTimeout: 60_000,
    hookTimeout: 10_000,
  },
});
