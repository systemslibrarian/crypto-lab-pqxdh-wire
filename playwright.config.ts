import { defineConfig } from '@playwright/test'

const baseURL = 'http://localhost:4700/crypto-lab-pqxdh-wire/'

export default defineConfig({
  testDir: './e2e',
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  // e2e/global-setup.ts mints the run id and truncates the observation sink;
  // e2e/global-teardown.ts reads it back and fails the run when a recorded kill
  // in e2e/verdict-mutations.json never executed. The teardown runs whatever the
  // tests did, which a project with `dependencies:` would not — a dependent
  // project is SKIPPED when its dependency fails, and a run with a mutation
  // applied is exactly where that answer matters.
  globalSetup: './e2e/global-setup.ts',
  globalTeardown: './e2e/global-teardown.ts',
  // Not the default `test-results`: Playwright wipes outputDir when the run
  // starts, which would race the truncation above. The sink lives beside it at
  // test-results/verdict-observations.ndjson.
  outputDir: 'test-results/artifacts',
  use: {
    baseURL,
    colorScheme: 'dark',
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'npm run build && npm run preview -- --port 4700 --strictPort',
    url: baseURL,
    reuseExistingServer: !process.env.CI,
  },
})