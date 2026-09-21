import { defineConfig } from '@playwright/test'

const baseURL = 'http://localhost:4700/crypto-lab-pqxdh-wire/'

export default defineConfig({
  testDir: './e2e',
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
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