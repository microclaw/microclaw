import { defineConfig, devices } from '@playwright/test'

// Browser smoke tests for the embedded Web UI. Every worker boots its own
// `microclaw start` (web channel only) from the built binary, so the tests
// exercise the exact bundle that ships inside the binary rather than a Vite
// dev server. See fixtures/microclaw-server.ts for how the server is started.
export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: !!process.env.CI,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: process.env.CI ? [['list'], ['github']] : [['list']],
  use: {
    ...devices['Desktop Chrome'],
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'chromium' }],
})
