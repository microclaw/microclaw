import { test as base, expect, type ConsoleMessage, type Page } from '@playwright/test'
import { startMicroclaw, type MicroclawServer } from './microclaw-server'

export interface BrowserErrors {
  /** Uncaught exceptions thrown in the page (`pageerror`). */
  pageErrors: string[]
  /** `console.error(...)` output. */
  consoleErrors: string[]
}

type Fixtures = {
  errors: BrowserErrors
}

type WorkerFixtures = {
  microclaw: MicroclawServer
}

export const test = base.extend<Fixtures, WorkerFixtures>({
  // One server per worker: booting the binary costs a second or two, and the
  // tests each use their own session key so they do not interfere.
  microclaw: [
    async ({}, use) => {
      const server = await startMicroclaw()
      try {
        await use(server)
      } finally {
        await server.stop()
      }
    },
    { scope: 'worker' },
  ],

  baseURL: async ({ microclaw }, use) => {
    await use(microclaw.baseURL)
  },

  // Collect every browser-side error for the duration of the test. The spec
  // asserts these are empty: a React "Maximum update depth exceeded" surfaces
  // here as a pageerror (and usually a console.error as well).
  errors: async ({ page }, use, testInfo) => {
    const errors: BrowserErrors = { pageErrors: [], consoleErrors: [] }
    attachErrorCollectors(page, errors)
    await use(errors)
    if (testInfo.status !== testInfo.expectedStatus) {
      await testInfo.attach('browser-errors.json', {
        body: JSON.stringify(errors, null, 2),
        contentType: 'application/json',
      })
    }
  },
})

export function attachErrorCollectors(page: Page, errors: BrowserErrors): void {
  page.on('pageerror', (err) => {
    errors.pageErrors.push(err.stack || err.message)
  })
  page.on('console', (msg: ConsoleMessage) => {
    if (msg.type() === 'error') {
      errors.consoleErrors.push(msg.text())
    }
  })
}

export { expect }
