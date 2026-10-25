import { test, expect } from '../fixtures/test'
import { E2E_PASSWORD } from '../fixtures/microclaw-server'
import type { Page } from '@playwright/test'

// Regression guard for issue #517: a dependency drift inside @assistant-ui made
// the composer throw "Maximum update depth exceeded" on the very first
// keystroke, and shipped in three releases because nothing ever typed into the
// real bundle. These tests drive the embedded Web UI served by the built
// microclaw binary with a real browser.

const COMPOSER_PLACEHOLDER = 'Message MicroClaw...'

async function signIn(page: Page): Promise<void> {
  await page.goto('/')
  const dialog = page.getByRole('dialog', { name: 'Sign In' })
  await expect(dialog).toBeVisible()
  await dialog.getByPlaceholder('********').fill(E2E_PASSWORD)
  await dialog.getByRole('button', { name: 'Sign In' }).click()
  await expect(dialog).toBeHidden()
  await expect(page.getByPlaceholder(COMPOSER_PLACEHOLDER)).toBeVisible()
}

async function typeIntoComposer(page: Page, text: string) {
  const composer = page.getByPlaceholder(COMPOSER_PLACEHOLDER)
  await composer.click()
  // pressSequentially fires one input/onChange per character, which is the
  // path that looped in #517 (fill() would only dispatch a single event).
  await composer.pressSequentially(text, { delay: 20 })
  await expect(composer).toHaveValue(text)
  return composer
}

test('typing and sending in the composer does not crash the page', async ({ page, errors }) => {
  await signIn(page)
  expect(errors.pageErrors, 'page errors after sign-in').toEqual([])

  const composer = await typeIntoComposer(page, 'hello from e2e')
  expect(errors.pageErrors, 'page errors while typing').toEqual([])
  expect(errors.consoleErrors, 'console errors while typing').toEqual([])

  const sendRequest = page.waitForRequest(
    (req) => req.method() === 'POST' && new URL(req.url()).pathname === '/api/send_stream',
    { timeout: 10_000 },
  )
  await composer.press('Enter')
  const request = await sendRequest
  expect(request.postDataJSON()).toMatchObject({ message: 'hello from e2e' })

  // The echo of our own message must render; the assistant turn will fail at
  // the provider (placeholder API key) and that failure must stay inside the
  // UI's error handling rather than crashing the page.
  await expect(page.getByText('hello from e2e', { exact: true }).first()).toBeVisible()
  await expect(composer).toHaveValue('')
  await page.waitForTimeout(1_500)
  expect(errors.pageErrors, 'page errors after send').toEqual([])
  expect(errors.consoleErrors, 'console errors after send').toEqual([])
})

test('composer still works after reloading with rendered history', async ({ page, errors }) => {
  await signIn(page)
  const first = await typeIntoComposer(page, 'first message')
  const firstSend = page.waitForRequest(
    (req) => req.method() === 'POST' && new URL(req.url()).pathname === '/api/send_stream',
  )
  await first.press('Enter')
  await firstSend
  await expect(page.getByText('first message', { exact: true }).first()).toBeVisible()

  // Session cookie survives the reload, so we land directly on the thread with
  // the stored history rendered — a different mount path than the empty thread.
  await page.reload()
  await expect(page.getByRole('dialog', { name: 'Sign In' })).toBeHidden()
  await expect(page.getByPlaceholder(COMPOSER_PLACEHOLDER)).toBeVisible()
  await expect(page.getByText('first message', { exact: true }).first()).toBeVisible()

  await typeIntoComposer(page, 'second message')
  expect(errors.pageErrors, 'page errors after reload + typing').toEqual([])
  expect(errors.consoleErrors, 'console errors after reload + typing').toEqual([])
})
