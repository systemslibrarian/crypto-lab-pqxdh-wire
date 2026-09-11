import { expect, test } from '@playwright/test'

import { boot, driveAllStates, NARROW, watchPageErrors } from './gate.js'

test('zero WCAG 2.1 A/AA findings across the real desktop states', async ({ page }) => {
  test.setTimeout(180_000)
  const errors = watchPageErrors(page)
  await boot(page)
  await driveAllStates(page, 'dark desktop')
  expect(errors).toEqual([])
})

test('zero WCAG 2.1 A/AA findings across the real 380px states', async ({ page }) => {
  test.setTimeout(180_000)
  const errors = watchPageErrors(page)
  await page.setViewportSize(NARROW)
  await boot(page)
  await driveAllStates(page, 'dark 380px')
  expect(errors).toEqual([])
})