import AxeBuilder from '@axe-core/playwright'
import { expect, type Page } from '@playwright/test'

import { auditContrast, formatContrastFailures } from './contrast.js'
import { auditNonText } from './nontext.js'
import { NONTEXT_BASELINE } from './nontext-baseline.js'

export const NARROW = { width: 380, height: 800 }
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']

export function watchPageErrors(page: Page): string[] {
  const errors: string[] = []
  page.on('pageerror', (error) => errors.push(error.message))
  return errors
}

export async function boot(page: Page): Promise<void> {
  await page.emulateMedia({ reducedMotion: 'reduce', colorScheme: 'dark' })
  await page.goto('./')
  await expect(page.locator('#app')).not.toBeEmpty()
  await expect(page.locator('h1')).toHaveCount(1)
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
  await expect(page.locator('[aria-label*="theme" i]')).toHaveCount(0)
  expect(await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches)).toBe(true)
}

export async function scan(page: Page, label: string): Promise<void> {
  await expect(page.locator('.cl-hero-title')).toBeVisible()
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze()
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze()
  const violations = [...wcag.violations, ...landmarks.violations].map((violation) => ({
    state: label,
    id: violation.id,
    nodes: violation.nodes.map((node) => node.target.join(' ')).slice(0, 8),
  }))
  expect(violations, `axe violations in ${label}`).toEqual([])

  const incomplete = [...wcag.incomplete, ...landmarks.incomplete]
    .filter((result) => result.id !== 'color-contrast')
    .map((result) => ({ state: label, id: result.id, nodes: result.nodes.map((node) => node.target.join(' ')).slice(0, 8) }))
  expect(incomplete, `unexplained axe incomplete results in ${label}`).toEqual([])

  const contrast = [...new Set(formatContrastFailures(await auditContrast(page)))]
  expect(contrast, `measured text contrast in ${label}`).toEqual([])
  const hiddenContrast = [...new Set(formatContrastFailures(await auditContrast(page, '[aria-hidden="true"], [aria-hidden="true"] *', true)))]
  expect(hiddenContrast, `measured aria-hidden contrast in ${label}`).toEqual([])

  const nonText = await auditNonText(page)
  expect(Object.keys(NONTEXT_BASELINE), 'non-text baseline must remain empty').toEqual([])
  expect(nonText, `non-text contrast in ${label}`).toEqual([])

  const scrollers = await page.locator('*').evaluateAll((elements) =>
    elements
      .filter((element) => /auto|scroll/.test(getComputedStyle(element).overflowX + getComputedStyle(element).overflowY))
      .filter((element) => element.scrollWidth > element.clientWidth || element.scrollHeight > element.clientHeight)
      .map((element) => ({ tag: element.tagName, tabindex: element.getAttribute('tabindex'), name: element.getAttribute('aria-label'), role: element.getAttribute('role') })),
  )
  expect(scrollers.filter((item) => item.tabindex !== '0' || !item.name || !item.role), `unreachable scrollers in ${label}`).toEqual([])

  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
  expect(overflow, `horizontal page overflow in ${label}`).toBeLessThanOrEqual(1)
}

export async function driveAllStates(page: Page, prefix: string): Promise<void> {
  const scanAt = (state: string) => scan(page, `${prefix} / ${state}`)
  await expect(page.locator('#bundle-panel')).toBeHidden()
  await expect(page.locator('#comparison-panel')).toBeHidden()
  await scanAt('arrival with disclosures and derived output hidden')

  await page.keyboard.press('Tab')
  await expect(page.locator('.skip-link')).toBeFocused()
  await scanAt('skip link focused')

  for (const expected of [
    'BUNDLE PUBLISHED',
    'ALICE COMPLETE',
    'MESSAGE SENT',
    'BOB COMPLETE',
    'MATCH',
  ]) {
    await page.locator('#step-button').click()
    await expect(page.locator('#protocol-status')).toContainText(expected)
    await scanAt(expected.toLowerCase())
  }

  await page.locator('#quantum-toggle').check()
  await expect(page.locator('#recompute-panel')).toContainText('SK = NOT DERIVED')
  await scanAt('curve break model with SS opaque')

  await page.locator('#lattice-toggle').check()
  await expect(page.locator('#recompute-panel')).toContainText('SK OPENED')
  await scanAt('curve and lattice break model')

  await page.locator('#bad-signature-button').click()
  await expect(page.locator('#bad-signature-output')).toContainText('signature verification failed')
  await scanAt('bad prekey signature rejected')

  await page.locator('#tamper-button').click()
  await expect(page.locator('#tamper-output')).toContainText('REJECTED AT FIRST AEAD')
  await scanAt('tampered KEM ciphertext rejected at AEAD')

  await page.locator('#reuse-toggle').check()
  await expect(page.locator('#reuse-output')).toContainText('SAME PQ KEY ID')
  await scanAt('last-resort KEM public key reused')

  await page.locator('#impersonate-button').click()
  await expect(page.locator('#impersonate-output')).toContainText('IMPERSONATED')
  await scanAt('classically authenticated impersonation fixture')

  await page.locator('#ratchet-button').click()
  await expect(page.locator('#ratchet-output')).toContainText('STILL READ')
  await scanAt('reduced ratchet followed by curve break model')

  for (const summary of await page.locator('summary').all()) {
    await summary.click()
  }
  await scanAt('all progressive disclosures opened through controls')

  await page.locator('#reset-button').click()
  await expect(page.locator('#comparison-panel')).toBeHidden()
  await expect(page.locator('#protocol-status')).toContainText('READY')
  await scanAt('fresh reset retires prior handshake')
}