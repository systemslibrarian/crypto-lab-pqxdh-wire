import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { expect, test, type Page } from '@playwright/test'

import { scanVerdicts, type VerdictViolation } from './verdict-scan.js'

interface MutationEntry {
  file: string
  find: string
  replace: string
  covers: string[]
  why: string
}

const repoRoot = fileURLToPath(new URL('../', import.meta.url))
const registry = JSON.parse(
  readFileSync(new URL('./verdict-mutations.json', import.meta.url), 'utf8'),
) as { mutations: Record<string, MutationEntry> }

const mutations = Object.entries(registry.mutations)
const coveredMarkers = new Set(mutations.flatMap(([, entry]) => entry.covers))

/**
 * Every state a visitor can reach, scanned as it renders. The marker set and the
 * containment rule are both read off this, so a verdict that only appears after
 * a button press is still covered.
 */
async function driveAndScan(page: Page): Promise<{
  markers: Set<string>
  violations: VerdictViolation[]
}> {
  const markers = new Set<string>()
  const violations: VerdictViolation[] = []
  const at = async (state: string) => {
    const scan = await scanVerdicts(page, state)
    scan.markers.forEach((marker) => markers.add(marker))
    violations.push(...scan.violations)
  }

  await at('arrival')

  for (const expected of [
    'BUNDLE PUBLISHED',
    'ALICE COMPLETE',
    'MESSAGE SENT',
    'BOB COMPLETE',
    'MATCH',
  ]) {
    await page.locator('#step-button').click()
    await expect(page.locator('#protocol-status')).toContainText(expected)
    await at(expected.toLowerCase())
  }

  await page.locator('#quantum-toggle').check()
  await expect(page.locator('#recompute-panel')).toContainText('SK = NOT DERIVED')
  await at('curve break')

  await page.locator('#lattice-toggle').check()
  await expect(page.locator('#recompute-panel')).toContainText('SK OPENED')
  await at('curve and lattice break')

  await page.locator('#bad-signature-button').click()
  await expect(page.locator('#bad-signature-output')).toContainText('ABORT')
  await at('bad prekey signature')

  await page.locator('#tamper-button').click()
  await expect(page.locator('#tamper-output')).toContainText('REJECTED')
  await at('tampered KEM ciphertext')

  await page.locator('#reuse-toggle').check()
  await expect(page.locator('#reuse-output')).toContainText('PQ KEY ID')
  await at('last-resort reuse')

  await page.locator('#impersonate-button').click()
  await expect(page.locator('#impersonate-output')).toContainText('IMPERSONATED')
  await at('impersonation fixture')

  await page.locator('#ratchet-button').click()
  await expect(page.locator('#ratchet-output')).toContainText('HEALED')
  await at('reduced ratchet under curve break')

  for (const summary of await page.locator('summary').all()) await summary.click()
  await at('all disclosures open')

  await page.locator('#reset-button').click()
  await expect(page.locator('#protocol-status')).toContainText('READY')
  await at('after reset')

  return { markers, violations }
}

test.beforeEach(async ({ page }) => {
  await page.goto('./')
  await expect(page.locator('#app')).not.toBeEmpty()
})

test('check 1: every verdict the page renders is covered by a recorded mutation', async ({
  page,
}) => {
  test.setTimeout(120_000)
  const { markers } = await driveAndScan(page)

  expect(markers.size, 'the page must render at least one marked verdict').toBeGreaterThan(0)

  const uncovered = [...markers].filter((marker) => !coveredMarkers.has(marker)).sort()
  expect(
    uncovered,
    'markers rendered by the page with no mutation in e2e/verdict-mutations.json',
  ).toEqual([])

  const unrendered = [...coveredMarkers].filter((marker) => !markers.has(marker)).sort()
  expect(
    unrendered,
    'mutations claiming to cover a marker this page never renders',
  ).toEqual([])
})

test('check 2: no verdict word or verdict styling renders outside a marker', async ({
  page,
}) => {
  test.setTimeout(120_000)
  const { violations } = await driveAndScan(page)
  const unique = [
    ...new Map(
      violations.map((violation) => [
        `${violation.kind}:${violation.detail}:${violation.where}`,
        violation,
      ]),
    ).values(),
  ]
  expect(unique, 'outcomes rendered outside any data-verdict marker').toEqual([])
})

test('check 2 fails the careless builder: a raw unmarked banner is caught', async ({
  page,
}) => {
  // The uncovered-verdict test adds the banner the way someone would who was not
  // thinking about this lane at all: shouty, styled, and unmarked. If the scanner
  // stays quiet here it is not enforcing anything and check 2 above is decoration.
  const clean = await scanVerdicts(page, 'before injection')
  expect(clean.violations, 'baseline must be clean before the injection').toEqual([])

  await page.evaluate(() => {
    const banner = document.createElement('div')
    banner.id = 'careless-banner'
    banner.className = 'verdict verdict-pass'
    banner.innerHTML = '<strong>ALL CHECKS PASSED — SESSION VERIFIED</strong>'
    document.querySelector('.shell')?.prepend(banner)
  })

  const dirty = await scanVerdicts(page, 'raw unmarked banner')
  expect(dirty.violations.some((violation) => violation.kind === 'styling')).toBe(true)
  expect(dirty.violations.some((violation) => violation.kind === 'word')).toBe(true)
  expect(
    dirty.violations.map((violation) => violation.detail),
    'the injected banner must be reported by both rules',
  ).toEqual(expect.arrayContaining(['PASSED', 'VERIFIED']))

  await page.evaluate(() => document.querySelector('#careless-banner')?.remove())
  const restored = await scanVerdicts(page, 'after removal')
  expect(restored.violations, 'removing the banner must clear the finding').toEqual([])
})

test('every recorded mutation still applies to the source it names', async () => {
  // A mutation whose `find` no longer matches guards nothing, and would let a
  // marker drift back to a canned value with this gate still green.
  const rotted: string[] = []
  for (const [id, entry] of mutations) {
    const source = readFileSync(new URL(entry.file, `file://${repoRoot}`), 'utf8')
    const occurrences = source.split(entry.find).length - 1
    if (occurrences !== 1) rotted.push(`${id}: ${entry.file} matched ${occurrences}x, want 1`)
    if (!entry.covers.length) rotted.push(`${id}: covers no marker`)
  }
  expect(rotted, 'mutations in e2e/verdict-mutations.json that no longer apply').toEqual([])
})
