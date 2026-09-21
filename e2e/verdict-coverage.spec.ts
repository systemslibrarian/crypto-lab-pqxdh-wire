import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { expect, test, type Page } from '@playwright/test'

import { driveEveryState } from './drive-every-state.js'
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
const coveredIds = new Set(mutations.flatMap(([, entry]) => entry.covers))
const SPEC_SOURCE = readFileSync(new URL('./verdicts.spec.ts', import.meta.url), 'utf8')

/**
 * Every state a visitor can reach, scanned as it renders. The marker set, the
 * measurement set and the containment rules are all read off this walk, so the
 * walk itself is the denominator — see e2e/drive-every-state.ts for the rule it
 * follows and the per-control enumeration it owes.
 */
async function driveAndScan(page: Page): Promise<{
  markers: Set<string>
  claims: Set<string>
  violations: VerdictViolation[]
}> {
  const markers = new Set<string>()
  const claims = new Set<string>()
  const violations: VerdictViolation[] = []
  await driveEveryState(page, async (state) => {
    const scan = await scanVerdicts(page, state)
    scan.markers.forEach((marker) => markers.add(marker))
    scan.claims.forEach((claim) => claims.add(claim))
    violations.push(...scan.violations)
  })
  return { markers, claims, violations }
}

test.beforeEach(async ({ page }) => {
  await page.goto('./')
  await expect(page.locator('#app')).not.toBeEmpty()
})

test('check 1: every verdict and every measurement the page renders is covered by a recorded mutation', async ({
  page,
}) => {
  test.setTimeout(180_000)
  const { markers, claims } = await driveAndScan(page)

  expect(markers.size, 'the page must render at least one marked verdict').toBeGreaterThan(0)
  expect(claims.size, 'the page must render at least one marked measurement').toBeGreaterThan(0)

  // data-claim markers are in this loop on the same terms as data-verdict ones.
  // Enforcing the rule over one of the two families is how a newly rendered
  // measurement ships with no mutation and nothing goes red.
  const rendered = new Set([...markers, ...claims])
  const uncovered = [...rendered].filter((id) => !coveredIds.has(id)).sort()
  expect(
    uncovered,
    'markers rendered by the page with no mutation in e2e/verdict-mutations.json',
  ).toEqual([])

  const unrendered = [...coveredIds].filter((id) => !rendered.has(id)).sort()
  expect(
    unrendered,
    'mutations claiming to cover a marker this page never renders',
  ).toEqual([])
})

test('check 1b: every covered marker is asserted through the text-and-state helper', async () => {
  // A spec that merely MENTIONS `data-verdict="<id>"` is not asserting anything,
  // and says nothing at all about state. Every mutation-covered id has to go
  // through expectVerdict/expectClaim, which refuse a text-only claim — so a
  // kill recorded here cannot be a mutation that flipped the words while the
  // marker went on painting pass.
  const missing = [...coveredIds]
    .filter(
      (id) =>
        !SPEC_SOURCE.includes(`expectVerdict(page, '${id}'`) &&
        !SPEC_SOURCE.includes(`expectClaim(page, '${id}'`),
    )
    .sort()
  expect(
    missing,
    'ids with a recorded mutation that no expectVerdict/expectClaim call in verdicts.spec.ts asserts',
  ).toEqual([])
})

test('check 2: no verdict word, verdict styling or measurement renders outside a marker', async ({
  page,
}) => {
  test.setTimeout(180_000)
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

test('check 2 fails the careless builder: a raw unmarked banner and a raw unmarked number are caught', async ({
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

  // The same injection with a number instead of a word. A measurement painted
  // into a result region carries no verdict word and no verdict styling, so
  // neither rule above sees it — which is why the third rule exists.
  await page.evaluate(() => {
    const row = document.createElement('div')
    row.id = 'careless-metric'
    row.innerHTML = '<dt>Wire cost</dt><dd>1,632 B</dd>'
    document.querySelector('#message-panel .message-metrics')?.append(row)
    document.querySelector<HTMLElement>('#message-panel')!.hidden = false
  })

  const numeric = await scanVerdicts(page, 'raw unmarked measurement')
  expect(
    numeric.violations.some((violation) => violation.kind === 'measurement'),
    'a digit-plus-unit measurement outside a marker must be reported',
  ).toBe(true)
  expect(numeric.violations.map((violation) => violation.detail)).toEqual(
    expect.arrayContaining(['1,632 B']),
  )

  await page.evaluate(() => {
    document.querySelector('#careless-metric')?.remove()
    document.querySelector<HTMLElement>('#message-panel')!.hidden = true
  })
  const settled = await scanVerdicts(page, 'after measurement removal')
  expect(settled.violations, 'removing the metric must clear the finding').toEqual([])
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
