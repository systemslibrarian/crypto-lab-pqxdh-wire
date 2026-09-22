import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { expect, test, type Page } from '@playwright/test'

import { driveEveryState } from './drive-every-state.js'
import { scanVerdicts, type VerdictViolation } from './verdict-scan.js'

interface MutationEntry {
  file: string
  find: string
  replace: string
  /** marker id -> the test title and the exact claim that kills it. */
  kills: Record<string, { test: string; claim: Record<string, unknown> }>
  why: string
}

const repoRoot = fileURLToPath(new URL('../', import.meta.url))
const registry = JSON.parse(
  readFileSync(new URL('./verdict-mutations.json', import.meta.url), 'utf8'),
) as { mutations: Record<string, MutationEntry> }

const mutations = Object.entries(registry.mutations)
// The covered set IS the set of recorded kills. `covers: [...]` used to sit
// beside them as a second list, which could disagree with the first.
const coveredIds = new Set(mutations.flatMap(([, entry]) => Object.keys(entry.kills ?? {})))

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

// check 1b — "every covered marker is asserted through the text-and-state
// helper" — used to live here as a scan of verdicts.spec.ts's own SOURCE for
// the substring `expectVerdict(page, '<id>'`. It is gone, not weakened: a
// mention is not an assertion, which is the very defect Fix 1 was written to
// close, and auditors across this lane defeated the source form three ways —
// commenting the call out, keeping it but feeding it values read off the page,
// and satisfying a file-granular rule from an unrelated line elsewhere in the
// file. The question is now asked of what RAN: expectVerdict/expectClaim record
// every (test, marker, claim) they execute, and e2e/global-teardown.ts requires
// every kill recorded in verdict-mutations.json to appear in that record.
// See e2e/observations.ts.

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

  // A bare state hook: no verdict word, no verdict class, no number — just an
  // attribute a stylesheet paints an outcome from. `#comparison-panel` carried
  // exactly this shape (`data-outcome`) outside every marker until this pass,
  // and the scan could not see it. It is in VERDICT_STYLE_SELECTOR now, and this
  // is the assertion that says so.
  await page.evaluate(() => {
    const hook = document.createElement('div')
    hook.id = 'careless-hook'
    hook.dataset.outcome = 'pass'
    hook.textContent = 'Comparison'
    document.querySelector('.shell')?.prepend(hook)
  })
  const hooked = await scanVerdicts(page, 'raw unmarked state hook')
  expect(
    hooked.violations.some(
      (violation) => violation.kind === 'styling' && violation.detail === 'div#careless-hook',
    ),
    'a state hook painting an outcome outside a marker must be reported',
  ).toBe(true)

  await page.evaluate(() => document.querySelector('#careless-hook')?.remove())
  const cleared = await scanVerdicts(page, 'after state hook removal')
  expect(cleared.violations, 'removing the state hook must clear the finding').toEqual([])
})

test('every recorded mutation still applies to the source it names', async () => {
  // A mutation whose `find` no longer matches guards nothing, and would let a
  // marker drift back to a canned value with this gate still green.
  const rotted: string[] = []
  for (const [id, entry] of mutations) {
    const source = readFileSync(new URL(entry.file, `file://${repoRoot}`), 'utf8')
    const occurrences = source.split(entry.find).length - 1
    if (occurrences !== 1) rotted.push(`${id}: ${entry.file} matched ${occurrences}x, want 1`)
    if (!Object.keys(entry.kills ?? {}).length) rotted.push(`${id}: records no kill`)
  }
  expect(rotted, 'mutations in e2e/verdict-mutations.json that no longer apply').toEqual([])
})
