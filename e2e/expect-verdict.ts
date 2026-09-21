import { expect, type Locator, type Page } from '@playwright/test'

/**
 * A marker's text and its state are ONE claim.
 *
 * Every recorded mutation used to be validated by `toContainText` alone, so a
 * mutation that flipped the words while leaving `data-result="pass"` styling in
 * place was recorded as a kill and the marker went on claiming pass in every
 * way a reader can see except the sentence. `expectVerdict` asserts both in a
 * single call and REFUSES a claim that carries only one of them, so the weak
 * shape cannot be written by accident.
 *
 * verdict-coverage.spec.ts then requires every mutation-covered marker to be
 * asserted through this helper — a mention of `data-verdict="<id>"` in the spec
 * source is not an assertion and never was.
 */
export interface VerdictClaim {
  /** Assert against this descendant of the marker rather than the marker itself. */
  within?: string
  /** Assert text against this descendant of `within` (the state stays on `within`). */
  label?: string
  text?: string
  contains?: string | readonly string[]
  absent?: string | readonly string[]
  /** `data-result` on the marker (or on `within`). */
  result?: string
  /** `data-state` on the marker (or on `within`). */
  state?: string
  /** Class list of the marker (or of `within`). */
  klass?: RegExp
}

const list = (value: string | readonly string[] | undefined): readonly string[] =>
  value === undefined ? [] : typeof value === 'string' ? [value] : value

function scopeFor(marker: Locator, claim: VerdictClaim): { state: Locator; text: Locator } {
  const state = claim.within ? marker.locator(claim.within) : marker
  return { state, text: claim.label ? state.locator(claim.label) : state }
}

export async function expectVerdict(
  page: Page,
  id: string,
  ...claims: readonly VerdictClaim[]
): Promise<void> {
  const marker = page.locator(`[data-verdict="${id}"]`)
  await expect(marker, `the page must render exactly one [data-verdict="${id}"]`).toHaveCount(1)
  expect(claims.length, `expectVerdict('${id}') was called with no claim`).toBeGreaterThan(0)

  for (const claim of claims) {
    const saysSomething = claim.text !== undefined || claim.contains !== undefined
    const showsState =
      claim.result !== undefined || claim.state !== undefined || claim.klass !== undefined
    expect(
      saysSomething && showsState,
      `expectVerdict('${id}') needs the rendered text AND the rendered state in the same claim; ` +
        'a text-only assertion cannot fail a mutation that leaves the styling saying pass',
    ).toBe(true)

    const { state, text } = scopeFor(marker, claim)
    if (claim.text !== undefined) await expect(text).toHaveText(claim.text)
    for (const fragment of list(claim.contains)) await expect(text).toContainText(fragment)
    for (const fragment of list(claim.absent)) await expect(text).not.toContainText(fragment)
    if (claim.result !== undefined) await expect(state).toHaveAttribute('data-result', claim.result)
    if (claim.state !== undefined) await expect(state).toHaveAttribute('data-state', claim.state)
    if (claim.klass !== undefined) await expect(state).toHaveClass(claim.klass)
  }
}

/**
 * The same rule for a rendered measurement: the number a reader sees and the
 * machine value beside it are one claim, so a mutation has to move both.
 */
export interface MeasurementClaim {
  text?: string
  contains?: string | readonly string[]
  value: string
}

export async function expectClaim(
  page: Page,
  id: string,
  claim: MeasurementClaim,
): Promise<void> {
  const marker = page.locator(`[data-claim="${id}"]`)
  await expect(marker, `the page must render exactly one [data-claim="${id}"]`).toHaveCount(1)
  expect(
    claim.text !== undefined || claim.contains !== undefined,
    `expectClaim('${id}') needs the rendered text as well as data-value`,
  ).toBe(true)
  if (claim.text !== undefined) await expect(marker).toHaveText(claim.text)
  for (const fragment of list(claim.contains)) await expect(marker).toContainText(fragment)
  await expect(marker).toHaveAttribute('data-value', claim.value)
}
