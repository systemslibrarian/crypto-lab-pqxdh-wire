import type { Page } from '@playwright/test'

/**
 * Coverage is derived from the rendered page, never from an enumeration written
 * by hand. A list of "the verdicts this lab has" is a self-report; the DOM is
 * evidence. Two rules are enforced against every state the page can reach:
 *
 *   1. every element that renders an outcome carries `data-verdict="<id>"`, and
 *      every id found that way must be covered by a recorded mutation;
 *   2. nothing renders verdict words or verdict styling outside a marker — that
 *      is what catches a careless builder dropping a raw banner in later.
 */

/**
 * Shouty outcome words. Matched only in ALL CAPS and only as whole words, so
 * "IMPLICIT REJECTION" (a section label) does not trip on REJECTED and prose
 * like "three spec KATs pass" does not trip on PASS.
 */
export const VERDICT_WORDS = [
  'ABORT',
  'ABORTED',
  'ACCEPT',
  'ACCEPTED',
  'BROKEN',
  'CONFIRMED',
  'DENIED',
  'DIVERGED',
  'FAIL',
  'FAILED',
  'FAILURE',
  'GREEN',
  'HEALED',
  'IMPERSONATED',
  'INSECURE',
  'INVALID',
  'LOCKED',
  'MATCH',
  'MATCHED',
  'MISMATCH',
  'OPENED',
  'PASS',
  'PASSED',
  'PROVEN',
  'RECOMPUTED',
  'REJECTED',
  'SAFE',
  'SEALED',
  'SECURE',
  'SUCCESS',
  'UNLOCKED',
  'UNSAFE',
  'UNVERIFIED',
  'VALID',
  'VERDICT',
  'VERIFIED',
] as const

/**
 * Anything that paints an outcome: the verdict block, result and state hooks.
 *
 * `[data-outcome]` is in this list because of one that was not. `#comparison-panel`
 * carried `data-outcome="pass" | "alarm"` as a CSS state hook, outside every
 * `data-verdict` element and outside this selector, so the rule below could not
 * see it: it could have gone on painting the whole card pass while the marker
 * inside it said alarm, and nothing would have reported it. That hook is gone —
 * the card is keyed off the marker's own `data-result` now — and the attribute
 * name stays here so a second one cannot arrive unmarked.
 */
export const VERDICT_STYLE_SELECTOR =
  '[class*="verdict"], [data-result], [data-state], [data-state-label], [data-outcome]'

/**
 * Where the page reports on a run. A rendered number is a claim in exactly the
 * way a rendered word is — `1,568 B`, `42 group operations`, a bare `6` — and
 * it is the easier one to leave unmarked, because a number does not look like a
 * claim. Inside these regions a measurement must sit in a marker, same as a
 * verdict word.
 *
 * The scope is the run-reporting regions rather than the whole document on
 * purpose: prose, citations and spec identifiers ("FIPS 203", "Revision 3",
 * "RFC 7748") are not measurements of this run, and a rule that flagged them
 * would be turned off within a week.
 */
export const RESULT_REGION_SELECTOR = [
  '#bundle-panel',
  '#message-panel',
  '#comparison-panel',
  '.kdf-stage',
  '#recompute-panel',
  '.fixture-output',
].join(', ')

/**
 * digit-plus-unit, and a bare short integer in a stats grid.
 *
 * The leading `(?<![\w.])` is load-bearing: without it a hex blob ending in
 * `0b` reads as "0 bytes" and the rule flakes on random key material.
 */
export const MEASUREMENT_PATTERN =
  /(?<![\w.])\d[\d,]*(?:\.\d+)?\s*(?:B|KB|MB|bits?|bytes?|ops?|operations?|ms|s|×|x)\b/i

/** A short integer standing alone in a definition list — "6", "42", "1,568". */
export const BARE_INTEGER_PATTERN = /^\d{1,3}(?:,\d{3})*$/

export interface VerdictViolation {
  state: string
  kind: 'word' | 'styling' | 'measurement'
  detail: string
  where: string
}

export interface VerdictScan {
  markers: string[]
  claims: string[]
  violations: VerdictViolation[]
}

export async function scanVerdicts(page: Page, state: string): Promise<VerdictScan> {
  return page.evaluate(
    ([stateLabel, words, styleSelector, regionSelector, measurementSource, bareIntegerSource]) => {
      const describe = (element: Element): string => {
        const id = element.id ? `#${element.id}` : ''
        const cls = element.className && typeof element.className === 'string'
          ? `.${element.className.trim().split(/\s+/).join('.')}`
          : ''
        return `${element.tagName.toLowerCase()}${id}${cls}`
      }

      const isVisible = (element: Element): boolean => {
        const rects = (element as HTMLElement).getClientRects()
        return rects.length > 0
      }

      const markers = [
        ...new Set(
          [...document.querySelectorAll('[data-verdict]')].map(
            (element) => (element as HTMLElement).dataset.verdict ?? '',
          ),
        ),
      ].filter(Boolean)

      const claims = [
        ...new Set(
          [...document.querySelectorAll('[data-claim]')].map(
            (element) => (element as HTMLElement).dataset.claim ?? '',
          ),
        ),
      ].filter(Boolean)

      const violations: Array<{
        state: string
        kind: 'word' | 'styling' | 'measurement'
        detail: string
        where: string
      }> = []

      for (const element of document.querySelectorAll(styleSelector)) {
        if (element.closest('[data-verdict]')) continue
        if (!isVisible(element)) continue
        violations.push({
          state: stateLabel,
          kind: 'styling',
          detail: describe(element),
          where: describe(element.parentElement ?? element),
        })
      }

      const pattern = new RegExp(`(?<![A-Z])(${words.join('|')})(?![A-Z])`, 'g')
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT)
      for (let node = walker.nextNode(); node; node = walker.nextNode()) {
        const owner = node.parentElement
        if (!owner) continue
        if (owner.closest('[data-verdict]')) continue
        if (!isVisible(owner)) continue
        const text = node.textContent ?? ''
        const hits = [...new Set([...text.matchAll(pattern)].map((match) => match[1]))]
        for (const hit of hits) {
          violations.push({
            state: stateLabel,
            kind: 'word',
            detail: hit,
            where: `${describe(owner)} :: ${text.trim().slice(0, 80)}`,
          })
        }
      }

      // A measurement painted outside any marker is exactly as unchecked as a
      // verdict painted outside one. Leaf text only: a container's text is the
      // concatenation of its children and would report the same number twice.
      const measurement = new RegExp(measurementSource, 'i')
      const bareInteger = new RegExp(bareIntegerSource)
      for (const region of document.querySelectorAll(regionSelector)) {
        const leaves = [region, ...region.querySelectorAll('*')].filter(
          (element) => element.children.length === 0,
        )
        for (const leaf of leaves) {
          if (leaf.closest('[data-verdict]') || leaf.closest('[data-claim]')) continue
          if (!isVisible(leaf)) continue
          const text = (leaf.textContent ?? '').trim()
          if (!text) continue
          const inStatsGrid = Boolean(leaf.closest('dl')) && leaf.tagName === 'DD'
          const hit = text.match(measurement)?.[0] ?? (inStatsGrid && bareInteger.test(text) ? text : '')
          if (!hit) continue
          violations.push({
            state: stateLabel,
            kind: 'measurement',
            detail: hit.trim(),
            where: `${describe(leaf)} :: ${text.slice(0, 80)}`,
          })
        }
      }

      return { markers, claims, violations }
    },
    [
      state,
      VERDICT_WORDS as unknown as string[],
      VERDICT_STYLE_SELECTOR,
      RESULT_REGION_SELECTOR,
      MEASUREMENT_PATTERN.source,
      BARE_INTEGER_PATTERN.source,
    ] as const,
  )
}
