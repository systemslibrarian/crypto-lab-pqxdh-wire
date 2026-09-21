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

/** Anything that paints an outcome: the verdict block, result and state hooks. */
export const VERDICT_STYLE_SELECTOR =
  '[class*="verdict"], [data-result], [data-state], [data-state-label]'

export interface VerdictViolation {
  state: string
  kind: 'word' | 'styling'
  detail: string
  where: string
}

export interface VerdictScan {
  markers: string[]
  violations: VerdictViolation[]
}

export async function scanVerdicts(page: Page, state: string): Promise<VerdictScan> {
  return page.evaluate(
    ([stateLabel, words, styleSelector]) => {
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

      const violations: Array<{
        state: string
        kind: 'word' | 'styling'
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

      return { markers, violations }
    },
    [state, VERDICT_WORDS as unknown as string[], VERDICT_STYLE_SELECTOR] as const,
  )
}
