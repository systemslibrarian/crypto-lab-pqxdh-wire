import { expect, type Page } from '@playwright/test'

/**
 * The DENOMINATOR, not a test.
 *
 * The marker-coverage rule and the outside-marker rule are both enumerated over
 * whatever this walk reaches, so anything that renders only in a state this
 * function never visits is outside the set those rules judge — and stays
 * outside however carefully the rules themselves are written. That is the
 * discovered-rather-than-declared denominator defect one level up from where
 * the coverage rules live.
 *
 * The rule, lane-wide:
 *
 *   driveEveryState visits every option of every control that changes what
 *   renders — each control on its own, not the full cross-product.
 *
 * Per-control rather than combinatorial is what keeps it affordable. The
 * cross-product would buy interaction coverage, which is a different question
 * and not one the marker rules ask.
 *
 * ## Every control on this page, and what it owes
 *
 * | Control | Options walked |
 * |---|---|
 * | `#step-button` | all six handshake states: 0 arrival, 1 bundle, 2 Alice, 3 sent, 4 Bob, 5 compare — plus its sixth press, whose label becomes "Run a fresh handshake" and which resets |
 * | `#reset-button` | its one press |
 * | `#quantum-toggle` | unchecked, checked, AND unchecked again — the third is its own render (`NO MODEL ACTIVE`) and was never visited |
 * | `#lattice-toggle` | unchecked (enabled), checked, unchecked again |
 * | `#reuse-toggle` | unchecked at arrival, checked, unchecked again through the change handler |
 * | `#bad-signature-button` | its one press |
 * | `#tamper-button` | its one press |
 * | `#impersonate-button` | its one press |
 * | `#ratchet-button` | pressed before the handshake (refusal), pressed with the curve break OFF (`HEALED`) and pressed with it ON (`HEALED — AND STILL READ`). The classical outcome was never visited: the old walk toggled the model on first and only ever saw one of this control's two reachable verdicts |
 * | `summary` × 2 | closed at arrival, opened |
 *
 * Deliberately NOT walked, with the reason:
 *
 * - `.skip-link` — focusing it moves focus and paints an outline; it renders no
 *   claim and changes no marker. The a11y gate drives it instead.
 * - the `DID NOT HEAL` branch of `#ratchet-button` — not reachable through any
 *   control, only under the `ratchet-grant-is-not-a-recovery` mutation, which is
 *   exactly where it is exercised.
 * - the `UNEXPECTED ACCEPT` branches of the two abort fixtures — same: reachable
 *   only under their recorded mutations.
 */
export async function driveEveryState(
  page: Page,
  visit: (state: string) => Promise<void>,
): Promise<void> {
  await visit('arrival')

  // #ratchet-button before a session exists — its refusal is a rendered state.
  await page.locator('#ratchet-button').click()
  await expect(page.locator('#ratchet-output')).toContainText('Complete the live handshake first')
  await visit('ratchet refused before the handshake')

  for (const expected of [
    'BUNDLE PUBLISHED',
    'ALICE COMPLETE',
    'MESSAGE SENT',
    'BOB COMPLETE',
    'MATCH',
  ]) {
    await page.locator('#step-button').click()
    await expect(page.locator('#protocol-status')).toContainText(expected)
    await visit(expected.toLowerCase())
  }

  // The ratchet with NO model granted. This is the control's other outcome and
  // the old walk never reached it, because it toggled the curve break on first.
  await page.locator('#ratchet-button').click()
  await expect(page.locator('#ratchet-output')).toContainText('HEALED')
  await expect(page.locator('#ratchet-output')).not.toContainText('STILL READ')
  await visit('reduced ratchet with no model granted')

  await page.locator('#quantum-toggle').check()
  await expect(page.locator('#recompute-panel')).toContainText('SK = NOT DERIVED')
  await visit('curve break')

  await page.locator('#lattice-toggle').check()
  await expect(page.locator('#recompute-panel')).toContainText('SK OPENED')
  await visit('curve and lattice break')

  await page.locator('#lattice-toggle').uncheck()
  await expect(page.locator('#recompute-panel')).toContainText('SK = NOT DERIVED')
  await visit('lattice break withdrawn')

  await page.locator('#ratchet-button').click()
  await expect(page.locator('#ratchet-output')).toContainText('HEALED — AND STILL READ')
  await visit('reduced ratchet under curve break')

  await page.locator('#quantum-toggle').uncheck()
  await expect(page.locator('#recompute-panel')).toContainText('NO MODEL ACTIVE')
  await visit('curve break withdrawn')

  await page.locator('#bad-signature-button').click()
  await expect(page.locator('#bad-signature-output')).toContainText('ABORT')
  await visit('bad prekey signature')

  await page.locator('#tamper-button').click()
  await expect(page.locator('#tamper-output')).toContainText('REJECTED')
  await visit('tampered KEM ciphertext')

  await page.locator('#reuse-toggle').check()
  await expect(page.locator('#reuse-output')).toContainText('PQ KEY ID')
  await visit('last-resort reuse')

  await page.locator('#reuse-toggle').uncheck()
  await expect(page.locator('#reuse-output')).toContainText('One-time PQ prekeys are available')
  await visit('last-resort reuse withdrawn')

  await page.locator('#impersonate-button').click()
  await expect(page.locator('#impersonate-output')).toContainText('IMPERSONATED')
  await visit('impersonation fixture')

  for (const summary of await page.locator('summary').all()) await summary.click()
  await visit('all disclosures open')

  // The step button's sixth press is its own option: the label is now
  // "Run a fresh handshake" and the press resets rather than advancing.
  await expect(page.locator('#step-button')).toHaveText('Run a fresh handshake')
  await page.locator('#step-button').click()
  await expect(page.locator('#protocol-status')).toContainText('READY')
  await visit('fresh handshake through the step button')

  await page.locator('#reset-button').click()
  await expect(page.locator('#protocol-status')).toContainText('READY')
  await visit('after reset')
}
