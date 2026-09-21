import { expect, test, type Page } from '@playwright/test'

/**
 * One test per `data-verdict` marker, asserting what that marker renders.
 *
 * These are the assertions the recorded mutations in e2e/verdict-mutations.json
 * must break. Keeping them one-to-one with the markers is what makes a kill
 * legible: when a mutation is applied, the failure is this verdict's own
 * assertion rather than a build error, a blank page, or the suite going red.
 */

const marker = (page: Page, id: string) => page.locator(`[data-verdict="${id}"]`)

/**
 * Advances the handshake by progress alone — the button's own label — and
 * asserts no verdict on the way. A helper that waited on `MATCH` would make
 * every test below fail inside the helper when the SK comparison is mutated,
 * which is not that verdict's own assertion and so is not a kill.
 */
async function completeHandshake(page: Page): Promise<void> {
  const button = page.locator('#step-button')
  for (const label of [
    'Alice computes five secrets',
    'Send initial message',
    'Bob derives independently',
    'Compare 32 bytes',
    'Run a fresh handshake',
  ]) {
    await button.click()
    await expect(button).toHaveText(label)
  }
}

test.beforeEach(async ({ page }) => {
  await page.goto('./')
  await expect(page.locator('#app')).not.toBeEmpty()
})

test('handshake-status reports the measured 32-byte comparison', async ({ page }) => {
  await completeHandshake(page)
  await expect(marker(page, 'handshake-status')).toHaveText(
    'MATCH — both modules independently derived the same 32 bytes',
  )
})

test('session-key-match renders the byte-for-byte verdict, not a canned banner', async ({
  page,
}) => {
  await expect(marker(page, 'session-key-match')).toContainText(
    'Session keys not compared yet',
  )
  await completeHandshake(page)
  await expect(page.locator('#comparison-title')).toHaveText('ALICE SK = BOB SK')
  await expect(marker(page, 'session-key-match')).toHaveClass(/verdict-pass/)
  await expect(page.locator('#comparison-panel')).toHaveAttribute('data-outcome', 'pass')

  const alice = await page.locator('[data-test="alice-sk"]').textContent()
  const bob = await page.locator('[data-test="bob-sk"]').textContent()
  expect(alice).toHaveLength(64)
  expect(alice).toBe(bob)
})

test('session-key-state labels SK from the comparison, not the step counter', async ({
  page,
}) => {
  const label = marker(page, 'session-key-state').locator('[data-state-label]')
  await expect(label).toHaveText('WAITING')
  await completeHandshake(page)
  await expect(label).toHaveText('MATCHED')
  await expect(marker(page, 'session-key-state')).toHaveAttribute('data-state', 'pass')
})

test('kdf-input-state opens exactly the boxes the grant covers', async ({ page }) => {
  const ss = marker(page, 'kdf-input-state').locator(
    '[data-material="SS"] [data-state-label]',
  )
  const dh1 = marker(page, 'kdf-input-state').locator(
    '[data-material="DH1"] [data-state-label]',
  )
  await expect(ss).toHaveText('SEALED')
  await completeHandshake(page)
  await expect(ss).toHaveText('HONEST INPUT')

  await page.locator('#quantum-toggle').check()
  await expect(dh1).toHaveText('OPENED IN MODEL')
  await expect(ss).toHaveText('OPAQUE TO MODEL')

  await page.locator('#lattice-toggle').check()
  await expect(ss).toHaveText('OPENED IN MODEL')
})

test('adversary-model derives SK only when both assumptions are granted', async ({
  page,
}) => {
  await completeHandshake(page)
  const panel = marker(page, 'adversary-model')
  await page.locator('#quantum-toggle').check()
  await expect(panel).toContainText('SS = UNKNOWN · SK = NOT DERIVED')
  await expect(page.locator('[data-test="adversary-sk"]')).toHaveCount(0)

  await page.locator('#lattice-toggle').check()
  await expect(panel).toContainText('SK OPENED — BOTH ASSUMPTIONS BROKEN')
  const honest = await page.locator('[data-test="alice-sk"]').textContent()
  await expect(page.locator('[data-test="adversary-sk"]')).toHaveText(honest ?? '')
})

test('prekey-signature-abort names the check that fired', async ({ page }) => {
  await page.locator('#bad-signature-button').click()
  const output = marker(page, 'prekey-signature-abort')
  await expect(output).toContainText(
    'ABORT — Signed ML-KEM prekey signature verification failed',
  )
  await expect(output).not.toContainText('UNEXPECTED ACCEPT')
  await expect(output).toHaveAttribute('data-result', 'alarm')
})

test('kem-tamper-abort names the AEAD as the place the mismatch surfaced', async ({
  page,
}) => {
  await page.locator('#tamper-button').click()
  const output = marker(page, 'kem-tamper-abort')
  await expect(output).toContainText(
    'REJECTED AT FIRST AEAD — Initial AEAD authentication failed after ML-KEM implicit rejection',
  )
  await expect(output).not.toContainText('UNEXPECTED ACCEPT')
  await expect(output).toHaveAttribute('data-result', 'alarm')
})

test('last-resort-reuse measures the three facts it claims', async ({ page }) => {
  await page.locator('#reuse-toggle').check()
  const output = marker(page, 'last-resort-reuse')
  await expect(output).toContainText('SAME PQ KEY ID')
  await expect(output).not.toContainText('NO LAST-RESORT REUSE OBSERVED')

  const rendered = (await output.locator('[data-test="reuse-checks"]').textContent()) ?? ''
  const checks = rendered.split(' · ').map((entry) => entry.trim()).filter(Boolean)
  expect(checks).toHaveLength(3)
  expect(checks.every((entry) => entry.endsWith(': PASS'))).toBe(true)
  await expect(output).toContainText('Reuse does not reveal either SK by itself')
})

test('impersonation reports four measured checks, not a flag', async ({ page }) => {
  await page.locator('#impersonate-button').click()
  const output = marker(page, 'impersonation')
  await expect(output).toContainText('PQ-CONFIDENTIAL — AND IMPERSONATED')
  await expect(output).not.toContainText('FIXTURE INVALID')

  const rendered =
    (await output.locator('[data-test="impersonate-checks"]').textContent()) ?? ''
  const checks = rendered.split(' · ').map((entry) => entry.trim()).filter(Boolean)
  expect(checks).toHaveLength(4)
  expect(checks.every((entry) => entry.endsWith(': PASS'))).toBe(true)
})

test('ratchet-heal reaches both outcomes from a chain that is always built', async ({
  page,
}) => {
  await completeHandshake(page)
  const output = marker(page, 'ratchet-heal')

  await page.locator('#ratchet-button').click()
  await expect(output).toContainText('HEALED')
  await expect(output).not.toContainText('STILL READ')
  await expect(output).not.toContainText('DID NOT HEAL')
  await expect(output).toHaveAttribute('data-result', 'pass')

  const compromised = (await page.locator('[data-test="alice-sk"]').textContent()) ?? ''
  const chain = ((await output.locator('[data-test="ratchet-roots"]').textContent()) ?? '')
    .replace('Root chain:', '')
    .split('→')
    .map((root) => root.trim())
  expect(chain).toHaveLength(4)
  expect(new Set(chain).size).toBe(4)
  expect(chain[0]).toBe(compromised.slice(0, 8))

  await page.locator('#quantum-toggle').check()
  await page.locator('#ratchet-button').click()
  await expect(output).toContainText('HEALED — AND STILL READ')
  await expect(output).toHaveAttribute('data-result', 'alarm')
})
