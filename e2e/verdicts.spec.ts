import { expect, test, type Page } from '@playwright/test'

import { expectClaim, expectVerdict } from './expect-verdict.js'

/**
 * One test per `data-verdict` marker and per `data-claim` measurement,
 * asserting what that marker renders AND the state it paints, together, through
 * `expectVerdict` / `expectClaim`.
 *
 * These are the assertions the recorded mutations in e2e/verdict-mutations.json
 * must break. Keeping them one-to-one with the markers is what makes a kill
 * legible: when a mutation is applied, the failure is this verdict's own
 * assertion rather than a build error, a blank page, or the suite going red.
 *
 * Text alone is not enough and is no longer accepted by the helper. A mutation
 * that flips the words while leaving `data-result="pass"` in place would have
 * been recorded as a kill, and the marker would go on claiming pass in every
 * way a reader can see except the sentence.
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
  await expectVerdict(page, 'handshake-status', {
    contains: 'READY — no key material generated yet',
    result: 'pending',
  })
  await completeHandshake(page)
  await expectVerdict(page, 'handshake-status', {
    text: 'MATCH — both modules independently derived the same 32 bytes',
    result: 'pass',
  })
})

test('session-key-match renders the byte-for-byte verdict, not a canned banner', async ({
  page,
}) => {
  await expectVerdict(page, 'session-key-match', {
    contains: 'Session keys not compared yet',
    result: 'pending',
  })
  await completeHandshake(page)
  await expectVerdict(page, 'session-key-match', {
    label: '#comparison-title',
    text: 'ALICE SK = BOB SK',
    result: 'pass',
    klass: /verdict-pass/,
  })
  await expect(page.locator('#comparison-panel')).toHaveAttribute('data-outcome', 'pass')

  const alice = await page.locator('[data-test="alice-sk"]').textContent()
  const bob = await page.locator('[data-test="bob-sk"]').textContent()
  expect(alice).toHaveLength(64)
  expect(alice).toBe(bob)
})

test('session-key-state labels SK from the comparison, not the step counter', async ({
  page,
}) => {
  await expectVerdict(page, 'session-key-state', {
    label: '[data-state-label]',
    text: 'WAITING',
    state: 'sealed',
  })
  await completeHandshake(page)
  await expectVerdict(page, 'session-key-state', {
    label: '[data-state-label]',
    text: 'MATCHED',
    state: 'pass',
  })
})

test('kdf-input-state opens exactly the boxes the grant covers', async ({ page }) => {
  await expectVerdict(page, 'kdf-input-state', {
    within: '[data-material="SS"]',
    label: '[data-state-label]',
    text: 'SEALED',
    state: 'sealed',
  })
  await completeHandshake(page)
  await expectVerdict(page, 'kdf-input-state', {
    within: '[data-material="SS"]',
    label: '[data-state-label]',
    text: 'HONEST INPUT',
    state: 'derived',
  })

  await page.locator('#quantum-toggle').check()
  await expectVerdict(
    page,
    'kdf-input-state',
    {
      within: '[data-material="DH1"]',
      label: '[data-state-label]',
      text: 'OPENED IN MODEL',
      state: 'alarm',
    },
    {
      within: '[data-material="SS"]',
      label: '[data-state-label]',
      text: 'OPAQUE TO MODEL',
      state: 'sealed',
    },
  )

  await page.locator('#lattice-toggle').check()
  await expectVerdict(page, 'kdf-input-state', {
    within: '[data-material="SS"]',
    label: '[data-state-label]',
    text: 'OPENED IN MODEL',
    state: 'alarm',
  })
})

test('adversary-model derives SK only when both assumptions are granted', async ({
  page,
}) => {
  await completeHandshake(page)
  await page.locator('#quantum-toggle').check()
  await expectVerdict(page, 'adversary-model', {
    contains: 'SS = UNKNOWN · SK = NOT DERIVED',
    result: 'locked',
  })
  await expect(page.locator('[data-test="adversary-sk"]')).toHaveCount(0)

  await page.locator('#lattice-toggle').check()
  await expectVerdict(page, 'adversary-model', {
    contains: 'SK OPENED — BOTH ASSUMPTIONS BROKEN',
    result: 'alarm',
  })
  const honest = await page.locator('[data-test="alice-sk"]').textContent()
  await expect(page.locator('[data-test="adversary-sk"]')).toHaveText(honest ?? '')
})

test('prekey-signature-abort names the check that fired', async ({ page }) => {
  await page.locator('#bad-signature-button').click()
  await expectVerdict(page, 'prekey-signature-abort', {
    contains: 'ABORT — Signed ML-KEM prekey signature verification failed',
    absent: 'UNEXPECTED ACCEPT',
    result: 'alarm',
  })
})

test('kem-tamper-abort names the AEAD as the place the mismatch surfaced', async ({
  page,
}) => {
  await page.locator('#tamper-button').click()
  await expectVerdict(page, 'kem-tamper-abort', {
    contains:
      'REJECTED AT FIRST AEAD — Initial AEAD authentication failed after ML-KEM implicit rejection',
    absent: 'UNEXPECTED ACCEPT',
    result: 'alarm',
  })
})

test('last-resort-reuse measures the three facts it claims', async ({ page }) => {
  await page.locator('#reuse-toggle').check()
  await expectVerdict(page, 'last-resort-reuse', {
    contains: ['SAME PQ KEY ID', 'Reuse does not reveal either SK by itself'],
    absent: 'NO LAST-RESORT REUSE OBSERVED',
    result: 'alarm',
  })

  const output = marker(page, 'last-resort-reuse')
  const rendered = (await output.locator('[data-test="reuse-checks"]').textContent()) ?? ''
  const checks = rendered.split(' · ').map((entry) => entry.trim()).filter(Boolean)
  expect(checks).toHaveLength(3)
  expect(checks.every((entry) => entry.endsWith(': PASS'))).toBe(true)
})

test('impersonation reports four measured checks, not a flag', async ({ page }) => {
  await page.locator('#impersonate-button').click()
  await expectVerdict(page, 'impersonation', {
    contains: 'PQ-CONFIDENTIAL — AND IMPERSONATED',
    absent: 'FIXTURE INVALID',
    result: 'alarm',
  })

  const output = marker(page, 'impersonation')
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
  await expectVerdict(page, 'ratchet-heal', {
    contains: 'HEALED',
    absent: ['STILL READ', 'DID NOT HEAL'],
    result: 'pass',
  })

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
  await expectVerdict(page, 'ratchet-heal', {
    contains: 'HEALED — AND STILL READ',
    result: 'alarm',
  })
})

/**
 * The wire measurements. These numbers used to be `1,568 B`, `1,632 B` and
 * `0 B` written into the page template, so the strongest claim the exhibit
 * makes — that no secret crossed the wire — was a literal about nothing.
 *
 * The oracle for the searched-bytes total is deliberately a SUM over the page's
 * own rendered KDF inputs, never `inputCount × 32`. A count multiplied by an
 * assumed width cannot distinguish "summed the six values actually searched"
 * from "multiplied one width out", which is exactly the distinction the sentence
 * beside it claims — and it is the shape that breaks silently the moment a run
 * omits DH4 because the one-time prekey is exhausted.
 */
const X25519_PUBLIC_KEY_BYTES = 32 // RFC 7748 §5
const ML_KEM_1024_BYTES = 1568 // FIPS 203: ML-KEM-1024 ek and c are both 1568 B

test('wire-secrecy searches the sent bytes rather than asserting they are clean', async ({
  page,
}) => {
  await expectVerdict(page, 'wire-secrecy', {
    contains: 'Initial message not built yet',
    result: 'pending',
  })
  await completeHandshake(page)

  // Every secret the page rendered for this session, summed at its own width.
  const secretHex = await Promise.all(
    ['value-dh1', 'value-dh2', 'value-dh3', 'value-dh4', 'value-ss', 'value-sk'].map((id) =>
      page.locator(`[data-test="${id}"]`).textContent(),
    ),
  )
  const searched = secretHex
    .map((hex) => (hex ?? '').trim())
    .filter((hex) => /^[0-9a-f]+$/.test(hex))
    .reduce((total, hex) => total + hex.length / 2, 0)
  expect(searched, 'the page must have rendered the secrets the scan claims to search').toBe(
    6 * X25519_PUBLIC_KEY_BYTES,
  )

  await expectVerdict(page, 'wire-secrecy', {
    contains: `searched the sent bytes for all ${searched.toLocaleString('en-US')} bytes`,
    absent: 'SECRET BYTES FOUND ON THE WIRE',
    result: 'pass',
  })
  await expectClaim(page, 'wire-scanned-secret-bytes', {
    text: `${searched.toLocaleString('en-US')} B`,
    value: String(searched),
  })
  await expectClaim(page, 'wire-secret-bytes', { text: '0 B', value: '0' })
})

test('wire-kem-ct-bytes and wire-ad-bytes measure the message rather than restate it', async ({
  page,
}) => {
  await completeHandshake(page)
  await expectClaim(page, 'wire-kem-ct-bytes', {
    text: '1,568 B',
    value: String(ML_KEM_1024_BYTES),
  })
  // AD binds IK_A || IK_B || PQPK_B — PQXDH Revision 3 — and the AEAD Bob
  // verified is the evidence these are the bytes actually authenticated.
  await expectClaim(page, 'wire-ad-bytes', {
    text: '1,632 B',
    value: String(2 * X25519_PUBLIC_KEY_BYTES + ML_KEM_1024_BYTES),
  })
})
