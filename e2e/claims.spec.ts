import { hkdfSync } from 'node:crypto'

import { expect, test, type Page } from '@playwright/test'

async function completeHandshake(page: Page): Promise<void> {
  for (const expected of ['BUNDLE PUBLISHED', 'ALICE COMPLETE', 'MESSAGE SENT', 'BOB COMPLETE', 'MATCH']) {
    await page.locator('#step-button').click()
    await expect(page.locator('#protocol-status')).toContainText(expected)
  }
}

function fromHex(value: string): Buffer {
  return Buffer.from(value.trim(), 'hex')
}

test.beforeEach(async ({ page }) => {
  await page.goto('./')
})

test('recomputes the displayed SK independently from displayed KDF inputs', async ({ page }) => {
  await completeHandshake(page)
  const ids = ['value-f', 'value-dh1', 'value-dh2', 'value-dh3', 'value-dh4', 'value-ss']
  const fields = await Promise.all(ids.map((id) => page.locator(`[data-test="${id}"]`).textContent()))
  const inputKeyMaterial = Buffer.concat(fields.map((value) => fromHex(value ?? '')))
  const expected = Buffer.from(
    hkdfSync(
      'sha512',
      inputKeyMaterial,
      Buffer.alloc(64),
      Buffer.from('PQXDH_CURVE25519_SHA-512_ML-KEM-1024'),
      32,
    ),
  ).toString('hex')

  await expect(page.locator('[data-test="value-sk"]')).toHaveText(expected)
  await expect(page.locator('[data-test="alice-sk"]')).toHaveText(expected)
  await expect(page.locator('[data-test="bob-sk"]')).toHaveText(expected)
})

test('names each real rejection cause', async ({ page }) => {
  await page.locator('#bad-signature-button').click()
  await expect(page.locator('#bad-signature-output')).toContainText('Signed ML-KEM prekey signature verification failed')

  await page.locator('#tamper-button').click()
  await expect(page.locator('#tamper-output')).toContainText('Initial AEAD authentication failed after ML-KEM implicit rejection')
})

test('derives no adversary SK until both modeled assumptions are granted', async ({ page }) => {
  await completeHandshake(page)
  const honestKey = await page.locator('[data-test="alice-sk"]').textContent()

  await page.locator('#quantum-toggle').check()
  await expect(page.locator('#recompute-panel')).toContainText('SS = UNKNOWN · SK = NOT DERIVED')
  await expect(page.locator('[data-test="adversary-sk"]')).toHaveCount(0)

  await page.locator('#lattice-toggle').check()
  await expect(page.locator('[data-test="adversary-sk"]')).toHaveText(honestKey ?? '')
})

test('shows last-resort reuse without claiming that reuse alone reveals SK', async ({ page }) => {
  await page.locator('#reuse-toggle').check()
  const output = page.locator('#reuse-output')
  await expect(output).toContainText('SAME PQ KEY ID')
  await expect(output).toContainText('Reuse does not reveal either SK by itself')
})

test('retires a completed handshake on reset and preserves it for a no-op check', async ({ page }) => {
  await completeHandshake(page)
  const honestKey = await page.locator('[data-test="alice-sk"]').textContent()
  await page.locator('#quantum-toggle').check()
  await page.locator('#quantum-toggle').check()
  await expect(page.locator('#comparison-panel')).toBeVisible()
  await expect(page.locator('[data-test="alice-sk"]')).toHaveText(honestKey ?? '')

  await page.locator('#reset-button').click()
  await expect(page.locator('#comparison-panel')).toBeHidden()
  await expect(page.locator('#bundle-panel')).toBeHidden()
  await expect(page.locator('#protocol-status')).toContainText('READY')
})

test('keeps hidden states genuinely hidden', async ({ page }) => {
  await expect(page.locator('#bundle-panel')).toHaveAttribute('hidden', '')
  await expect(page.locator('#message-panel')).toHaveAttribute('hidden', '')
  await expect(page.locator('#comparison-panel')).toHaveAttribute('hidden', '')
  await expect(page.locator('#bundle-panel')).toBeHidden()
})

test('reaches the authenticated impersonation negative-claim fixture', async ({ page }) => {
  await page.locator('#impersonate-button').click()
  await expect(page.locator('#impersonate-output')).toContainText('PQ-CONFIDENTIAL — AND IMPERSONATED')
  await expect(page.locator('#impersonate-output')).toContainText('Every Ed25519 prekey signature and the initial AES-GCM check passed')
  await expect(page.getByText("Its prekey signature is classical", { exact: false })).toBeVisible()
})

test('reaches both reduced-ratchet negative-claim outcomes', async ({ page }) => {
  await completeHandshake(page)
  await page.locator('#ratchet-button').click()
  await expect(page.locator('#ratchet-output')).toContainText('HEALED')
  await expect(page.locator('#ratchet-output')).not.toContainText('STILL READ')

  await page.locator('#quantum-toggle').check()
  await page.locator('#ratchet-button').click()
  await expect(page.locator('#ratchet-output')).toContainText('HEALED — AND STILL READ')
  await expect(page.getByText('this is one DH-root update', { exact: false })).toBeVisible()
})