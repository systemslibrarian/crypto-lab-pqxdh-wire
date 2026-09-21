import { describe, expect, it } from 'vitest'

import { createBobState, publishBundle } from '../pqxdh/bundle.js'
import { runAlice } from '../pqxdh/alice.js'
import { containsBytes, measureWire, wireBytes } from './wire.js'

describe('containsBytes', () => {
  it('finds a run that is present', () => {
    const haystack = Uint8Array.from([9, 1, 2, 3, 9])
    expect(containsBytes(haystack, Uint8Array.from([1, 2, 3]))).toBe(true)
    expect(containsBytes(haystack, Uint8Array.from([9]))).toBe(true)
  })

  it('rejects a run that only overlaps, and a needle longer than the haystack', () => {
    const haystack = Uint8Array.from([9, 1, 2, 3, 9])
    expect(containsBytes(haystack, Uint8Array.from([2, 3, 4]))).toBe(false)
    expect(containsBytes(haystack, Uint8Array.from([1, 2, 3, 9, 9, 9]))).toBe(false)
  })

  it('refuses the empty needle rather than reporting a match', () => {
    // The whole secret search rests on this: an empty needle matching would
    // make "found none" satisfiable by looking for nothing.
    expect(containsBytes(Uint8Array.from([1, 2]), new Uint8Array())).toBe(false)
  })
})

describe('measureWire', () => {
  it('measures the real initial message and finds no secret in it', async () => {
    const state = createBobState()
    const bundle = publishBundle(state)
    const alice = await runAlice(bundle)
    const secrets = [
      alice.components.dh1,
      alice.components.dh2,
      alice.components.dh3,
      alice.components.dh4!,
      alice.components.sharedSecret,
      alice.sessionKey,
    ]

    const measurement = measureWire(alice.message, alice.associatedData, secrets)
    expect(measurement.kemCiphertextBytes).toBe(alice.message.kemCiphertext.length)
    expect(measurement.kemCiphertextBytes).toBe(1568)
    expect(measurement.associatedDataBytes).toBe(alice.associatedData.length)
    expect(measurement.associatedDataBytes).toBe(32 + 32 + 1568)
    expect(measurement.scannedSecretBytes).toBe(
      secrets.reduce((total, secret) => total + secret.length, 0),
    )
    expect(measurement.secretBytesOnWire).toBe(0)
  })

  it('reports a secret that really is on the wire, so the zero is not vacuous', async () => {
    const state = createBobState()
    const bundle = publishBundle(state)
    const alice = await runAlice(bundle)
    const onTheWire = wireBytes(alice.message).slice(64, 96)

    const measurement = measureWire(alice.message, alice.associatedData, [
      onTheWire,
      alice.sessionKey,
    ])
    expect(measurement.secretBytesOnWire).toBe(onTheWire.length)
    expect(measurement.scannedSecretBytes).toBe(onTheWire.length + alice.sessionKey.length)
  })

  it('puts the public keys, KEM ciphertext, nonce and AEAD ciphertext on the wire', async () => {
    const state = createBobState()
    const bundle = publishBundle(state)
    const alice = await runAlice(bundle)
    const wire = wireBytes(alice.message)
    expect(wire.length).toBe(
      alice.message.aliceIdentityPublic.length +
        alice.message.aliceEphemeralPublic.length +
        alice.message.kemCiphertext.length +
        alice.message.aeadNonce.length +
        alice.message.aeadCiphertext.length,
    )
    expect(containsBytes(wire, alice.message.kemCiphertext)).toBe(true)
    expect(containsBytes(wire, alice.sessionKey)).toBe(false)
  })
})
