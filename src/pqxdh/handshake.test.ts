import { x25519 } from '@noble/curves/ed25519.js'
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { concatBytes, hexToBytes } from '@noble/hashes/utils.js'
import { describe, expect, it } from 'vitest'

import { bytesToHex, equalBytes } from '../crypto/bytes.js'
import { createAdversaryGrant, recomputeAsAdversary, runImpersonationFixture } from '../model/quantum.js'
import { adversaryAdvance, runRatchetModel } from '../model/ratchet-step.js'
import { runAlice } from './alice.js'
import { runBob } from './bob.js'
import { createBobState, publishBundle } from './bundle.js'
import { runVerifiedHandshake } from '../verify/session.js'

describe('PQXDH handshake', () => {
  it('derives byte-identical Alice and Bob session keys', async () => {
    const session = await runVerifiedHandshake()
    expect(session.keysMatch).toBe(true)
    expect(session.alice.sessionKey).toEqual(session.bob.sessionKey)
    expect(new TextDecoder().decode(session.bob.plaintext)).toBe('PQXDH initial message')
  })

  it('uses the last-resort PQ prekey only when selected', async () => {
    const session = await runVerifiedHandshake(false)
    expect(session.bundle.pqPrekeyKind).toBe('last-resort')
    expect(session.keysMatch).toBe(true)
  })

  it('omits DH4 when the curve one-time prekey is exhausted', async () => {
    const state = createBobState()
    const bundle = publishBundle(state, { includeCurveOneTime: false })
    const alice = await runAlice(bundle)
    const bob = await runBob(state, bundle, alice.message)

    expect(alice.components.dh4).toBeUndefined()
    expect(bob.components.dh4).toBeUndefined()
    expect(alice.sessionKey).toEqual(bob.sessionKey)
  })

  it('fails closed and names a bad ML-KEM prekey signature', async () => {
    const state = createBobState()
    const bundle = publishBundle(state)
    bundle.pqPrekeySignature = bundle.pqPrekeySignature.slice()
    bundle.pqPrekeySignature[0] ^= 1
    await expect(runAlice(bundle)).rejects.toThrow(
      'Signed ML-KEM prekey signature verification failed',
    )
  })

  it('surfaces tampered ML-KEM ciphertext at the first AEAD', async () => {
    const state = createBobState()
    const bundle = publishBundle(state)
    const alice = await runAlice(bundle)
    alice.message.kemCiphertext = alice.message.kemCiphertext.slice()
    alice.message.kemCiphertext[0] ^= 1
    await expect(runBob(state, bundle, alice.message)).rejects.toThrow(
      'Initial AEAD authentication failed after ML-KEM implicit rejection',
    )
  })

  it('refuses IK_A = IK_B', async () => {
    const state = createBobState()
    const bundle = publishBundle(state)
    await expect(runAlice(bundle, state.identityDh)).rejects.toThrow('IK_A equals IK_B')
  })
})

describe('component known-answer tests', () => {
  it('passes the RFC 7748 X25519 test vector', () => {
    const alicePrivate = hexToBytes(
      '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
    )
    const bobPrivate = hexToBytes(
      '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
    )
    const expectedAlicePublic = hexToBytes(
      '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
    )
    const expectedShared = hexToBytes(
      '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742',
    )

    expect(x25519.getPublicKey(alicePrivate)).toEqual(expectedAlicePublic)
    expect(x25519.getSharedSecret(alicePrivate, x25519.getPublicKey(bobPrivate))).toEqual(
      expectedShared,
    )
  })

  it('passes NIST ACVP ML-KEM-1024 keyGen tgId 3 tcId 51', () => {
    const d = hexToBytes(
      'f3a706faf090c03db506863ab0b20bd8a1627956318e88c67eb875e8e7266009',
    )
    const z = hexToBytes(
      '35d2bc43dd1cc879f765bf2a0c5e297889dde910e57e2bb0eae417b90ab7a275',
    )
    const keys = ml_kem1024.keygen(concatBytes(d, z))

    expect(keys.publicKey).toHaveLength(1568)
    expect(keys.secretKey).toHaveLength(3168)
    expect(bytesToHex(sha256(keys.publicKey))).toBe(
      'b78619e4fceeeb86dee3fedb945eca6da61dae312771ef8fa871951d391bd7b6',
    )
    expect(bytesToHex(sha256(keys.secretKey))).toBe(
      '925ed6f1cf0379ede29d8209432d6e08c73ed0423883febf85416343f4fa1f86',
    )
  })

  it('runs deterministic ML-KEM-1024 encapsulation and implicit rejection', () => {
    const keys = ml_kem1024.keygen(new Uint8Array(64).fill(0x31))
    const encapsulated = ml_kem1024.encapsulate(
      keys.publicKey,
      new Uint8Array(32).fill(0x72),
    )
    const decapsulated = ml_kem1024.decapsulate(encapsulated.cipherText, keys.secretKey)
    const tampered = encapsulated.cipherText.slice()
    tampered[0] ^= 1

    expect(keys.publicKey).toHaveLength(1568)
    expect(encapsulated.cipherText).toHaveLength(1568)
    expect(decapsulated).toEqual(encapsulated.sharedSecret)
    expect(ml_kem1024.decapsulate(tampered, keys.secretKey)).not.toEqual(
      encapsulated.sharedSecret,
    )
  })
})

describe('modeled limits', () => {
  it('cannot recompute SK from curve breaks without the KEM secret', async () => {
    const session = await runVerifiedHandshake()
    const grant = createAdversaryGrant(session, false)
    const result = recomputeAsAdversary(session, grant)

    expect(Object.keys(grant.curvePrivateKeys)).toHaveLength(5)
    expect('kemSharedSecret' in grant).toBe(false)
    expect(result.opened).toEqual(['DH1', 'DH2', 'DH3', 'DH4'])
    expect(result.sessionKey).toBeUndefined()
  })

  it('recomputes the honest SK only when the modeled lattice break grants SS', async () => {
    const session = await runVerifiedHandshake()
    const grant = createAdversaryGrant(session, true)
    const result = recomputeAsAdversary(session, grant)

    expect(result.opened).toContain('SS')
    expect(equalBytes(result.sessionKey!, session.alice.sessionKey)).toBe(true)
  })

  it('shows classical signatures accepting an impersonated bundle', async () => {
    const fixture = await runImpersonationFixture()

    // Assert the individual measurements, not just the summary. A summary that
    // is a hardcoded literal agrees with any of these being false.
    expect(fixture.signedPrekeySignatureValid).toBe(true)
    expect(fixture.pqPrekeySignatureValid).toBe(true)
    expect(fixture.signedByBobsIdentity).toBe(true)
    expect(fixture.initialMessageOpened).toBe(true)
    expect(fixture.checksGreen).toBe(true)
    expect(fixture.sessionKey).toHaveLength(32)
  })

  it('shows classical ratchet healing and modeled quantum readability', () => {
    const compromisedRoot = new Uint8Array(32).fill(0x42)
    const classical = runRatchetModel(compromisedRoot, false)
    const quantum = runRatchetModel(compromisedRoot, true)

    expect(classical.healed).toBe(true)
    expect(classical.stillReadable).toBe(false)
    expect(quantum.healed).toBe(true)
    expect(quantum.stillReadable).toBe(true)

    // `healed` must mean the chain moved, not that the loop ran a fixed number
    // of times: every root is distinct and the last one is not the compromise.
    const distinct = new Set(classical.honestRoots.map((root) => bytesToHex(root)))
    expect(distinct.size).toBe(4)
    expect(equalBytes(classical.honestRoots[0], compromisedRoot)).toBe(true)
    expect(equalBytes(classical.honestRoots.at(-1)!, compromisedRoot)).toBe(false)
    expect(classical.adversaryRoots).toHaveLength(1)
    expect(quantum.adversaryRoots).toHaveLength(4)

    // The adversary chain is built in both runs and compared elementwise, so
    // `stillReadable` is a measurement of two chains rather than a restatement
    // of the premise. Classically it stalls on the compromised root.
    expect(equalBytes(classical.adversaryRoots[0], compromisedRoot)).toBe(true)
    quantum.adversaryRoots.forEach((root, index) => {
      expect(equalBytes(root, quantum.honestRoots[index])).toBe(true)
    })
  })

  it('refuses a grant that is not a recovery of the wire public key', () => {
    // `stillReadable` used to recompute the honest step inline with Alice's
    // secret still in scope, so it had one reachable outcome. The adversary now
    // takes only the transcript plus a grant, and checks that the granted
    // secret really is the one behind the public key it saw.
    const root = new Uint8Array(32).fill(0x11)
    const alice = x25519.keygen()
    const bob = x25519.keygen()
    const transcript = { alicePublic: alice.publicKey, bobPublic: bob.publicKey }

    const followed = adversaryAdvance(root, transcript, {
      recoveredAliceSecret: alice.secretKey,
    })
    expect(followed).toBeDefined()

    expect(adversaryAdvance(root, transcript, {})).toBeUndefined()
    expect(
      adversaryAdvance(root, transcript, {
        recoveredAliceSecret: x25519.keygen().secretKey,
      }),
    ).toBeUndefined()
  })
})