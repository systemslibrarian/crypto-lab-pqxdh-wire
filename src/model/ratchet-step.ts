import { x25519 } from '@noble/curves/ed25519.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha512 } from '@noble/hashes/sha2.js'
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils.js'

import { equalBytes } from '../crypto/bytes.js'

const RATCHET_INFO = utf8ToBytes('PQXDH-Wire-reduced-DH-ratchet-step')

function deriveNextRoot(rootKey: Uint8Array, dhOutput: Uint8Array): Uint8Array {
  return hkdf(
    sha512,
    concatBytes(rootKey, dhOutput),
    new Uint8Array(sha512.outputLen),
    RATCHET_INFO,
    32,
  )
}

/** Exactly what a passive observer sees on the wire for one root update. */
export interface RatchetStepTranscript {
  alicePublic: Uint8Array
  bobPublic: Uint8Array
}

/**
 * What the model hands the adversary for one step. Under the curve-break
 * premise, Shor recovers Alice's ephemeral secret from `alicePublic`; with no
 * break granted, the adversary receives nothing and holds only the transcript.
 */
export interface AdversaryStepGrant {
  recoveredAliceSecret?: Uint8Array
}

export interface RatchetModelResult {
  honestRoots: Uint8Array[]
  adversaryRoots: Uint8Array[]
  healed: boolean
  stillReadable: boolean
}

/**
 * The adversary's own root update. It is deliberately a separate function that
 * closes over nothing: its only inputs are its previous root, the public
 * transcript, and the grant. The earlier version recomputed the step inline
 * with `alice.secretKey` still in scope — the identical expression three lines
 * above the honest one, off a chain that was only ever extended under
 * `quantumBreak` — so `stillReadable` had one reachable outcome and was a
 * verdict that could not report false. Here the adversary advances only if the
 * grant actually carries a secret, and only if that secret really is the one
 * behind the public key on the wire; otherwise it stays on its last root.
 */
export function adversaryAdvance(
  previousRoot: Uint8Array,
  transcript: RatchetStepTranscript,
  grant: AdversaryStepGrant,
): Uint8Array | undefined {
  const secret = grant.recoveredAliceSecret
  if (!secret) return undefined
  if (!equalBytes(x25519.getPublicKey(secret), transcript.alicePublic)) return undefined
  return deriveNextRoot(previousRoot, x25519.getSharedSecret(secret, transcript.bobPublic))
}

export function runRatchetModel(
  compromisedRoot: Uint8Array,
  quantumBreak: boolean,
): RatchetModelResult {
  const honestRoots = [compromisedRoot]
  const adversaryRoots = [compromisedRoot]

  for (let step = 0; step < 3; step += 1) {
    const alice = x25519.keygen()
    const bob = x25519.keygen()
    const aliceDh = x25519.getSharedSecret(alice.secretKey, bob.publicKey)
    const bobDh = x25519.getSharedSecret(bob.secretKey, alice.publicKey)
    const nextAliceRoot = deriveNextRoot(honestRoots.at(-1)!, aliceDh)
    const nextBobRoot = deriveNextRoot(honestRoots.at(-1)!, bobDh)
    if (!equalBytes(nextAliceRoot, nextBobRoot)) {
      throw new Error('Reduced ratchet peers disagreed')
    }
    honestRoots.push(nextAliceRoot)

    const transcript: RatchetStepTranscript = {
      alicePublic: alice.publicKey,
      bobPublic: bob.publicKey,
    }
    const grant: AdversaryStepGrant = quantumBreak
      ? { recoveredAliceSecret: alice.secretKey }
      : {}
    if (adversaryRoots.length === step + 1) {
      const next = adversaryAdvance(adversaryRoots.at(-1)!, transcript, grant)
      if (next) adversaryRoots.push(next)
    }
  }

  // Measured against a chain that is always built — including the classical case
  // where it stalls at the compromised root — so this comparison has two
  // reachable outcomes instead of restating its own premise.
  const stillReadable =
    adversaryRoots.length === honestRoots.length &&
    honestRoots.every((root, index) => equalBytes(root, adversaryRoots[index]))

  // Measured, not counted. `honestRoots.length === 4` is true by construction of
  // the loop above, so it reported HEALED even if every step had left the root
  // unchanged. Healing means each step actually replaced the root and the chain
  // has left the compromised value behind.
  const healed =
    honestRoots.length === 4 &&
    honestRoots.every(
      (root, index) => index === 0 || !equalBytes(root, honestRoots[index - 1]),
    ) &&
    !equalBytes(honestRoots.at(-1)!, compromisedRoot)
  return {
    honestRoots,
    adversaryRoots,
    healed,
    stillReadable,
  }
}
