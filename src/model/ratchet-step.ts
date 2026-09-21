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

export interface RatchetModelResult {
  honestRoots: Uint8Array[]
  adversaryRoots: Uint8Array[]
  healed: boolean
  stillReadable: boolean
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

    if (quantumBreak) {
      const modeledRecoveredDh = x25519.getSharedSecret(alice.secretKey, bob.publicKey)
      adversaryRoots.push(deriveNextRoot(adversaryRoots.at(-1)!, modeledRecoveredDh))
    }
  }

  const stillReadable =
    quantumBreak && equalBytes(honestRoots.at(-1)!, adversaryRoots.at(-1)!)
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