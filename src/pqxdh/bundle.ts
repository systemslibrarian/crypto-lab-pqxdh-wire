import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js'

import { bytesToHex } from '../crypto/bytes.js'
import type { BobPrivateState, KeyPair, PublicBundle } from './types.js'

function idFor(publicKey: Uint8Array): string {
  return bytesToHex(publicKey.slice(0, 6))
}

function signPrekey(publicKey: Uint8Array, signingSecret: Uint8Array): Uint8Array {
  return ed25519.sign(publicKey, signingSecret)
}

export function verifyPrekeySignature(
  signature: Uint8Array,
  publicKey: Uint8Array,
  signingPublic: Uint8Array,
): boolean {
  return ed25519.verify(signature, publicKey, signingPublic, { zip215: false })
}

export function createBobState(): BobPrivateState {
  return {
    identityDh: x25519.keygen(),
    identitySigning: ed25519.keygen(),
    signedPrekey: x25519.keygen(),
    oneTimePrekey: x25519.keygen(),
    pqOneTimePrekey: ml_kem1024.keygen(),
    pqLastResortPrekey: ml_kem1024.keygen(),
  }
}

export function publishBundle(
  state: BobPrivateState,
  options: { useOneTimePq?: boolean; includeCurveOneTime?: boolean } = {},
): PublicBundle {
  const useOneTimePq = options.useOneTimePq ?? true
  const includeCurveOneTime = options.includeCurveOneTime ?? true
  const selectedPq = useOneTimePq ? state.pqOneTimePrekey : state.pqLastResortPrekey

  return {
    identityDhPublic: state.identityDh.publicKey,
    identitySigningPublic: state.identitySigning.publicKey,
    signedPrekeyPublic: state.signedPrekey.publicKey,
    signedPrekeySignature: signPrekey(
      state.signedPrekey.publicKey,
      state.identitySigning.secretKey,
    ),
    ...(includeCurveOneTime
      ? { oneTimePrekeyPublic: state.oneTimePrekey.publicKey }
      : {}),
    pqPrekeyPublic: selectedPq.publicKey,
    pqPrekeySignature: signPrekey(selectedPq.publicKey, state.identitySigning.secretKey),
    pqPrekeyKind: useOneTimePq ? 'one-time' : 'last-resort',
    signedPrekeyId: idFor(state.signedPrekey.publicKey),
    ...(includeCurveOneTime
      ? { oneTimePrekeyId: idFor(state.oneTimePrekey.publicKey) }
      : {}),
    pqPrekeyId: idFor(selectedPq.publicKey),
  }
}

export function cloneKeyPair(keyPair: KeyPair): KeyPair {
  return {
    secretKey: keyPair.secretKey.slice(),
    publicKey: keyPair.publicKey.slice(),
  }
}