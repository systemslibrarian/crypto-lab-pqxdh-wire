import { x25519 } from '@noble/curves/ed25519.js'
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { concatBytes } from '@noble/hashes/utils.js'

import { decryptInitialMessage } from '../crypto/aead.js'
import { deriveSessionKey, type KdfComponents } from './kdf.js'
import { HandshakeAbort } from './alice.js'
import type { BobPrivateState, InitialMessage, PublicBundle } from './types.js'

export interface BobResult {
  components: KdfComponents
  sessionKey: Uint8Array
  plaintext: Uint8Array
}

export async function runBob(
  state: BobPrivateState,
  bundle: PublicBundle,
  message: InitialMessage,
): Promise<BobResult> {
  if (
    message.signedPrekeyId !== bundle.signedPrekeyId ||
    message.oneTimePrekeyId !== bundle.oneTimePrekeyId ||
    message.pqPrekeyId !== bundle.pqPrekeyId
  ) {
    throw new HandshakeAbort('Initial message references an unknown prekey')
  }

  const pqPrekey =
    message.pqPrekeyKind === 'one-time'
      ? state.pqOneTimePrekey
      : state.pqLastResortPrekey
  const components: KdfComponents = {
    dh1: x25519.getSharedSecret(
      state.signedPrekey.secretKey,
      message.aliceIdentityPublic,
    ),
    dh2: x25519.getSharedSecret(
      state.identityDh.secretKey,
      message.aliceEphemeralPublic,
    ),
    dh3: x25519.getSharedSecret(
      state.signedPrekey.secretKey,
      message.aliceEphemeralPublic,
    ),
    ...(message.oneTimePrekeyId
      ? {
          dh4: x25519.getSharedSecret(
            state.oneTimePrekey.secretKey,
            message.aliceEphemeralPublic,
          ),
        }
      : {}),
    sharedSecret: ml_kem1024.decapsulate(message.kemCiphertext, pqPrekey.secretKey),
  }
  const sessionKey = deriveSessionKey(components)
  const associatedData = concatBytes(
    message.aliceIdentityPublic,
    state.identityDh.publicKey,
    pqPrekey.publicKey,
  )

  try {
    const plaintext = await decryptInitialMessage(
      sessionKey,
      { nonce: message.aeadNonce, ciphertext: message.aeadCiphertext },
      associatedData,
    )
    return { components, sessionKey, plaintext }
  } catch {
    throw new HandshakeAbort(
      'Initial AEAD authentication failed after ML-KEM implicit rejection',
    )
  }
}