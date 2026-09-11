import { x25519 } from '@noble/curves/ed25519.js'
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils.js'

import { encryptInitialMessage } from '../crypto/aead.js'
import { equalBytes } from '../crypto/bytes.js'
import { verifyPrekeySignature } from './bundle.js'
import { deriveSessionKey, type KdfComponents } from './kdf.js'
import type { InitialMessage, KeyPair, PublicBundle } from './types.js'

export class HandshakeAbort extends Error {
  override name = 'HandshakeAbort'
}

export interface AliceResult {
  identity: KeyPair
  ephemeral: KeyPair
  components: KdfComponents
  sessionKey: Uint8Array
  associatedData: Uint8Array
  message: InitialMessage
}

export async function runAlice(
  bundle: PublicBundle,
  identity: KeyPair = x25519.keygen(),
): Promise<AliceResult> {
  if (
    !verifyPrekeySignature(
      bundle.signedPrekeySignature,
      bundle.signedPrekeyPublic,
      bundle.identitySigningPublic,
    )
  ) {
    throw new HandshakeAbort('Signed X25519 prekey signature verification failed')
  }
  if (
    !verifyPrekeySignature(
      bundle.pqPrekeySignature,
      bundle.pqPrekeyPublic,
      bundle.identitySigningPublic,
    )
  ) {
    throw new HandshakeAbort('Signed ML-KEM prekey signature verification failed')
  }
  if (equalBytes(identity.publicKey, bundle.identityDhPublic)) {
    throw new HandshakeAbort('IK_A equals IK_B; refusing a reflected identity')
  }

  const ephemeral = x25519.keygen()
  const encapsulated = ml_kem1024.encapsulate(bundle.pqPrekeyPublic)
  const components: KdfComponents = {
    dh1: x25519.getSharedSecret(identity.secretKey, bundle.signedPrekeyPublic),
    dh2: x25519.getSharedSecret(ephemeral.secretKey, bundle.identityDhPublic),
    dh3: x25519.getSharedSecret(ephemeral.secretKey, bundle.signedPrekeyPublic),
    ...(bundle.oneTimePrekeyPublic
      ? {
          dh4: x25519.getSharedSecret(
            ephemeral.secretKey,
            bundle.oneTimePrekeyPublic,
          ),
        }
      : {}),
    sharedSecret: encapsulated.sharedSecret,
  }
  const sessionKey = deriveSessionKey(components)

  // Revision 2 binds the KEM public key in AD for KEMs that do not encode it in CT.
  const associatedData = concatBytes(
    identity.publicKey,
    bundle.identityDhPublic,
    bundle.pqPrekeyPublic,
  )
  const encrypted = await encryptInitialMessage(
    sessionKey,
    utf8ToBytes('PQXDH initial message'),
    associatedData,
  )

  return {
    identity,
    ephemeral,
    components,
    sessionKey,
    associatedData,
    message: {
      aliceIdentityPublic: identity.publicKey,
      aliceEphemeralPublic: ephemeral.publicKey,
      kemCiphertext: encapsulated.cipherText,
      aeadNonce: encrypted.nonce,
      aeadCiphertext: encrypted.ciphertext,
      signedPrekeyId: bundle.signedPrekeyId,
      ...(bundle.oneTimePrekeyId ? { oneTimePrekeyId: bundle.oneTimePrekeyId } : {}),
      pqPrekeyId: bundle.pqPrekeyId,
      pqPrekeyKind: bundle.pqPrekeyKind,
    },
  }
}