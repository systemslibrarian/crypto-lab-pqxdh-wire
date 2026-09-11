import { x25519 } from '@noble/curves/ed25519.js'

import { deriveSessionKey, type KdfComponents } from '../pqxdh/kdf.js'
import { createBobState, publishBundle } from '../pqxdh/bundle.js'
import { runAlice } from '../pqxdh/alice.js'
import { runBob } from '../pqxdh/bob.js'
import type { KeyPair } from '../pqxdh/types.js'
import type { VerifiedSession } from '../verify/session.js'

export interface CurvePrivateKeyGrant {
  aliceIdentity: Uint8Array
  aliceEphemeral: Uint8Array
  bobIdentity: Uint8Array
  bobSignedPrekey: Uint8Array
  bobOneTimePrekey: Uint8Array
}

export interface AdversaryGrant {
  curvePrivateKeys: CurvePrivateKeyGrant
  kemSharedSecret?: Uint8Array
}

export interface AdversaryResult {
  opened: Array<'DH1' | 'DH2' | 'DH3' | 'DH4' | 'SS'>
  components: Required<Omit<KdfComponents, 'sharedSecret'>>
  sessionKey?: Uint8Array
}

export function createAdversaryGrant(
  session: VerifiedSession,
  includeLatticeBreak: boolean,
): AdversaryGrant {
  const curvePrivateKeys: CurvePrivateKeyGrant = {
    aliceIdentity: session.alice.identity.secretKey,
    aliceEphemeral: session.alice.ephemeral.secretKey,
    bobIdentity: session.bobState.identityDh.secretKey,
    bobSignedPrekey: session.bobState.signedPrekey.secretKey,
    bobOneTimePrekey: session.bobState.oneTimePrekey.secretKey,
  }
  return {
    curvePrivateKeys,
    ...(includeLatticeBreak
      ? { kemSharedSecret: session.alice.components.sharedSecret }
      : {}),
  }
}

export function recomputeAsAdversary(
  session: VerifiedSession,
  grant: AdversaryGrant,
): AdversaryResult {
  const components = {
    dh1: x25519.getSharedSecret(
      grant.curvePrivateKeys.aliceIdentity,
      session.bundle.signedPrekeyPublic,
    ),
    dh2: x25519.getSharedSecret(
      grant.curvePrivateKeys.aliceEphemeral,
      session.bundle.identityDhPublic,
    ),
    dh3: x25519.getSharedSecret(
      grant.curvePrivateKeys.aliceEphemeral,
      session.bundle.signedPrekeyPublic,
    ),
    dh4: x25519.getSharedSecret(
      grant.curvePrivateKeys.aliceEphemeral,
      session.bundle.oneTimePrekeyPublic!,
    ),
  }
  if (!grant.kemSharedSecret) {
    return { opened: ['DH1', 'DH2', 'DH3', 'DH4'], components }
  }
  return {
    opened: ['DH1', 'DH2', 'DH3', 'DH4', 'SS'],
    components,
    sessionKey: deriveSessionKey({
      ...components,
      sharedSecret: grant.kemSharedSecret,
    }),
  }
}

export async function runImpersonationFixture(): Promise<{
  checksGreen: boolean
  sessionKey: Uint8Array
}> {
  const bob = createBobState()
  const attacker = createBobState()
  const forgedState = {
    ...attacker,
    identityDh: bob.identityDh,
    identitySigning: bob.identitySigning,
  }
  const forgedBundle = publishBundle(forgedState)
  const alice = await runAlice(forgedBundle)
  const adversary = await runBob(forgedState, forgedBundle, alice.message)
  return { checksGreen: true, sessionKey: adversary.sessionKey }
}

export function cloneIdentity(identity: KeyPair): KeyPair {
  return { secretKey: identity.secretKey.slice(), publicKey: identity.publicKey.slice() }
}