import { x25519 } from '@noble/curves/ed25519.js'

import { equalBytes } from '../crypto/bytes.js'
import { deriveSessionKey, type KdfComponents } from '../pqxdh/kdf.js'
import { createBobState, publishBundle, verifyPrekeySignature } from '../pqxdh/bundle.js'
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

export interface ImpersonationFixture {
  /** Ed25519 over SPK_B, re-verified against the identity key Alice trusts. */
  signedPrekeySignatureValid: boolean
  /** Ed25519 over PQOPK_B, re-verified the same way. */
  pqPrekeySignatureValid: boolean
  /** The bundle is signed by Bob's real identity key, so it authenticates as Bob. */
  signedByBobsIdentity: boolean
  /** The adversary really opened Alice's initial AES-GCM message. */
  initialMessageOpened: boolean
  /** Every check above, measured — not a constant. */
  checksGreen: boolean
  sessionKey: Uint8Array
}

const INITIAL_MESSAGE_PLAINTEXT = 'PQXDH initial message'

/**
 * The negative claim, as a result rather than a disclaimer: PQXDH's prekey
 * signature is classical, so a model granted Bob's Ed25519 signing key and his
 * X25519 identity key publishes a bundle that passes every check Alice makes.
 *
 * Each verdict below is measured after the fact — the prekey signatures are
 * re-verified independently of runAlice's control flow, and the "message opened"
 * verdict compares the plaintext the adversary recovered against what Alice sent
 * plus a byte-for-byte session-key comparison. Returning `checksGreen: true` as a
 * literal (as this did) made the page's headline claim an assertion about the
 * fixture rather than evidence from it, which _MASTER-TEMPLATE.md §4.1d forbids:
 * assertion 2 must hold "against the rendered verdicts, not a flag the test sets".
 */
export async function runImpersonationFixture(): Promise<ImpersonationFixture> {
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

  const signedPrekeySignatureValid = verifyPrekeySignature(
    forgedBundle.signedPrekeySignature,
    forgedBundle.signedPrekeyPublic,
    forgedBundle.identitySigningPublic,
  )
  const pqPrekeySignatureValid = verifyPrekeySignature(
    forgedBundle.pqPrekeySignature,
    forgedBundle.pqPrekeyPublic,
    forgedBundle.identitySigningPublic,
  )
  const signedByBobsIdentity = equalBytes(
    forgedBundle.identitySigningPublic,
    bob.identitySigning.publicKey,
  )
  const initialMessageOpened =
    new TextDecoder().decode(adversary.plaintext) === INITIAL_MESSAGE_PLAINTEXT &&
    equalBytes(alice.sessionKey, adversary.sessionKey)

  return {
    signedPrekeySignatureValid,
    pqPrekeySignatureValid,
    signedByBobsIdentity,
    initialMessageOpened,
    checksGreen:
      signedPrekeySignatureValid &&
      pqPrekeySignatureValid &&
      signedByBobsIdentity &&
      initialMessageOpened,
    sessionKey: adversary.sessionKey,
  }
}

export function cloneIdentity(identity: KeyPair): KeyPair {
  return { secretKey: identity.secretKey.slice(), publicKey: identity.publicKey.slice() }
}