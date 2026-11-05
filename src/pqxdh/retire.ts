import type { AliceResult } from './alice'
import type { BobResult } from './bob'
import type { BobPrivateState } from './types'

/** Overwrite each array in place. A missing array is simply skipped. */
export function wipeSecrets(...values: Array<Uint8Array | undefined>): void {
  for (const value of values) value?.fill(0)
}

/**
 * Best-effort erasure of every secret the live handshake still holds.
 *
 * The page claims this happens — "Reset overwrites the live handshake's
 * retained secret arrays" — so it needs a test, and it cannot have one while it
 * closes over module-scoped state in main.ts. Making it take its subjects also
 * makes what it covers checkable: `retire.test.ts` asserts every named array is
 * zeroed, and that is the list the claim rests on.
 *
 * JavaScript cannot guarantee secure erasure: an engine may have copied these
 * bytes during a GC move or into a detached buffer, and nothing here can reach
 * such a copy. Only discarding the page context does. The README and the
 * in-page profile both say so.
 */
export function retireHandshakeSecrets(
  bobState: BobPrivateState | undefined,
  alice: AliceResult | undefined,
  bob: BobResult | undefined,
): void {
  if (bobState) {
    wipeSecrets(
      bobState.identityDh.secretKey,
      bobState.identitySigning.secretKey,
      bobState.signedPrekey.secretKey,
      bobState.oneTimePrekey.secretKey,
      bobState.pqOneTimePrekey.secretKey,
      bobState.pqLastResortPrekey.secretKey,
    )
  }
  if (alice) {
    wipeSecrets(
      alice.identity.secretKey,
      alice.ephemeral.secretKey,
      alice.components.dh1,
      alice.components.dh2,
      alice.components.dh3,
      alice.components.dh4,
      alice.components.sharedSecret,
      alice.sessionKey,
    )
  }
  if (bob) {
    wipeSecrets(
      bob.components.dh1,
      bob.components.dh2,
      bob.components.dh3,
      bob.components.dh4,
      bob.components.sharedSecret,
      bob.sessionKey,
      bob.plaintext,
    )
  }
}
