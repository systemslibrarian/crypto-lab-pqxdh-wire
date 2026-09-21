import { runAlice, type AliceResult } from '../pqxdh/alice.js'
import { runBob, type BobResult } from '../pqxdh/bob.js'
import { createBobState, publishBundle } from '../pqxdh/bundle.js'
import type { BobPrivateState, PublicBundle } from '../pqxdh/types.js'
import { sessionKeysMatch } from './match.js'

export interface VerifiedSession {
  bobState: BobPrivateState
  bundle: PublicBundle
  alice: AliceResult
  bob: BobResult
  keysMatch: boolean
}

export async function runVerifiedHandshake(
  useOneTimePq = true,
): Promise<VerifiedSession> {
  const bobState = createBobState()
  const bundle = publishBundle(bobState, { useOneTimePq })
  const alice = await runAlice(bundle)
  const bob = await runBob(bobState, bundle, alice.message)
  return {
    bobState,
    bundle,
    alice,
    bob,
    keysMatch: sessionKeysMatch(alice.sessionKey, bob.sessionKey),
  }
}