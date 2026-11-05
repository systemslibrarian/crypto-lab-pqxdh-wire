import { describe, expect, it } from 'vitest'

import { runVerifiedHandshake } from '../verify/session.js'
import { retireHandshakeSecrets, wipeSecrets } from './retire.js'

/**
 * The page and the README both claim reset "overwrites the live handshake's
 * retained secret arrays". That claim had no test: making the wipe a no-op left
 * all 22 unit and 26 browser tests green, because the browser can only see the
 * rendered key TEXT disappear, not whether the arrays behind it were cleared.
 */
describe('retireHandshakeSecrets', () => {
  it('zeroes every secret array a completed handshake still holds', async () => {
    const session = await runVerifiedHandshake()
    const { bobState, alice, bob } = session

    // The arrays the claim covers, captured by reference before the wipe.
    // Typed as possibly-undefined so an array that becomes optional reddens
    // here rather than being silently skipped.
    const secrets: Array<[string, Uint8Array | undefined]> = [
      ['bob.identityDh', bobState.identityDh.secretKey],
      ['bob.identitySigning', bobState.identitySigning.secretKey],
      ['bob.signedPrekey', bobState.signedPrekey.secretKey],
      ['bob.oneTimePrekey', bobState.oneTimePrekey.secretKey],
      ['bob.pqOneTimePrekey', bobState.pqOneTimePrekey.secretKey],
      ['bob.pqLastResortPrekey', bobState.pqLastResortPrekey.secretKey],
      ['alice.identity', alice.identity.secretKey],
      ['alice.ephemeral', alice.ephemeral.secretKey],
      ['alice.dh1', alice.components.dh1],
      ['alice.dh2', alice.components.dh2],
      ['alice.dh3', alice.components.dh3],
      ['alice.dh4', alice.components.dh4],
      ['alice.sharedSecret', alice.components.sharedSecret],
      ['alice.sessionKey', alice.sessionKey],
      ['bob.dh1', bob.components.dh1],
      ['bob.dh2', bob.components.dh2],
      ['bob.dh3', bob.components.dh3],
      ['bob.dh4', bob.components.dh4],
      ['bob.sharedSecret', bob.components.sharedSecret],
      ['bob.sessionKey', bob.sessionKey],
      ['bob.plaintext', bob.plaintext],
    ]

    // A handshake that produced only zeros would make the assertion below
    // vacuous, so check there is something to erase first.
    for (const [name, bytes] of secrets) {
      expect(bytes, name).toBeDefined()
      expect(bytes!.length, name).toBeGreaterThan(0)
      expect(bytes!.some((byte) => byte !== 0), `${name} before`).toBe(true)
    }

    retireHandshakeSecrets(bobState, alice, bob)

    for (const [name, bytes] of secrets) {
      expect(bytes!.every((byte) => byte === 0), `${name} after`).toBe(true)
    }
  })

  it('tolerates a handshake that never started', () => {
    expect(() => retireHandshakeSecrets(undefined, undefined, undefined)).not.toThrow()
  })

  it('skips an absent array rather than throwing', () => {
    const present = Uint8Array.from([1, 2, 3])
    expect(() => wipeSecrets(undefined, present, undefined)).not.toThrow()
    expect([...present]).toEqual([0, 0, 0])
  })
})
