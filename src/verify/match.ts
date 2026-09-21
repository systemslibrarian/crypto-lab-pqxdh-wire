import { equalBytes } from '../crypto/bytes.js'

/**
 * The byte-for-byte session-key verdict, in exactly one place.
 *
 * The comparison panel used to ship `ALICE SK = BOB SK` as static markup that
 * nothing ever rewrote, so the page asserted a match it had not performed.
 * Every surface that renders that verdict now reads this function, which gives
 * a §4.1c mutation a single source to force and a single thing to watch go red.
 */
export function sessionKeysMatch(
  aliceSessionKey: Uint8Array,
  bobSessionKey: Uint8Array,
): boolean {
  return equalBytes(aliceSessionKey, bobSessionKey)
}
