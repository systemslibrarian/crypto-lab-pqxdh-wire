import { concatBytes } from '@noble/hashes/utils.js'

import type { InitialMessage } from '../pqxdh/types.js'

/**
 * What the initial message actually costs, and what it actually carries.
 *
 * The message strip used to print `1,568 B`, `1,632 B` and `0 B` as literals in
 * the page template. Two of those happened to be right and the third — "no
 * secret crossed the wire" — is the strongest claim on the page, stated as a
 * number that no run produced. A rendered number is a claim in exactly the way
 * a rendered word is, so each one is measured here from the bytes the handshake
 * really built, and each is marked and mutation-covered like any other verdict.
 */
export interface WireMeasurement {
  kemCiphertextBytes: number
  associatedDataBytes: number
  secretBytesOnWire: number
  scannedSecretBytes: number
}

/** True when `needle` appears as a contiguous run inside `haystack`. */
export function containsBytes(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length === 0) return false
  for (let start = 0; start + needle.length <= haystack.length; start += 1) {
    let matched = true
    for (let index = 0; index < needle.length; index += 1) {
      if (haystack[start + index] !== needle[index]) {
        matched = false
        break
      }
    }
    if (matched) return true
  }
  return false
}

/** Exactly the bytes Alice puts on the wire — no private value is in scope here. */
export function wireBytes(message: InitialMessage): Uint8Array {
  return concatBytes(
    message.aliceIdentityPublic,
    message.aliceEphemeralPublic,
    message.kemCiphertext,
    message.aeadNonce,
    message.aeadCiphertext,
  )
}

export function measureWire(
  message: InitialMessage,
  associatedData: Uint8Array,
  secrets: readonly Uint8Array[],
): WireMeasurement {
  const wire = wireBytes(message)
  let secretBytesOnWire = 0
  for (const secret of secrets) {
    if (containsBytes(wire, secret)) secretBytesOnWire += secret.length
  }
  // Summed over the secrets actually searched, never a count multiplied by an
  // assumed width. A search that reports "nothing found" is only evidence if
  // the page can also say how much it looked for.
  const scannedSecretBytes = secrets.reduce((total, secret) => total + secret.length, 0)
  return {
    kemCiphertextBytes: message.kemCiphertext.length,
    associatedDataBytes: associatedData.length,
    secretBytesOnWire,
    scannedSecretBytes,
  }
}
