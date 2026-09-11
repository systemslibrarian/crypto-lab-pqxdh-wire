import { hkdf } from '@noble/hashes/hkdf.js'
import { sha512 } from '@noble/hashes/sha2.js'
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils.js'

export const F_PREFIX = new Uint8Array(32).fill(0xff)
export const PQXDH_INFO = utf8ToBytes('PQXDH_CURVE25519_SHA-512_ML-KEM-1024')

export interface KdfComponents {
  dh1: Uint8Array
  dh2: Uint8Array
  dh3: Uint8Array
  dh4?: Uint8Array
  sharedSecret: Uint8Array
}

export function encodeKdfInput(components: KdfComponents): Uint8Array {
  return concatBytes(
    F_PREFIX,
    components.dh1,
    components.dh2,
    components.dh3,
    ...(components.dh4 ? [components.dh4] : []),
    components.sharedSecret,
  )
}

export function deriveSessionKey(components: KdfComponents): Uint8Array {
  const zeroSalt = new Uint8Array(sha512.outputLen)
  return hkdf(sha512, encodeKdfInput(components), zeroSalt, PQXDH_INFO, 32)
}