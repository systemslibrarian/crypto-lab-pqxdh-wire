import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { hexToBytes } from '@noble/hashes/utils.js'
import { describe, expect, it } from 'vitest'

import { deriveSessionKey, encodeKdfInput, F_PREFIX } from './kdf.js'

const component = (byte: number) => new Uint8Array(32).fill(byte)

describe('PQXDH KDF', () => {
  it('passes RFC 5869 test case 1', () => {
    const output = hkdf(
      sha256,
      hexToBytes('0b'.repeat(22)),
      hexToBytes('000102030405060708090a0b0c'),
      hexToBytes('f0f1f2f3f4f5f6f7f8f9'),
      42,
    )

    expect(output).toEqual(
      hexToBytes(
        '3cb25f25faacd57a90434f64d0362f2a' +
          '2d2d0a90cf1a5a4c5db02d56ecc4c5bf' +
          '34007208d5b887185865',
      ),
    )
  })

  it('prefixes the transcript with exactly 32 0xff bytes', () => {
    const components = {
      dh1: component(1),
      dh2: component(2),
      dh3: component(3),
      dh4: component(4),
      sharedSecret: component(5),
    }
    const input = encodeKdfInput(components)

    expect(F_PREFIX).toHaveLength(32)
    expect([...F_PREFIX].every((byte) => byte === 0xff)).toBe(true)
    expect(input.slice(0, 32)).toEqual(F_PREFIX)
    expect(input).toHaveLength(192)
    expect(deriveSessionKey(components)).toHaveLength(32)
  })
})