export interface KeyPair {
  secretKey: Uint8Array
  publicKey: Uint8Array
}

export type PqPrekeyKind = 'one-time' | 'last-resort'

export interface BobPrivateState {
  identityDh: KeyPair
  identitySigning: KeyPair
  signedPrekey: KeyPair
  oneTimePrekey: KeyPair
  pqOneTimePrekey: KeyPair
  pqLastResortPrekey: KeyPair
}

export interface PublicBundle {
  identityDhPublic: Uint8Array
  identitySigningPublic: Uint8Array
  signedPrekeyPublic: Uint8Array
  signedPrekeySignature: Uint8Array
  oneTimePrekeyPublic?: Uint8Array
  pqPrekeyPublic: Uint8Array
  pqPrekeySignature: Uint8Array
  pqPrekeyKind: PqPrekeyKind
  signedPrekeyId: string
  oneTimePrekeyId?: string
  pqPrekeyId: string
}

export interface InitialMessage {
  aliceIdentityPublic: Uint8Array
  aliceEphemeralPublic: Uint8Array
  kemCiphertext: Uint8Array
  aeadNonce: Uint8Array
  aeadCiphertext: Uint8Array
  signedPrekeyId: string
  oneTimePrekeyId?: string
  pqPrekeyId: string
  pqPrekeyKind: PqPrekeyKind
}