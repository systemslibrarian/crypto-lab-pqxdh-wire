export interface AeadCiphertext {
  nonce: Uint8Array
  ciphertext: Uint8Array
}

async function importKey(rawKey: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', new Uint8Array(rawKey), 'AES-GCM', false, [
    'encrypt',
    'decrypt',
  ])
}

export async function encryptInitialMessage(
  key: Uint8Array,
  plaintext: Uint8Array,
  associatedData: Uint8Array,
): Promise<AeadCiphertext> {
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const cryptoKey = await importKey(key)
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: new Uint8Array(associatedData) },
    cryptoKey,
    new Uint8Array(plaintext),
  )
  return { nonce, ciphertext: new Uint8Array(ciphertext) }
}

export async function decryptInitialMessage(
  key: Uint8Array,
  encrypted: AeadCiphertext,
  associatedData: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await importKey(key)
  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: new Uint8Array(encrypted.nonce),
      additionalData: new Uint8Array(associatedData),
    },
    cryptoKey,
    new Uint8Array(encrypted.ciphertext),
  )
  return new Uint8Array(plaintext)
}