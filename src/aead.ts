import type { AbortOptions, Binary, Data } from './types.js'

export type Backend = 'native' | 'wasm' | 'js'

export interface AeadOptions extends AbortOptions {
  nonce: Binary
  aad?: Data
}

export interface Sealed {
  ciphertext: Uint8Array
  tag: Uint8Array
}

export interface AeadCipher {
  encrypt(data: Data, options: AeadOptions): Promise<Sealed>
  decrypt(data: Sealed, options: AeadOptions): Promise<Uint8Array>
  encryptSync(data: Data, options: AeadOptions): Sealed
  decryptSync(data: Sealed, options: AeadOptions): Uint8Array
  dispose(): void
  readonly backend: Backend
}
