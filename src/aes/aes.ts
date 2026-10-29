import type { Backend } from '../aead.js'
import type { AbortOptions, Binary, Data, Disposal } from '../types.js'
import { cbc } from './cbc.js'
import type { CbcOptions } from './cbc.js'
import { ctr } from './ctr.js'
import { gcm } from './gcm.js'
import type { AeadCipher, GcmOptions } from './gcm.js'
import { ige } from './ige.js'

export type { Backend }

export interface CipherOptions extends AbortOptions {
  iv: Binary
  output?: Uint8Array
}

export interface Cipher {
  encrypt(data: Data, options: CipherOptions): Promise<Uint8Array>
  decrypt(data: Binary, options: CipherOptions): Promise<Uint8Array>
  encryptSync(data: Data, options: CipherOptions): Uint8Array
  decryptSync(data: Binary, options: CipherOptions): Uint8Array
  dispose(): void
  readonly backend: Backend
}

export interface CtrState {
  update(data: Data, output?: Uint8Array): Uint8Array
  dispose(): void
}

export interface CtrCipher extends Cipher {
  create(options: CipherOptions): CtrState & Disposal
}

export interface AES {
  ige(key: Binary): Cipher & Disposal
  ctr(key: Binary): CtrCipher & Disposal
  cbc(key: Binary, options?: CbcOptions): Cipher & Disposal
  gcm(key: Binary, options?: GcmOptions): AeadCipher & Disposal
}

export const aes: AES = { ige, ctr, cbc, gcm }
