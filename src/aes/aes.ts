import type { Binary, Data } from '../types.js'
import { cbc } from './cbc.js'
import { ctr } from './ctr.js'
import { gcm } from './gcm.js'
import type { AeadCipher, GcmOptions } from './gcm.js'
import { ige } from './ige.js'

export interface CipherOptions {
  iv: Binary
}

export interface Cipher {
  encrypt(data: Data, options: CipherOptions): Promise<Uint8Array>
  decrypt(data: Binary, options: CipherOptions): Promise<Uint8Array>
}

export interface AES {
  ige(key: Binary): Cipher
  ctr(key: Binary): Cipher
  cbc(key: Binary): Cipher
  gcm(key: Binary, options?: GcmOptions): AeadCipher
}

export const aes: AES = { ige, ctr, cbc, gcm }
