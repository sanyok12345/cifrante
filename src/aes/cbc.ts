import { toBinary, toBytes } from '../bytes.js'
import { AuthenticationError, InvalidInputError } from '../errors.js'
import { nativeCipher } from '../native/web.js'
import type { Binary } from '../types.js'
import type { Cipher } from './aes.js'
import { AesBlock, ivBytes, keyBytes } from './block.js'

export function cbc(key: Binary): Cipher {
  const secret = keyBytes(key)
  const native = nativeCipher('cbc', secret)
  let block: AesBlock | undefined

  return {
    async encrypt(data, options) {
      const input = toBytes(data)
      const initial = ivBytes(options, 16)
      const result = await native.encrypt(initial, input)

      if (result !== undefined) {
        return result
      }

      block ??= new AesBlock(secret)

      const padding = 16 - input.length % 16
      const padded = new Uint8Array(input.length + padding)
      padded.set(input)
      padded.fill(padding, input.length)

      const output = new Uint8Array(padded.length)
      let previous: Uint8Array = initial
      const mixed = new Uint8Array(16)

      for (let offset = 0; offset < padded.length; offset += 16) {
        for (let i = 0; i < 16; i++) {
          mixed[i] = padded[offset + i] ^ previous[i]
        }

        previous = block.encrypt(mixed)
        output.set(previous, offset)
      }

      padded.fill(0)
      return output
    },

    async decrypt(data, options) {
      const input = toBinary(data)
      const initial = ivBytes(options, 16)

      if (input.length === 0 || input.length % 16 !== 0) {
        throw new InvalidInputError(
          'AES-CBC ciphertext must contain nonempty complete 16-byte blocks',
        )
      }

      const decrypted = await native.decrypt(initial, input)

      if (decrypted !== undefined) {
        return decrypted
      }

      block ??= new AesBlock(secret)

      const output = new Uint8Array(input.length)
      let previous: Uint8Array = initial

      for (let offset = 0; offset < input.length; offset += 16) {
        const ciphertext = input.subarray(offset, offset + 16)
        const result = block.decrypt(ciphertext)

        for (let i = 0; i < 16; i++) {
          output[offset + i] = result[i] ^ previous[i]
        }

        previous = ciphertext
      }

      const padding = output[output.length - 1]
      let invalid = Number(padding === 0 || padding > 16)

      for (let i = 1; i <= 16; i++) {
        invalid |= (output[output.length - i] ^ padding) & -(i <= padding ? 1 : 0)
      }

      if (invalid !== 0) {
        output.fill(0)
        throw new AuthenticationError('Invalid AES-CBC padding')
      }

      const plaintext = output.slice(0, output.length - padding)
      output.fill(0)
      return plaintext
    },
  }
}
