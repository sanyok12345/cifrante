import { toBinary, toBytes } from '../bytes.js'
import { InvalidInputError } from '../errors.js'
import { nativeCipher } from '../platform/web.js'
import type { Binary } from '../types.js'
import type { Cipher } from './aes.js'
import { AesBlock, ivBytes, keyBytes } from './block.js'

export function ctr(key: Binary): Cipher {
  const secret = keyBytes(key)
  const native = nativeCipher('ctr', secret)
  let block: AesBlock | undefined

  async function transform(
    data: Uint8Array,
    initial: Uint8Array,
    decrypt: boolean,
  ): Promise<Uint8Array> {
    let carry = Math.max(0, Math.ceil(data.length / 16) - 1)

    for (let i = 15; i >= 0; i--) {
      carry = Math.floor((initial[i] + carry) / 256)
    }

    if (carry !== 0) {
      throw new InvalidInputError('AES-CTR counter would overflow')
    }

    const result = await (decrypt
      ? native.decrypt(initial, data)
      : native.encrypt(initial, data))

    if (result !== undefined) {
      return result
    }

    block ??= new AesBlock(secret)

    const counter = initial.slice()
    const output = new Uint8Array(data.length)

    for (let offset = 0; offset < data.length; offset += 16) {
      const stream = block.encrypt(counter)

      for (let i = 0; i < Math.min(16, data.length - offset); i++) {
        output[offset + i] = data[offset + i] ^ stream[i]
      }

      for (let i = 15; i >= 0; i--) {
        counter[i] = (counter[i] + 1) & 255

        if (counter[i] !== 0) {
          break
        }
      }
    }

    return output
  }

  return {
    async encrypt(data, options) {
      const input = toBytes(data)
      const initial = ivBytes(options, 16)
      return transform(input, initial, false)
    },

    async decrypt(data, options) {
      const input = toBinary(data)
      const initial = ivBytes(options, 16)
      return transform(input, initial, true)
    },
  }
}
