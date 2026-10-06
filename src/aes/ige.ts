import { toBinary, toBytes } from '../bytes.js'
import { InvalidInputError } from '../errors.js'
import type { Binary } from '../types.js'
import type { Cipher } from './aes.js'
import { AesBlock, ivBytes, keyBytes } from './block.js'
import { lazy } from '../lazy.js'
import { createAesWasm } from '../wasm/aes.js'

export function ige(key: Binary): Cipher {
  const secret = keyBytes(key)
  const prepare = lazy(() => createAesWasm(secret))
  let block: AesBlock | undefined

  function transform(
    data: Uint8Array,
    initial: Uint8Array,
    decrypt: boolean,
  ): Uint8Array<ArrayBuffer> {
    if (data.length % 16 !== 0) {
      throw new InvalidInputError('AES-IGE input must contain complete 16-byte blocks')
    }

    if (data.length === 0) {
      return new Uint8Array()
    }

    const wasm = prepare()

    if (wasm) {
      return wasm.transform('ige', data, initial, decrypt)
    }

    block ??= new AesBlock(secret)

    const output = new Uint8Array(data.length)
    let previousCiphertext: Uint8Array = initial.subarray(0, 16)
    let previousPlaintext: Uint8Array = initial.subarray(16, 32)
    const mixed = new Uint8Array(16)

    for (let offset = 0; offset < data.length; offset += 16) {
      const input = data.subarray(offset, offset + 16)
      const before = decrypt ? previousPlaintext : previousCiphertext
      const after = decrypt ? previousCiphertext : previousPlaintext

      for (let i = 0; i < 16; i++) {
        mixed[i] = input[i] ^ before[i]
      }

      const result = decrypt ? block.decrypt(mixed) : block.encrypt(mixed)

      for (let i = 0; i < 16; i++) {
        result[i] ^= after[i]
      }

      output.set(result, offset)
      previousCiphertext = decrypt ? input : result
      previousPlaintext = decrypt ? result : input
    }

    return output
  }

  return {
    async encrypt(data, options) {
      const input = toBytes(data)
      const initial = ivBytes(options, 32)
      return transform(input, initial, false)
    },

    async decrypt(data, options) {
      const input = toBinary(data)
      const initial = ivBytes(options, 32)
      return transform(input, initial, true)
    },
  }
}
