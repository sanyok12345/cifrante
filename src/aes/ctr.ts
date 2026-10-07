import { toBinary, toBinaryView, toBytes, toBytesView } from '../bytes.js'
import { InvalidInputError } from '../errors.js'
import { lazy } from '../lazy.js'
import { createAesWasm } from '../wasm/aes.js'
import { nativeCipher } from '../native/web.js'
import type { Binary } from '../types.js'
import type { Cipher } from './aes.js'
import { AesBlock, ivBytes, keyBytes } from './block.js'

export function ctr(key: Binary): Cipher {
  const secret = keyBytes(key)
  const native = nativeCipher('ctr', secret)
  const prepare = lazy(() => createAesWasm(secret))
  let block: AesBlock | undefined

  async function transform(
    data: Uint8Array,
    initial: Uint8Array,
    decrypt: boolean,
    useNative: boolean,
  ): Promise<Uint8Array> {
    let carry = Math.max(0, Math.ceil(data.length / 16) - 1)

    for (let i = 15; i >= 0; i--) {
      carry = Math.floor((initial[i] + carry) / 256)
    }

    if (carry !== 0) {
      throw new InvalidInputError('AES-CTR counter would overflow')
    }

    if (useNative) {
      const result = await (decrypt
        ? native.decrypt(initial, data)
        : native.encrypt(initial, data))

      if (result !== undefined) {
        return result
      }
    }

    const wasm = prepare()

    if (wasm) {
      return wasm.transform('ctr', data, initial, decrypt)
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
      const useNative = native.available()
      const input = useNative ? toBytes(data) : toBytesView(data)
      const initial = ivBytes(options, 16, useNative)
      return transform(input, initial, false, useNative)
    },

    async decrypt(data, options) {
      const useNative = native.available()
      const input = useNative ? toBinary(data) : toBinaryView(data)
      const initial = ivBytes(options, 16, useNative)
      return transform(input, initial, true, useNative)
    },
  }
}
