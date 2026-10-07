import { toBinary, toBinaryView, toBytes, toBytesView } from '../bytes.js'
import { InvalidInputError } from '../errors.js'
import { lazy } from '../lazy.js'
import { createAesWasm } from '../wasm/aes.js'
import { nativeCipher } from '../native/web.js'
import type { Binary } from '../types.js'
import { SLICE, stable } from '../yield.js'
import type { Cipher } from './aes.js'
import { AesBlock, ivBytes, keyBytes } from './block.js'

export function ctr(key: Binary): Cipher {
  const secret = keyBytes(key)
  const native = nativeCipher('ctr', secret)
  const prepare = lazy(() => createAesWasm(secret))
  let block: AesBlock | undefined

  function validate(data: Uint8Array, initial: Uint8Array): void {
    let carry = Math.max(0, Math.ceil(data.length / 16) - 1)

    for (let i = 15; i >= 0; i--) {
      carry = Math.floor((initial[i] + carry) / 256)
    }

    if (carry !== 0) {
      throw new InvalidInputError('AES-CTR counter would overflow')
    }
  }

  function fallback(data: Uint8Array, initial: Uint8Array): Uint8Array<ArrayBuffer> {
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

  function transform(
    data: Uint8Array,
    initial: Uint8Array,
    decrypt: boolean,
  ): Uint8Array<ArrayBuffer> {
    const wasm = prepare()

    return wasm ? wasm.transform('ctr', data, initial, decrypt) : fallback(data, initial)
  }

  async function transformAsync(
    data: Uint8Array,
    initial: Uint8Array,
    decrypt: boolean,
    useNative: boolean,
  ): Promise<Uint8Array> {
    validate(data, initial)

    if (useNative) {
      const result = await (decrypt
        ? native.decrypt(initial, data)
        : native.encrypt(initial, data))

      if (result !== undefined) {
        return result
      }
    }

    if (data.length <= SLICE) {
      return transform(data, initial, decrypt)
    }

    const wasm = prepare()

    return wasm
      ? wasm.transformAsync('ctr', useNative ? data : stable(data), initial, decrypt)
      : fallback(data, initial)
  }

  return {
    async encrypt(data, options) {
      const useNative = native.available()
      const input = useNative ? toBytes(data) : toBytesView(data)
      const initial = ivBytes(options, 16, useNative)
      return transformAsync(input, initial, false, useNative)
    },

    async decrypt(data, options) {
      const useNative = native.available()
      const input = useNative ? toBinary(data) : toBinaryView(data)
      const initial = ivBytes(options, 16, useNative)
      return transformAsync(input, initial, true, useNative)
    },
  }
}
