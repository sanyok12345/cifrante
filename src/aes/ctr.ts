import { toBinary, toBinaryView, toBytes, toBytesView } from '../bytes.js'
import { lazy } from '../lazy.js'
import { createAesWasm } from '../wasm/aes.js'
import { nativeCipher } from '../native/web.js'
import type { Binary } from '../types.js'
import { SLICE } from '../yield.js'
import type { Cipher } from './aes.js'
import { AesBlock, ivBytes, keyBytes } from './block.js'

export function ctr(key: Binary): Cipher {
  const secret = keyBytes(key)
  const native = nativeCipher('ctr', secret)
  const prepare = lazy(() => createAesWasm(secret))
  let block: AesBlock | undefined

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

    return wasm ? wasm.transformAsync('ctr', data, initial, decrypt) : fallback(data, initial)
  }

  function transformSync(data: Uint8Array, initial: Uint8Array, decrypt: boolean): Uint8Array {
    const result = decrypt ? native.decryptSync?.(initial, data) : native.encryptSync?.(initial, data)

    return result ?? transform(data, initial, decrypt)
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

    encryptSync(data, options) {
      return transformSync(toBytesView(data), ivBytes(options, 16, false), false)
    },

    decryptSync(data, options) {
      return transformSync(toBinaryView(data), ivBytes(options, 16, false), true)
    },
  }
}
