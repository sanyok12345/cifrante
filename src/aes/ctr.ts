import { toBinary, toBinaryView, toBytes, toBytesView } from '../bytes.js'
import { InvalidInputError } from '../errors.js'
import { lazy } from '../lazy.js'
import { createAesWasm } from '../wasm/aes.js'
import { nativeCipher } from '../native/web.js'
import type { NativeStream } from '../native/types.js'
import type { Binary } from '../types.js'
import { SLICE } from '../yield.js'
import type { CtrCipher } from './aes.js'
import { AesBlock, ivBytes, keyBytes } from './block.js'

export function ctr(key: Binary): CtrCipher {
  const secret = keyBytes(key)
  const native = nativeCipher('ctr', secret)
  const prepare = lazy(() => createAesWasm(secret))
  let block: AesBlock | undefined

  function software(initial: Uint8Array): NativeStream {
    block ??= new AesBlock(secret)

    const counter = Uint8Array.from(initial)
    let keystream = new Uint8Array(16)
    let used = 16

    return {
      update(data) {
        const output = new Uint8Array(data.length)

        for (let offset = 0; offset < data.length;) {
          if (used === 16) {
            keystream = block!.encrypt(counter)
            used = 0

            for (let i = 15; i >= 0; i--) {
              counter[i] = (counter[i] + 1) & 255

              if (counter[i] !== 0) {
                break
              }
            }
          }

          const count = Math.min(16 - used, data.length - offset)

          for (let i = 0; i < count; i++) {
            output[offset + i] = data[offset + i] ^ keystream[used + i]
          }

          used += count
          offset += count
        }

        return output
      },
      dispose() {
        counter.fill(0)
        keystream.fill(0)
      },
    }
  }

  function transform(
    data: Uint8Array,
    initial: Uint8Array,
    decrypt: boolean,
  ): Uint8Array {
    const wasm = prepare()

    return wasm ? wasm.transform('ctr', data, initial, decrypt) : software(initial).update(data)
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

    return wasm ? wasm.transformAsync('ctr', data, initial, decrypt) : software(initial).update(data)
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

    create(options) {
      const initial = ivBytes(options, 16)
      const state = native.stream?.(initial) ?? prepare()?.ctrState(initial) ?? software(initial)
      let disposed = false

      return {
        update(data) {
          if (disposed) {
            throw new InvalidInputError('AES-CTR state has been disposed')
          }

          const input = toBytesView(data)

          return input.length === 0 ? new Uint8Array() : state.update(input)
        },

        dispose() {
          if (!disposed) {
            disposed = true
            state.dispose()
          }
        },
      }
    },
  }
}
