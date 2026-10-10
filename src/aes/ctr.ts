import { toBinaryView, toBytesView } from '../bytes.js'
import { InvalidInputError } from '../errors.js'
import { lazy } from '../lazy.js'
import { createAesWasm } from '../wasm/aes.js'
import { nativeCipher } from '../native/web.js'
import type { Binary } from '../types.js'
import { SLICE } from '../yield.js'
import type { CipherOptions, CtrCipher } from './aes.js'
import { AesBlock, deliver, fit, ivBytes, keyBytes, outputBytes } from './block.js'

interface Stream {
  update(data: Uint8Array, target?: Uint8Array): Uint8Array
  dispose(): void
}

export function ctr(key: Binary): CtrCipher {
  const secret = keyBytes(key)
  const native = nativeCipher('ctr', secret)
  const prepare = lazy(() => createAesWasm(secret))
  let block: AesBlock | undefined

  function software(initial: Uint8Array): Stream {
    block ??= new AesBlock(secret)

    const counter = Uint8Array.from(initial)
    let keystream = new Uint8Array(16)
    let used = 16

    return {
      update(data, target) {
        const output = target ?? new Uint8Array(data.length)

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

  function stream(initial: Uint8Array): Stream {
    const state = native.stream?.(initial)

    if (state !== undefined) {
      return {
        update: (data, target) => deliver(state.update(data), target),
        dispose: () => state.dispose(),
      }
    }

    return prepare()?.ctrState(initial) ?? software(initial)
  }

  function transform(
    data: Uint8Array,
    initial: Uint8Array,
    decrypt: boolean,
    target: Uint8Array | undefined,
  ): Uint8Array {
    const wasm = prepare()
    const output = wasm
      ? wasm.transform('ctr', data, initial, decrypt, target)
      : software(initial).update(data, target)

    return fit(output, data.length)
  }

  async function transformAsync(
    data: Uint8Array,
    initial: Uint8Array,
    decrypt: boolean,
    target: Uint8Array | undefined,
    useNative: boolean,
  ): Promise<Uint8Array> {
    if (useNative) {
      const result = await (decrypt
        ? native.decrypt(initial, data)
        : native.encrypt(initial, data))

      if (result !== undefined) {
        return deliver(result, target)
      }
    }

    if (data.length <= SLICE) {
      return transform(data, initial, decrypt, target)
    }

    const wasm = prepare()
    const output = wasm
      ? await wasm.transformAsync('ctr', data, initial, decrypt, target)
      : software(initial).update(data, target)

    return fit(output, data.length)
  }

  function transformSync(
    data: Uint8Array,
    initial: Uint8Array,
    decrypt: boolean,
    target: Uint8Array | undefined,
  ): Uint8Array {
    const result = decrypt ? native.decryptSync?.(initial, data) : native.encryptSync?.(initial, data)

    return result === undefined ? transform(data, initial, decrypt, target) : deliver(result, target)
  }

  function operation(view: Uint8Array, options: CipherOptions, copy: boolean) {
    return {
      input: copy ? Uint8Array.from(view) : view,
      initial: ivBytes(options, 16, copy),
      target: outputBytes(options.output, view, view.length),
    }
  }

  return {
    async encrypt(data, options) {
      const useNative = native.available()
      const { input, initial, target } = operation(toBytesView(data), options, useNative)
      return transformAsync(input, initial, false, target, useNative)
    },

    async decrypt(data, options) {
      const useNative = native.available()
      const { input, initial, target } = operation(toBinaryView(data), options, useNative)
      return transformAsync(input, initial, true, target, useNative)
    },

    encryptSync(data, options) {
      const { input, initial, target } = operation(toBytesView(data), options, false)
      return transformSync(input, initial, false, target)
    },

    decryptSync(data, options) {
      const { input, initial, target } = operation(toBinaryView(data), options, false)
      return transformSync(input, initial, true, target)
    },

    create(options) {
      const state = stream(ivBytes(options, 16))
      let disposed = false

      return {
        update(data, output) {
          if (disposed) {
            throw new InvalidInputError('AES-CTR state has been disposed')
          }

          const input = toBytesView(data)
          const target = outputBytes(output, input, input.length)

          if (input.length === 0) {
            return target ? fit(target, 0) : new Uint8Array()
          }

          return fit(state.update(input, target), input.length)
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
