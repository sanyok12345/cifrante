import { toBinaryView, toBytesView } from '../bytes.js'
import { InvalidInputError } from '../errors.js'
import { lazy } from '../lazy.js'
import { aesWasmAvailable, createAesWasm } from '../wasm/aes.js'
import { nativeAddon, nativeCipher } from '../native/web.js'
import type { Binary, Disposal } from '../types.js'
import { CHUNK, SLICE, pacer, watch } from '../yield.js'
import type { Backend, CipherOptions, CtrCipher, CtrState } from './aes.js'
import { AesBlock, deliver, disposable, fit, ivBytes, keyBytes, lifecycle, outputBytes } from './block.js'

interface Stream {
  update(data: Uint8Array, target?: Uint8Array): Uint8Array
  dispose(): void
}

export function ctr(key: Binary): CtrCipher & Disposal {
  const secret = keyBytes(key)
  const native = nativeCipher('ctr', secret)
  const accelerated = nativeAddon()
  let instance: ReturnType<typeof createAesWasm>
  const prepare = lazy(() => (instance = createAesWasm(secret)))
  let keys: Uint8Array<ArrayBuffer> | undefined
  const schedule = lazy(() => {
    keys = new Uint8Array(241)
    accelerated!.expand(secret, keys)
    return keys
  })
  let block: AesBlock | undefined
  const life = lifecycle('AES-CTR cipher', () => {
    secret.fill(0)
    keys?.fill(0)
    instance?.dispose()
    block?.clear()
  })

  function counter(initial: Uint8Array): Uint8Array<ArrayBuffer> {
    const state = new Uint8Array(33)

    state.set(initial)
    state[32] = 16
    return state
  }

  function hardware(initial: Uint8Array): Stream {
    const keys = schedule().slice()
    const state = counter(initial)

    return {
      update(data, target) {
        const output = target ? fit(target, data.length) : new Uint8Array(data.length)

        accelerated!.ctr(keys, state, data, output)
        return output
      },
      dispose() {
        keys.fill(0)
        state.fill(0)
      },
    }
  }

  function keystream(data: Uint8Array, initial: Uint8Array, target: Uint8Array | undefined): Uint8Array {
    const state = counter(initial)
    const output = target ? fit(target, data.length) : new Uint8Array(data.length)

    accelerated!.ctr(schedule(), state, data, output)
    state.fill(0)
    return output
  }

  function software(initial: Uint8Array, own = false): Stream {
    const engine = own ? new AesBlock(secret) : (block ??= new AesBlock(secret))
    const counter = Uint8Array.from(initial)
    let keystream = new Uint8Array(16)
    let used = 16

    return {
      update(data, target) {
        const output = target ?? new Uint8Array(data.length)

        for (let offset = 0; offset < data.length;) {
          if (used === 16) {
            keystream = engine.encrypt(counter)
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

        if (own) {
          engine.clear()
        }
      },
    }
  }

  async function keystreamAsync(
    data: Uint8Array,
    initial: Uint8Array,
    target: Uint8Array | undefined,
    guard: () => void,
  ): Promise<Uint8Array> {
    const output = target ? fit(target, data.length) : new Uint8Array(data.length)
    const state = hardware(initial)
    const pace = pacer(guard)

    try {
      for (let offset = 0; offset < data.length; offset += CHUNK) {
        state.update(data.subarray(offset, offset + CHUNK), output.subarray(offset, offset + CHUNK))

        if (offset + CHUNK < data.length && pace.due()) {
          await pace.pause()
        }
      }

      return output
    } catch (error) {
      output.fill(0)
      throw error
    } finally {
      state.dispose()
    }
  }

  function stream(initial: Uint8Array): Stream {
    if (accelerated) {
      return hardware(initial)
    }

    const state = native.stream?.(initial)

    if (state !== undefined) {
      return {
        update: (data, target) => deliver(state.update(data), target),
        dispose: () => state.dispose(),
      }
    }

    return prepare()?.ctrState(initial) ?? software(initial, true)
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
    guard: () => void,
  ): Promise<Uint8Array> {
    if (accelerated) {
      return data.length <= SLICE ? keystream(data, initial, target) : keystreamAsync(data, initial, target, guard)
    }

    if (useNative) {
      const result = await (decrypt
        ? native.decrypt(initial, data)
        : native.encrypt(initial, data))

      guard()

      if (result !== undefined) {
        return deliver(result, target)
      }
    }

    if (data.length <= SLICE) {
      return transform(data, initial, decrypt, target)
    }

    const wasm = prepare()
    const output = wasm
      ? await wasm.transformAsync('ctr', data, initial, decrypt, target, guard)
      : software(initial).update(data, target)

    return fit(output, data.length)
  }

  function transformSync(
    data: Uint8Array,
    initial: Uint8Array,
    decrypt: boolean,
    target: Uint8Array | undefined,
  ): Uint8Array {
    if (accelerated) {
      return keystream(data, initial, target)
    }

    const result = decrypt ? native.decryptSync?.(initial, data) : native.encryptSync?.(initial, data)

    return result === undefined ? transform(data, initial, decrypt, target) : deliver(result, target)
  }

  function operation(view: Uint8Array, options: CipherOptions, copy: boolean) {
    const guard = watch(options, life.check)

    guard()

    return {
      guard,
      input: copy ? Uint8Array.from(view) : view,
      initial: ivBytes(options, 16, copy),
      target: outputBytes(options.output, view, view.length),
    }
  }

  return disposable<CtrCipher>({
    async encrypt(data, options) {
      const useNative = !accelerated && native.available()
      const { input, initial, target, guard } = operation(toBytesView(data), options, useNative)
      return transformAsync(input, initial, false, target, useNative, guard)
    },

    async decrypt(data, options) {
      const useNative = !accelerated && native.available()
      const { input, initial, target, guard } = operation(toBinaryView(data), options, useNative)
      return transformAsync(input, initial, true, target, useNative, guard)
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
      watch(options, life.check)()

      const state = stream(ivBytes(options, 16))
      let disposed = false

      return disposable<CtrState>({
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
      })
    },

    dispose: life.dispose,

    get backend(): Backend {
      return accelerated || native.available() ? 'native' : aesWasmAvailable() ? 'wasm' : 'js'
    },
  })
}
