import { toBinaryView, toBytesView } from '../bytes.js'
import { AuthenticationError, InvalidInputError } from '../errors.js'
import { lazy } from '../lazy.js'
import { nativeCipher } from '../native/web.js'
import type { Binary, Disposal } from '../types.js'
import { createAesWasm } from '../wasm/aes.js'
import { SLICE, watch } from '../yield.js'
import type { Cipher, CipherOptions } from './aes.js'
import { AesBlock, deliver, disposable, fit, ivBytes, keyBytes, lifecycle, outputBytes } from './block.js'

export interface CbcOptions {
  padding?: boolean
}

export function cbc(key: Binary, options: CbcOptions = {}): Cipher & Disposal {
  const secret = keyBytes(key)

  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    throw new InvalidInputError('Invalid AES-CBC options')
  }

  if (options.padding !== undefined && typeof options.padding !== 'boolean') {
    throw new InvalidInputError('AES-CBC padding must be a boolean')
  }

  const padding = options.padding ?? true
  const native = nativeCipher('cbc', secret)
  let instance: ReturnType<typeof createAesWasm>
  const prepare = lazy(() => (instance = createAesWasm(secret)))
  let block: AesBlock | undefined
  const life = lifecycle('AES-CBC cipher', () => {
    secret.fill(0)
    instance?.dispose()
    block?.clear()
  })

  function fallback(
    data: Uint8Array,
    initial: Uint8Array,
    decrypt: boolean,
    target?: Uint8Array,
  ): Uint8Array {
    block ??= new AesBlock(secret)

    const output = target ?? new Uint8Array(data.length)
    let previous: Uint8Array = initial.slice()
    const mixed = new Uint8Array(16)

    for (let offset = 0; offset < data.length; offset += 16) {
      const input = data.slice(offset, offset + 16)

      if (decrypt) {
        const result = block.decrypt(input)

        for (let i = 0; i < 16; i++) {
          output[offset + i] = result[i] ^ previous[i]
        }

        previous = input
      } else {
        for (let i = 0; i < 16; i++) {
          mixed[i] = input[i] ^ previous[i]
        }

        previous = block.encrypt(mixed)
        output.set(previous, offset)
      }
    }

    mixed.fill(0)
    return output
  }

  function transform(
    data: Uint8Array,
    initial: Uint8Array,
    decrypt: boolean,
    target?: Uint8Array,
  ): Uint8Array {
    const wasm = prepare()

    return wasm
      ? wasm.transform('cbc', data, initial, decrypt, target)
      : fallback(data, initial, decrypt, target)
  }

  async function transformAsync(
    data: Uint8Array,
    initial: Uint8Array,
    decrypt: boolean,
    target: Uint8Array | undefined,
    guard: () => void,
  ): Promise<Uint8Array> {
    if (data.length <= SLICE) {
      return transform(data, initial, decrypt, target)
    }

    const wasm = prepare()

    return wasm
      ? wasm.transformAsync('cbc', data, initial, decrypt, target, guard)
      : fallback(data, initial, decrypt, target)
  }

  function padded(length: number): number {
    return length - length % 16 + 16
  }

  function pad(input: Uint8Array): Uint8Array<ArrayBuffer> {
    const value = padded(input.length) - input.length
    const output = new Uint8Array(input.length + value)

    output.set(input)
    output.fill(value, input.length)
    return output
  }

  function validate(input: Uint8Array): void {
    if (input.length === 0 || input.length % 16 !== 0) {
      throw new InvalidInputError(
        'AES-CBC ciphertext must contain nonempty complete 16-byte blocks',
      )
    }
  }

  function validateBlocks(input: Uint8Array): void {
    if (input.length % 16 !== 0) {
      throw new InvalidInputError('Unpadded AES-CBC input must contain complete 16-byte blocks')
    }
  }

  function unpad(output: Uint8Array, target: Uint8Array | undefined): Uint8Array {
    const value = output[output.length - 1]
    let invalid = Number(value === 0 || value > 16)

    for (let i = 1; i <= 16; i++) {
      invalid |= (output[output.length - i] ^ value) & -(i <= value ? 1 : 0)
    }

    if (invalid !== 0) {
      output.fill(0)
      throw new AuthenticationError('Invalid AES-CBC padding')
    }

    if (target !== undefined) {
      output.fill(0, output.length - value)
      return fit(target, output.length - value)
    }

    const plaintext = output.slice(0, output.length - value)
    output.fill(0)
    return plaintext
  }

  function region(target: Uint8Array | undefined, length: number): Uint8Array | undefined {
    return target === undefined ? undefined : target.subarray(0, length)
  }

  function prepareOperation(view: Uint8Array, options: CipherOptions, copy: boolean, decrypt: boolean) {
    const guard = watch(options, life.check)

    guard()

    const initial = ivBytes(options, 16, copy)
    const length = !padding || decrypt ? view.length : padded(view.length)

    return {
      input: copy ? Uint8Array.from(view) : view,
      initial,
      target: outputBytes(options.output, view, length),
      guard,
    }
  }

  async function openAsync(
    input: Uint8Array,
    initial: Uint8Array,
    target: Uint8Array | undefined,
    useNative: boolean,
    guard: () => void,
  ): Promise<Uint8Array> {
    validate(input)

    try {
      if (useNative) {
        const decrypted = await native.decrypt(initial, input)

        guard()

        if (decrypted !== undefined) {
          return deliver(decrypted, target)
        }
      }

      return unpad(await transformAsync(input, initial, true, region(target, input.length), guard), target)
    } catch (error) {
      target?.fill(0, 0, input.length)
      throw error
    }
  }

  function open(input: Uint8Array, initial: Uint8Array, target: Uint8Array | undefined): Uint8Array {
    validate(input)

    try {
      const decrypted = native.decryptSync?.(initial, input)

      if (decrypted !== undefined) {
        return deliver(decrypted, target)
      }

      return unpad(transform(input, initial, true, region(target, input.length)), target)
    } catch (error) {
      target?.fill(0, 0, input.length)
      throw error
    }
  }

  async function blocksAsync(
    input: Uint8Array,
    initial: Uint8Array,
    target: Uint8Array | undefined,
    decrypt: boolean,
    useNative: boolean,
    guard: () => void,
  ): Promise<Uint8Array> {
    validateBlocks(input)

    if (input.length === 0) {
      return target ? fit(target, 0) : new Uint8Array()
    }

    if (useNative) {
      const result = await (decrypt ? native.decryptBlocks : native.encryptBlocks)?.(initial, input)

      guard()

      if (result !== undefined) {
        return deliver(result, target)
      }
    }

    return fit(await transformAsync(input, initial, decrypt, region(target, input.length), guard), input.length)
  }

  function blocksSync(
    input: Uint8Array,
    initial: Uint8Array,
    target: Uint8Array | undefined,
    decrypt: boolean,
  ): Uint8Array {
    validateBlocks(input)

    if (input.length === 0) {
      return target ? fit(target, 0) : new Uint8Array()
    }

    const result = (decrypt ? native.decryptBlocksSync : native.encryptBlocksSync)?.(initial, input)

    if (result !== undefined) {
      return deliver(result, target)
    }

    return fit(transform(input, initial, decrypt, region(target, input.length)), input.length)
  }

  return disposable<Cipher>({
    async encrypt(data, options) {
      const useNative = native.available()
      const { input, initial, target, guard } = prepareOperation(toBytesView(data), options, useNative, false)

      if (!padding) {
        return blocksAsync(input, initial, target, false, useNative, guard)
      }

      if (useNative) {
        const result = await native.encrypt(initial, input)

        guard()

        if (result !== undefined) {
          return deliver(result, target)
        }
      }

      const plain = pad(input)

      try {
        return fit(await transformAsync(plain, initial, false, region(target, plain.length), guard), plain.length)
      } finally {
        plain.fill(0)
      }
    },

    async decrypt(data, options) {
      const useNative = native.available()
      const { input, initial, target, guard } = prepareOperation(toBinaryView(data), options, useNative, true)

      return padding
        ? openAsync(input, initial, target, useNative, guard)
        : blocksAsync(input, initial, target, true, useNative, guard)
    },

    encryptSync(data, options) {
      const { input, initial, target } = prepareOperation(toBytesView(data), options, false, false)

      if (!padding) {
        return blocksSync(input, initial, target, false)
      }

      const result = native.encryptSync?.(initial, input)

      if (result !== undefined) {
        return deliver(result, target)
      }

      const plain = pad(input)

      try {
        return fit(transform(plain, initial, false, region(target, plain.length)), plain.length)
      } finally {
        plain.fill(0)
      }
    },

    decryptSync(data, options) {
      const { input, initial, target } = prepareOperation(toBinaryView(data), options, false, true)

      return padding ? open(input, initial, target) : blocksSync(input, initial, target, true)
    },

    dispose: life.dispose,
  })
}
