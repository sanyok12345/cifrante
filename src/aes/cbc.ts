import { toBinary, toBinaryView, toBytes, toBytesView } from '../bytes.js'
import { AuthenticationError, InvalidInputError } from '../errors.js'
import { lazy } from '../lazy.js'
import { nativeCipher } from '../native/web.js'
import type { Binary } from '../types.js'
import { createAesWasm } from '../wasm/aes.js'
import { SLICE } from '../yield.js'
import type { Cipher } from './aes.js'
import { AesBlock, ivBytes, keyBytes } from './block.js'

export interface CbcOptions {
  padding?: boolean
}

export function cbc(key: Binary, options: CbcOptions = {}): Cipher {
  const secret = keyBytes(key)

  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    throw new InvalidInputError('Invalid AES-CBC options')
  }

  if (options.padding !== undefined && typeof options.padding !== 'boolean') {
    throw new InvalidInputError('AES-CBC padding must be a boolean')
  }

  const padding = options.padding ?? true
  const native = nativeCipher('cbc', secret)
  const prepare = lazy(() => createAesWasm(secret))
  let block: AesBlock | undefined

  function fallback(
    data: Uint8Array,
    initial: Uint8Array,
    decrypt: boolean,
  ): Uint8Array<ArrayBuffer> {
    block ??= new AesBlock(secret)

    const output = new Uint8Array(data.length)
    let previous: Uint8Array = initial
    const mixed = new Uint8Array(16)

    for (let offset = 0; offset < data.length; offset += 16) {
      const input = data.subarray(offset, offset + 16)

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
  ): Uint8Array<ArrayBuffer> {
    const wasm = prepare()

    return wasm ? wasm.transform('cbc', data, initial, decrypt) : fallback(data, initial, decrypt)
  }

  async function transformAsync(
    data: Uint8Array,
    initial: Uint8Array,
    decrypt: boolean,
  ): Promise<Uint8Array<ArrayBuffer>> {
    if (data.length <= SLICE) {
      return transform(data, initial, decrypt)
    }

    const wasm = prepare()

    return wasm ? wasm.transformAsync('cbc', data, initial, decrypt) : fallback(data, initial, decrypt)
  }

  function pad(input: Uint8Array): Uint8Array<ArrayBuffer> {
    const padding = 16 - input.length % 16
    const padded = new Uint8Array(input.length + padding)

    padded.set(input)
    padded.fill(padding, input.length)
    return padded
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

  async function blocksAsync(
    input: Uint8Array,
    initial: Uint8Array,
    decrypt: boolean,
    useNative: boolean,
  ): Promise<Uint8Array> {
    validateBlocks(input)

    if (input.length === 0) {
      return new Uint8Array()
    }

    if (useNative) {
      const result = await (decrypt ? native.decryptBlocks : native.encryptBlocks)?.(initial, input)

      if (result !== undefined) {
        return result
      }
    }

    return transformAsync(input, initial, decrypt)
  }

  function blocksSync(input: Uint8Array, initial: Uint8Array, decrypt: boolean): Uint8Array {
    validateBlocks(input)

    if (input.length === 0) {
      return new Uint8Array()
    }

    const result = (decrypt ? native.decryptBlocksSync : native.encryptBlocksSync)?.(initial, input)

    return result ?? transform(input, initial, decrypt)
  }

  function unpad(output: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
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
  }

  return {
    async encrypt(data, options) {
      const useNative = native.available()
      const input = useNative ? toBytes(data) : toBytesView(data)
      const initial = ivBytes(options, 16, useNative)

      if (!padding) {
        return blocksAsync(input, initial, false, useNative)
      }

      if (useNative) {
        const result = await native.encrypt(initial, input)

        if (result !== undefined) {
          return result
        }
      }

      const padded = pad(input)

      try {
        return await transformAsync(padded, initial, false)
      } finally {
        padded.fill(0)
      }
    },

    async decrypt(data, options) {
      const useNative = native.available()
      const input = useNative ? toBinary(data) : toBinaryView(data)
      const initial = ivBytes(options, 16, useNative)

      if (!padding) {
        return blocksAsync(input, initial, true, useNative)
      }

      validate(input)

      if (useNative) {
        const decrypted = await native.decrypt(initial, input)

        if (decrypted !== undefined) {
          return decrypted
        }
      }

      return unpad(await transformAsync(input, initial, true))
    },

    encryptSync(data, options) {
      const input = toBytesView(data)
      const initial = ivBytes(options, 16, false)

      if (!padding) {
        return blocksSync(input, initial, false)
      }

      const result = native.encryptSync?.(initial, input)

      if (result !== undefined) {
        return result
      }

      const padded = pad(input)

      try {
        return transform(padded, initial, false)
      } finally {
        padded.fill(0)
      }
    },

    decryptSync(data, options) {
      const input = toBinaryView(data)
      const initial = ivBytes(options, 16, false)

      if (!padding) {
        return blocksSync(input, initial, true)
      }

      validate(input)

      return native.decryptSync?.(initial, input) ?? unpad(transform(input, initial, true))
    },
  }
}
