import { toBinaryView, toBytesView } from '../bytes.js'
import { InvalidInputError } from '../errors.js'
import { lazy } from '../lazy.js'
import { nativeCipher } from '../native/web.js'
import type { Binary } from '../types.js'
import { createAesWasm } from '../wasm/aes.js'
import { SLICE, yieldNow } from '../yield.js'
import type { Cipher, CipherOptions } from './aes.js'
import { AesBlock, ivBytes, keyBytes } from './block.js'

const NATIVE_SYNC_THRESHOLD = 512
const NATIVE_ASYNC_THRESHOLD = 65536

function words(bytes: Uint8Array): Uint32Array {
  return new Uint32Array(bytes.buffer, bytes.byteOffset, bytes.length >>> 2)
}

function aligned(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return bytes.byteOffset % 4 === 0 && bytes.buffer instanceof ArrayBuffer
    ? (bytes as Uint8Array<ArrayBuffer>)
    : Uint8Array.from(bytes)
}

function chainInput(
  data: Uint8Array,
  before: Uint8Array,
  previous: Uint8Array,
): Uint8Array<ArrayBuffer> {
  const prepared = Uint8Array.from(data)
  const target = words(prepared)
  const first = words(aligned(before))
  const second = words(aligned(previous))

  for (let i = target.length - 1; i >= 8; i--) {
    target[i] ^= target[i - 8]
  }

  for (let i = 0; i < Math.min(4, target.length); i++) {
    target[i] ^= first[i]
  }

  for (let i = 4; i < Math.min(8, target.length); i++) {
    target[i] ^= second[i - 4]
  }

  return prepared
}

function chainOutput(
  blocks: Uint8Array,
  prepared: Uint8Array,
  before: Uint8Array,
  previous: Uint8Array,
  output: Uint8Array<ArrayBuffer>,
): [Uint8Array, Uint8Array] {
  const target = words(output)
  const source = words(aligned(blocks))
  const chain = words(prepared)
  const even = Uint32Array.from(words(aligned(before)))
  const odd = Uint32Array.from(words(aligned(previous)))

  for (let i = 0; i < target.length; i += 4) {
    const history = (i >>> 2) & 1 ? odd : even

    for (let j = 0; j < 4; j++) {
      const plain = chain[i + j] ^ history[j]

      target[i + j] = source[i + j] ^ ((i >>> 2) & 1 ? even : odd)[j]
      history[j] = plain
    }
  }

  const blocksCount = target.length >>> 2
  const last = new Uint8Array((blocksCount & 1 ? even : odd).buffer)
  const beforeLast = new Uint8Array((blocksCount & 1 ? odd : even).buffer)

  return [beforeLast, last]
}

const ZERO_BLOCK = new Uint8Array(16)

export function ige(key: Binary): Cipher {
  const secret = keyBytes(key)
  const native = nativeCipher('cbc', secret)
  const prepare = lazy(() => createAesWasm(secret))
  let block: AesBlock | undefined

  function validate(data: Uint8Array): void {
    if (data.length % 16 !== 0) {
      throw new InvalidInputError('AES-IGE input must contain complete 16-byte blocks')
    }
  }

  function fallback(
    data: Uint8Array,
    initial: Uint8Array,
    decrypt: boolean,
  ): Uint8Array<ArrayBuffer> {
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

  function encryptNativeChunks(
    data: Uint8Array,
    initial: Uint8Array,
    encryptBlocks: (iv: Uint8Array, blocks: Uint8Array) => Uint8Array | undefined,
  ): Uint8Array<ArrayBuffer> | undefined {
    const output = new Uint8Array(data.length)
    let chain: Uint8Array = Uint8Array.from(initial.subarray(0, 16))
    let before: Uint8Array = ZERO_BLOCK
    let previous: Uint8Array = Uint8Array.from(initial.subarray(16, 32))

    for (let offset = 0; offset < data.length; offset += SLICE) {
      const slice = data.subarray(offset, offset + SLICE)
      const prepared = chainInput(slice, before, previous)
      const blocks = encryptBlocks(chain, prepared)

      if (blocks === undefined) {
        return undefined
      }

      ;[before, previous] = chainOutput(blocks, prepared, before, previous, output.subarray(offset, offset + slice.length))
      chain = Uint8Array.from(blocks.subarray(blocks.length - 16))
    }

    return output
  }

  function encryptNativeSync(data: Uint8Array, initial: Uint8Array): Uint8Array<ArrayBuffer> | undefined {
    if (data.length < NATIVE_SYNC_THRESHOLD || !native.encryptBlocksSync || !native.available()) {
      return undefined
    }

    return encryptNativeChunks(data, initial, native.encryptBlocksSync)
  }

  async function encryptNative(data: Uint8Array, initial: Uint8Array): Promise<Uint8Array<ArrayBuffer> | undefined> {
    const sync = native.encryptBlocksSync !== undefined
    const threshold = sync ? NATIVE_SYNC_THRESHOLD : NATIVE_ASYNC_THRESHOLD

    if (data.length < threshold || !native.available() || (!sync && !native.encryptBlocks)) {
      return undefined
    }

    if (data.length <= SLICE && sync) {
      return encryptNativeSync(data, initial)
    }

    const output = new Uint8Array(data.length)
    let chain: Uint8Array = Uint8Array.from(initial.subarray(0, 16))
    let before: Uint8Array = ZERO_BLOCK
    let previous: Uint8Array = Uint8Array.from(initial.subarray(16, 32))

    for (let offset = 0; offset < data.length; offset += SLICE) {
      const slice = data.subarray(offset, offset + SLICE)
      const prepared = chainInput(slice, before, previous)
      const blocks = sync
        ? native.encryptBlocksSync!(chain, prepared)
        : await native.encryptBlocks!(chain, prepared)

      if (blocks === undefined) {
        return undefined
      }

      ;[before, previous] = chainOutput(blocks, prepared, before, previous, output.subarray(offset, offset + slice.length))
      chain = Uint8Array.from(blocks.subarray(blocks.length - 16))

      if (sync && offset + SLICE < data.length) {
        await yieldNow()
      }
    }

    return output
  }

  function transform(
    data: Uint8Array,
    initial: Uint8Array,
    decrypt: boolean,
  ): Uint8Array<ArrayBuffer> {
    validate(data)

    if (data.length === 0) {
      return new Uint8Array()
    }

    if (!decrypt) {
      const result = encryptNativeSync(data, initial)

      if (result !== undefined) {
        return result
      }
    }

    const wasm = prepare()

    return wasm ? wasm.transform('ige', data, initial, decrypt) : fallback(data, initial, decrypt)
  }

  async function transformAsync(
    data: Uint8Array,
    initial: Uint8Array,
    decrypt: boolean,
  ): Promise<Uint8Array<ArrayBuffer>> {
    validate(data)

    if (data.length === 0) {
      return new Uint8Array()
    }

    if (!decrypt) {
      const result = await encryptNative(data, initial)

      if (result !== undefined) {
        return result
      }
    }

    if (data.length <= SLICE) {
      return transform(data, initial, decrypt)
    }

    const wasm = prepare()

    return wasm ? wasm.transformAsync('ige', data, initial, decrypt) : fallback(data, initial, decrypt)
  }

  return {
    async encrypt(data, options) {
      return transformAsync(toBytesView(data), ivBytes(options, 32, false), false)
    },

    async decrypt(data, options) {
      return transformAsync(toBinaryView(data), ivBytes(options, 32, false), true)
    },

    encryptSync(data, options: CipherOptions) {
      return transform(toBytesView(data), ivBytes(options, 32, false), false)
    },

    decryptSync(data, options: CipherOptions) {
      return transform(toBinaryView(data), ivBytes(options, 32, false), true)
    },
  }
}
