import { toBinaryView, toBytesView } from '../bytes.js'
import { InvalidInputError } from '../errors.js'
import { lazy } from '../lazy.js'
import { nativeAddon, nativeCipher } from '../native/web.js'
import type { Binary, Disposal } from '../types.js'
import { aesWasmAvailable, createAesWasm } from '../wasm/aes.js'
import { OFFLOAD_SLICE, SLICE, watch } from '../yield.js'
import type { Backend, Cipher, CipherOptions } from './aes.js'
import { AesBlock, disposable, fit, ivBytes, keyBytes, lifecycle, outputBytes } from './block.js'

const CBC_SYNC_THRESHOLD = 512
const CBC_ASYNC_THRESHOLD = 65536
const ZERO_BLOCK = new Uint8Array(16)

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
  output: Uint8Array,
): [Uint8Array, Uint8Array] {
  const destination = output.byteOffset % 4 === 0 ? output : new Uint8Array(output.length)
  const target = words(destination)
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

  if (destination !== output) {
    output.set(destination)
    destination.fill(0)
  }

  const count = target.length >>> 2
  const last = new Uint8Array((count & 1 ? even : odd).buffer)
  const beforeLast = new Uint8Array((count & 1 ? odd : even).buffer)

  return [beforeLast, last]
}

function continuation(
  tail: Uint8Array,
  output: Uint8Array,
  end: number,
  decrypt: boolean,
): Uint8Array<ArrayBuffer> {
  const iv = new Uint8Array(32)
  const result = output.subarray(end - 16, end)

  iv.set(decrypt ? tail : result)
  iv.set(decrypt ? result : tail, 16)
  return iv
}

export function ige(key: Binary): Cipher & Disposal {
  const secret = keyBytes(key)
  const accelerated = nativeAddon()
  const native = nativeCipher('cbc', secret)
  let instance: ReturnType<typeof createAesWasm>
  const prepare = lazy(() => (instance = createAesWasm(secret)))
  let block: AesBlock | undefined
  const life = lifecycle('AES-IGE cipher', () => {
    secret.fill(0)
    instance?.dispose()
    block?.clear()
  })

  function validate(data: Uint8Array): void {
    if (data.length % 16 !== 0) {
      throw new InvalidInputError('AES-IGE input must contain complete 16-byte blocks')
    }
  }

  function fallback(
    data: Uint8Array,
    initial: Uint8Array,
    decrypt: boolean,
    target?: Uint8Array,
  ): Uint8Array {
    block ??= new AesBlock(secret)

    const output = target ?? new Uint8Array(data.length)
    let previousCiphertext: Uint8Array = initial.slice(0, 16)
    let previousPlaintext: Uint8Array = initial.slice(16, 32)
    const mixed = new Uint8Array(16)

    for (let offset = 0; offset < data.length; offset += 16) {
      const input = data.slice(offset, offset + 16)
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

    mixed.fill(0)
    return output
  }

  function portable(
    data: Uint8Array,
    initial: Uint8Array,
    decrypt: boolean,
    target?: Uint8Array,
  ): Uint8Array {
    const wasm = prepare()

    return wasm
      ? wasm.transform('ige', data, initial, decrypt, target)
      : fallback(data, initial, decrypt, target)
  }

  function accelerate(
    data: Uint8Array,
    initial: Uint8Array,
    decrypt: boolean,
    output: Uint8Array,
  ): void {
    if (decrypt) {
      accelerated!.decrypt(secret, initial, data, output)
    } else {
      accelerated!.encrypt(secret, initial, data, output)
    }
  }

  async function accelerateAsync(
    data: Uint8Array,
    initial: Uint8Array,
    decrypt: boolean,
    target: Uint8Array | undefined,
    guard: () => void,
  ): Promise<Uint8Array> {
    const output = target ?? new Uint8Array(data.length)

    if (data.length <= SLICE) {
      accelerate(data, initial, decrypt, fit(output, data.length))
      return output
    }

    const run = decrypt ? accelerated!.decryptAsync : accelerated!.encryptAsync
    let iv = initial

    try {
      for (let offset = 0; offset < data.length; offset += OFFLOAD_SLICE) {
        const end = Math.min(offset + OFFLOAD_SLICE, data.length)
        const tail = data.slice(end - 16, end)

        await run(secret, iv, data.subarray(offset, end), output.subarray(offset, end))
        guard()

        if (end < data.length) {
          iv = continuation(tail, output, end, decrypt)
        }
      }

      return output
    } catch (error) {
      output.fill(0, 0, data.length)
      throw error
    }
  }

  async function encryptCbc(
    data: Uint8Array,
    initial: Uint8Array,
    target: Uint8Array | undefined,
    encryptBlocks: (iv: Uint8Array, blocks: Uint8Array) => Promise<Uint8Array | undefined>,
    guard: () => void,
  ): Promise<Uint8Array | undefined> {
    const output = target ?? new Uint8Array(data.length)
    let chain: Uint8Array = initial.slice(0, 16)
    let before: Uint8Array = ZERO_BLOCK
    let previous: Uint8Array = initial.slice(16, 32)

    for (let offset = 0; offset < data.length; offset += SLICE) {
      const slice = data.subarray(offset, offset + SLICE)
      const prepared = chainInput(slice, before, previous)
      const blocks = await encryptBlocks(chain, prepared)

      guard()

      if (blocks === undefined) {
        output.fill(0, 0, offset)
        return undefined
      }

      ;[before, previous] = chainOutput(blocks, prepared, before, previous, output.subarray(offset, offset + slice.length))
      chain = blocks.slice(blocks.length - 16)
    }

    return output
  }

  function encryptCbcSync(
    data: Uint8Array,
    initial: Uint8Array,
    target: Uint8Array | undefined,
  ): Uint8Array | undefined {
    const encryptBlocks = native.encryptBlocksSync

    if (data.length < CBC_SYNC_THRESHOLD || !encryptBlocks || !native.available()) {
      return undefined
    }

    const output = target ?? new Uint8Array(data.length)
    let chain: Uint8Array = initial.slice(0, 16)
    let before: Uint8Array = ZERO_BLOCK
    let previous: Uint8Array = initial.slice(16, 32)

    for (let offset = 0; offset < data.length; offset += SLICE) {
      const slice = data.subarray(offset, offset + SLICE)
      const prepared = chainInput(slice, before, previous)
      const blocks = encryptBlocks(chain, prepared)

      if (blocks === undefined) {
        output.fill(0, 0, offset)
        return undefined
      }

      ;[before, previous] = chainOutput(blocks, prepared, before, previous, output.subarray(offset, offset + slice.length))
      chain = blocks.slice(blocks.length - 16)
    }

    return output
  }

  function encryptCbcAsync(
    data: Uint8Array,
    initial: Uint8Array,
    target: Uint8Array | undefined,
    guard: () => void,
  ): Promise<Uint8Array | undefined> | Uint8Array | undefined {
    if (native.encryptBlocksSync && data.length <= SLICE) {
      return encryptCbcSync(data, initial, target)
    }

    const minimum = native.encryptBlocksSync ? CBC_SYNC_THRESHOLD : CBC_ASYNC_THRESHOLD

    if (data.length < minimum || !native.encryptBlocks || !native.available()) {
      return undefined
    }

    return encryptCbc(data, initial, target, native.encryptBlocks, guard)
  }

  function transform(
    data: Uint8Array,
    initial: Uint8Array,
    decrypt: boolean,
    target: Uint8Array | undefined,
  ): Uint8Array {
    validate(data)

    if (data.length === 0) {
      return target ? fit(target, 0) : new Uint8Array()
    }

    if (accelerated) {
      const output = target ? fit(target, data.length) : new Uint8Array(data.length)

      accelerate(data, initial, decrypt, output)
      return output
    }

    if (!decrypt) {
      const output = encryptCbcSync(data, initial, target)

      if (output !== undefined) {
        return fit(output, data.length)
      }
    }

    return fit(portable(data, initial, decrypt, target), data.length)
  }

  async function transformAsync(
    data: Uint8Array,
    initial: Uint8Array,
    decrypt: boolean,
    target: Uint8Array | undefined,
    guard: () => void,
  ): Promise<Uint8Array> {
    validate(data)

    if (data.length === 0) {
      return target ? fit(target, 0) : new Uint8Array()
    }

    if (accelerated) {
      return fit(await accelerateAsync(data, initial, decrypt, target, guard), data.length)
    }

    if (!decrypt) {
      const output = await encryptCbcAsync(data, initial, target, guard)

      guard()

      if (output !== undefined) {
        return fit(output, data.length)
      }
    }

    if (data.length <= SLICE) {
      return fit(portable(data, initial, decrypt, target), data.length)
    }

    const wasm = prepare()
    const output = wasm
      ? await wasm.transformAsync('ige', data, initial, decrypt, target, guard)
      : fallback(data, initial, decrypt, target)

    return fit(output, data.length)
  }

  function run<T>(
    data: Uint8Array,
    options: CipherOptions,
    operation: (input: Uint8Array, initial: Uint8Array, target: Uint8Array | undefined, guard: () => void) => T,
  ): T {
    const guard = watch(options, life.check)

    guard()

    const initial = ivBytes(options, 32, false)

    return operation(data, initial, outputBytes(options.output, data, data.length), guard)
  }

  return disposable<Cipher>({
    async encrypt(data, options) {
      return run(toBytesView(data), options, (input, initial, target, guard) =>
        transformAsync(input, initial, false, target, guard))
    },

    async decrypt(data, options) {
      return run(toBinaryView(data), options, (input, initial, target, guard) =>
        transformAsync(input, initial, true, target, guard))
    },

    encryptSync(data, options) {
      return run(toBytesView(data), options, (input, initial, target) =>
        transform(input, initial, false, target))
    },

    decryptSync(data, options) {
      return run(toBinaryView(data), options, (input, initial, target) =>
        transform(input, initial, true, target))
    },

    dispose: life.dispose,

    get backend(): Backend {
      return accelerated ? 'native' : aesWasmAvailable() ? 'wasm' : 'js'
    },
  })
}
