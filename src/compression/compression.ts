import { assertLength, toBinary, toBytes } from '../bytes.js'
import { InvalidInputError } from '../errors.js'
import {
  COMPRESSION_OFFLOAD,
  nativeCompress,
  nativeCompressSync,
  nativeDecompress,
  nativeDecompressSync,
} from '../native/web.js'
import type { AbortOptions, Binary, Data } from '../types.js'
import { watch } from '../yield.js'
import { containers } from './formats.js'
import type { Format } from './formats.js'
import { CORRUPT_DATA } from './tables.js'

export interface CompressionOptions extends AbortOptions {
  maxLength?: number
}

export interface Compress {
  (data: Data, options?: AbortOptions): Promise<Uint8Array>
  sync(data: Data): Uint8Array
}

export interface Decompress {
  (data: Binary, options?: CompressionOptions): Promise<Uint8Array>
  sync(data: Binary, options?: Omit<CompressionOptions, 'signal'>): Uint8Array
}

export interface Compression {
  compress: Compress
  decompress: Decompress
}

function limit(options: Omit<CompressionOptions, 'signal'> | undefined): number {
  const maxLength = options?.maxLength ?? Infinity

  if (maxLength !== Infinity) {
    assertLength(maxLength, 'maxLength')
  }

  return maxLength
}

function create(format: Format): Compression {
  const { encode, decode } = containers[format]

  function named<T>(run: () => T): T {
    try {
      return run()
    } catch (error) {
      if (error instanceof InvalidInputError && error.message === CORRUPT_DATA) {
        throw new InvalidInputError(`Invalid ${format} data`)
      }

      throw error
    }
  }

  function compressSync(data: Data): Uint8Array {
    const input = toBytes(data)

    return nativeCompressSync(format, input) ?? encode(input)
  }

  async function compress(data: Data, options?: AbortOptions): Promise<Uint8Array> {
    const guard = watch(options)

    guard()

    const input = toBytes(data)

    if (input.length >= COMPRESSION_OFFLOAD.compress) {
      const offloaded = await nativeCompress(format, input)

      guard()

      if (offloaded !== undefined) {
        return offloaded
      }
    }

    return nativeCompressSync(format, input) ?? encode(input)
  }

  function decompressSync(data: Binary, options?: Omit<CompressionOptions, 'signal'>): Uint8Array {
    const maxLength = limit(options)
    const input = toBinary(data)

    return named(() => nativeDecompressSync(format, input, maxLength) ?? decode(input, maxLength))
  }

  async function decompress(data: Binary, options?: CompressionOptions): Promise<Uint8Array> {
    const guard = watch(options)

    guard()

    const maxLength = limit(options)
    const input = toBinary(data)

    if (input.length >= COMPRESSION_OFFLOAD.decompress) {
      const offloaded = await nativeDecompress(format, input, maxLength, guard)

      guard()

      if (offloaded !== undefined) {
        return offloaded
      }
    }

    return named(() => nativeDecompressSync(format, input, maxLength) ?? decode(input, maxLength))
  }

  return {
    compress: Object.assign(compress, { sync: compressSync }),
    decompress: Object.assign(decompress, { sync: decompressSync }),
  }
}

export const gzip: Compression = /* @__PURE__ */ create('gzip')
export const deflate: Compression = /* @__PURE__ */ create('deflate')
export const zlib: Compression = /* @__PURE__ */ create('zlib')
