import { assertLength, toBinary, toBytes } from '../bytes.js'
import { GZIP_OFFLOAD, nativeGunzip, nativeGunzipSync, nativeGzip, nativeGzipSync } from '../native/web.js'
import type { AbortOptions, Binary, Data } from '../types.js'
import { watch } from '../yield.js'
import { compressGzip, decompressGzip } from './container.js'

export interface GzipOptions extends AbortOptions {
  maxLength?: number
}

export interface GzipCompress {
  (data: Data, options?: AbortOptions): Promise<Uint8Array>
  sync(data: Data): Uint8Array
}

export interface GzipDecompress {
  (data: Binary, options?: GzipOptions): Promise<Uint8Array>
  sync(data: Binary, options?: Omit<GzipOptions, 'signal'>): Uint8Array
}

export interface Gzip {
  compress: GzipCompress
  decompress: GzipDecompress
}

function limit(options: Omit<GzipOptions, 'signal'> | undefined): number {
  const maxLength = options?.maxLength ?? Infinity

  if (maxLength !== Infinity) {
    assertLength(maxLength, 'maxLength')
  }

  return maxLength
}

async function compress(data: Data, options?: AbortOptions): Promise<Uint8Array> {
  const guard = watch(options)

  guard()

  const input = toBytes(data)

  if (input.length >= GZIP_OFFLOAD.compress) {
    const offloaded = await nativeGzip(input)

    guard()

    if (offloaded !== undefined) {
      return offloaded
    }
  }

  return nativeGzipSync(input) ?? compressGzip(input)
}

function compressSync(data: Data): Uint8Array {
  const input = toBytes(data)

  return nativeGzipSync(input) ?? compressGzip(input)
}

async function decompress(data: Binary, options?: GzipOptions): Promise<Uint8Array> {
  const guard = watch(options)

  guard()

  const maxLength = limit(options)
  const input = toBinary(data)

  if (input.length >= GZIP_OFFLOAD.decompress) {
    const offloaded = await nativeGunzip(input, maxLength, guard)

    guard()

    if (offloaded !== undefined) {
      return offloaded
    }
  }

  return nativeGunzipSync(input, maxLength) ?? decompressGzip(input, maxLength)
}

function decompressSync(data: Binary, options?: Omit<GzipOptions, 'signal'>): Uint8Array {
  const maxLength = limit(options)
  const input = toBinary(data)

  return nativeGunzipSync(input, maxLength) ?? decompressGzip(input, maxLength)
}

export const gzip: Gzip = {
  compress: /* @__PURE__ */ Object.assign(compress, { sync: compressSync }),
  decompress: /* @__PURE__ */ Object.assign(decompress, { sync: decompressSync }),
}
