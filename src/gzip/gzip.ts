import { assertLength, toBinary, toBytes } from '../bytes.js'
import { nativeGunzip, nativeGzip } from '../native/web.js'
import type { AbortOptions, Binary, Data } from '../types.js'
import { watch } from '../yield.js'
import { compressGzip, decompressGzip } from './container.js'

export interface GzipOptions extends AbortOptions {
  maxLength?: number
}

export interface Gzip {
  compress(data: Data, options?: AbortOptions): Promise<Uint8Array>
  decompress(data: Binary, options?: GzipOptions): Promise<Uint8Array>
}

async function compress(data: Data, options?: AbortOptions): Promise<Uint8Array> {
  const guard = watch(options)

  guard()

  const input = toBytes(data)
  const native = await nativeGzip(input)

  guard()

  return native ?? compressGzip(input)
}

async function decompress(data: Binary, options?: GzipOptions): Promise<Uint8Array> {
  const guard = watch(options)

  guard()

  const limit = options?.maxLength ?? Infinity

  if (limit !== Infinity) {
    assertLength(limit, 'maxLength')
  }

  const input = toBinary(data)
  const native = await nativeGunzip(input, limit, guard)

  guard()

  return native ?? decompressGzip(input, limit)
}

export const gzip: Gzip = { compress, decompress }
