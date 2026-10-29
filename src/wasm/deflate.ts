import { InvalidInputError } from '../errors.js'
import { deflateBound } from '../compression/deflate.js'
import { CORRUPT_DATA } from '../compression/tables.js'
import { growable } from './module.js'
import type { GrowableExports } from './module.js'
import source from '../../build/wasm/deflate.wasm'

type DeflateExports = GrowableExports & {
  compress(input: number, length: number, output: number): number
  inflate(input: number, length: number, offset: number, output: number, capacity: number): number
  inflated(): number
  consumed(): number
  clear(): void
}

const STATUS_OK = 0
const STATUS_FULL = 1

const reserve = /* @__PURE__ */ growable<DeflateExports>(source)

export function deflateWasm(data: Uint8Array): Uint8Array | undefined {
  const reserved = reserve(data.length + deflateBound(data.length))

  if (reserved === undefined) {
    return undefined
  }

  const { exports, base } = reserved
  const memory = new Uint8Array(exports.memory.buffer)
  const output = base + data.length
  let written = 0

  memory.set(data, base)

  try {
    written = exports.compress(base, data.length, output)
    return memory.slice(output, output + written)
  } finally {
    memory.fill(0, base, output + written)
    exports.clear()
  }
}

export function inflateWasm(
  data: Uint8Array,
  offset: number,
  limit: number,
  hint: number,
): { output: Uint8Array, end: number } | undefined {
  let capacity = Math.min(limit, Math.max(hint, 1024))

  for (;;) {
    const reserved = reserve(data.length + capacity)

    if (reserved === undefined) {
      return undefined
    }

    const { exports, base } = reserved

    const memory = new Uint8Array(exports.memory.buffer)
    const output = base + data.length
    let status: number

    memory.set(data, base)

    try {
      status = exports.inflate(base, data.length, offset, output, capacity)

      if (status === STATUS_OK) {
        return { output: memory.slice(output, output + exports.inflated()), end: exports.consumed() }
      }
    } finally {
      memory.fill(0, base, output + exports.inflated())
    }

    if (status !== STATUS_FULL) {
      throw new InvalidInputError(CORRUPT_DATA)
    }

    if (capacity >= limit) {
      throw new InvalidInputError('Decompressed data exceeds maxLength')
    }

    capacity = Math.min(limit, capacity * 2)
  }
}
