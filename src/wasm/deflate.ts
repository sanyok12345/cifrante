import { decodeBase64 } from '../bytes.js'
import { InvalidInputError } from '../errors.js'
import { lazy } from '../lazy.js'
import { CORRUPT_DATA } from '../compression/tables.js'
import source from '../../build/wasm/deflate.wasm'

type DeflateExports = WebAssembly.Exports & {
  memory: WebAssembly.Memory
  heap_base(): number
  bound(length: number): number
  compress(input: number, length: number, output: number): number
  inflate(input: number, length: number, offset: number, output: number, capacity: number): number
  inflated(): number
  consumed(): number
  clear(): void
}

const SHARED_MEMORY = 32 * 1024 * 1024
const STATUS_OK = 0
const STATUS_FULL = 1

const compiled = /* @__PURE__ */ lazy(() => {
  if (typeof WebAssembly === 'undefined') {
    return undefined
  }

  try {
    return new WebAssembly.Module(decodeBase64(source))
  } catch (error) {
    if (error instanceof WebAssembly.CompileError) {
      return undefined
    }

    throw error
  }
})

const shared = /* @__PURE__ */ lazy(() => {
  const module = compiled()

  return module && new WebAssembly.Instance(module).exports as DeflateExports
})

function engine(bytes: number): DeflateExports | undefined {
  const module = compiled()

  if (module === undefined) {
    return undefined
  }

  return bytes > SHARED_MEMORY ? new WebAssembly.Instance(module).exports as DeflateExports : shared()
}

function reserve(exports: DeflateExports, bytes: number): number | undefined {
  const base = exports.heap_base()
  const missing = base + bytes - exports.memory.buffer.byteLength

  if (missing > 0) {
    try {
      exports.memory.grow(Math.ceil(missing / 65536))
    } catch (error) {
      if (error instanceof RangeError) {
        return undefined
      }

      throw error
    }
  }

  return base
}

export function deflateWasm(data: Uint8Array): Uint8Array | undefined {
  const exports = engine(data.length * 2)

  if (exports === undefined) {
    return undefined
  }

  const bound = exports.bound(data.length)
  const base = reserve(exports, data.length + bound)

  if (base === undefined) {
    return undefined
  }

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
    const exports = engine(data.length + capacity)

    if (exports === undefined) {
      return undefined
    }

    const base = reserve(exports, data.length + capacity)

    if (base === undefined) {
      return undefined
    }

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
