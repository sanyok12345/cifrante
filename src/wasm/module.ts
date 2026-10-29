import { decodeBase64 } from '../bytes.js'
import { lazy } from '../lazy.js'

export function wasm<T extends WebAssembly.Exports>(...sources: string[]): () => T | undefined {
  return lazy(() => {
    if (typeof WebAssembly === 'undefined') {
      return undefined
    }

    for (const source of sources) {
      try {
        const module = new WebAssembly.Module(decodeBase64(source))
        return new WebAssembly.Instance(module).exports as T
      } catch (error) {
        if (!(error instanceof WebAssembly.CompileError)) {
          throw error
        }
      }
    }

    return undefined
  })
}

const SHARED_MEMORY = 32 * 1024 * 1024

export type GrowableExports = WebAssembly.Exports & {
  memory: WebAssembly.Memory
  heap_base(): number
}

export function growable<T extends GrowableExports>(source: string): (bytes: number) => { exports: T, base: number } | undefined {
  const compiled = lazy(() => {
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

  const shared = lazy(() => {
    const module = compiled()

    return module && new WebAssembly.Instance(module).exports as T
  })

  return (bytes) => {
    const module = compiled()

    if (module === undefined) {
      return undefined
    }

    const exports = bytes > SHARED_MEMORY ? new WebAssembly.Instance(module).exports as T : shared()!
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

    return { exports, base }
  }
}
