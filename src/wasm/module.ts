import { decodeBase64 } from '../bytes.js'
import { lazy } from '../lazy.js'

export function wasm<T extends WebAssembly.Exports>(source: string): () => T | undefined {
  return lazy(() => {
    if (typeof WebAssembly === 'undefined') {
      return undefined
    }

    try {
      const module = new WebAssembly.Module(decodeBase64(source))
      return new WebAssembly.Instance(module).exports as T
    } catch (error) {
      if (error instanceof WebAssembly.CompileError) {
        return undefined
      }

      throw error
    }
  })
}
