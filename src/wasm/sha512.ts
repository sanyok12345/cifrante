import { wasmHash } from './hash.js'
import source from '../../build/wasm/sha512.wasm'

export const createSha512Wasm = /* @__PURE__ */ wasmHash(source, 'SHA-512', 64)
