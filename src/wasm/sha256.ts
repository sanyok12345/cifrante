import { hashModule, wasmHash } from './hash.js'
import source from '../../build/wasm/sha256.wasm'

export const createSha256Wasm = /* @__PURE__ */ wasmHash(hashModule(source), 'SHA-256', 32)
