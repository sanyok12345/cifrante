import { hashModule, wasmHash } from './hash.js'
import source from '../../build/wasm/sha512.wasm'

const load = /* @__PURE__ */ hashModule(source)

export const createSha512Wasm = /* @__PURE__ */ wasmHash(load, 'SHA-512', 64)
export const createSha384Wasm = /* @__PURE__ */ wasmHash(load, 'SHA-384', 48, 64, 'init_384')
