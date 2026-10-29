import type { Session } from '../chacha20/core.js'
import { UnsupportedError } from '../errors.js'
import { growable } from './module.js'
import type { GrowableExports } from './module.js'
import source from '../../build/wasm/chacha20.wasm'

type ChaChaExports = GrowableExports & {
  state_size(): number
  init(state: number, key: number, nonce: number, aad: number, length: number): void
  update(state: number, input: number, output: number, length: number, decrypting: number): void
  final(state: number, tag: number): void
}

const reserve = /* @__PURE__ */ growable<ChaChaExports>(source)

export function chacha20Poly1305Wasm(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, decrypting: boolean): Session | undefined {
  const reserved = reserve(512 + aad.length)

  if (reserved === undefined) {
    return undefined
  }

  const size = reserved.exports.state_size()
  let state: Uint8Array = new Uint8Array(size)

  function run<T>(extra: number, operation: (exports: ChaChaExports, memory: Uint8Array, base: number) => T): T {
    const reserved = reserve(size + extra)

    if (reserved === undefined) {
      throw new UnsupportedError('Unable to reserve WebAssembly memory')
    }

    const { exports, base } = reserved
    const memory = new Uint8Array(exports.memory.buffer)

    memory.set(state, base)

    try {
      const result = operation(exports, memory, base)
      state = memory.slice(base, base + size)
      return result
    } finally {
      memory.fill(0, base, base + size + extra)
    }
  }

  run(64 + aad.length, (exports, memory, base) => {
    memory.set(key, base + size)
    memory.set(nonce, base + size + 32)
    memory.set(aad, base + size + 64)
    exports.init(base, base + size, base + size + 32, base + size + 64, aad.length)
  })

  function finish(): Uint8Array {
    const tag = run(16, (exports, memory, base) => {
      exports.final(base, base + size)
      return memory.slice(base + size, base + size + 16)
    })

    state.fill(0)
    return tag
  }

  return {
    update(input, output) {
      run(input.length * 2, (exports, memory, base) => {
        memory.set(input, base + size)
        exports.update(base, base + size, base + size + input.length, input.length, decrypting ? 1 : 0)
        output.set(memory.subarray(base + size + input.length, base + size + 2 * input.length))
      })
    },

    seal: finish,

    open(tag) {
      const expected = finish()
      let difference = expected.length ^ tag.length

      for (let i = 0; i < expected.length; i++) {
        difference |= expected[i] ^ tag[i]
      }

      return difference === 0
    },
  }
}

export function chacha20WasmAvailable(): boolean {
  return reserve(0) !== undefined
}
