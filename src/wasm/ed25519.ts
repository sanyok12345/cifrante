import { growable } from './module.js'
import type { GrowableExports } from './module.js'
import source from '../../build/wasm/ed25519.wasm'

type Ed25519Exports = GrowableExports & {
  public_key(seed: number, output: number): void
  sign(seed: number, message: number, length: number, output: number): void
  verify(publicKey: number, message: number, length: number, signature: number): number
}

const reserve = /* @__PURE__ */ growable<Ed25519Exports>(source)

function call<T>(message: Uint8Array, run: (exports: Ed25519Exports, memory: Uint8Array, base: number, offset: number) => T): T | undefined {
  const reserved = reserve(128 + message.length)

  if (reserved === undefined) {
    return undefined
  }

  const { exports, base } = reserved
  const memory = new Uint8Array(exports.memory.buffer)

  memory.set(message, base + 128)

  try {
    return run(exports, memory, base, base + 128)
  } finally {
    memory.fill(0, base, base + 128 + message.length)
  }
}

export function ed25519PublicWasm(seed: Uint8Array): Uint8Array | undefined {
  return call(new Uint8Array(0), (exports, memory, base) => {
    memory.set(seed, base)
    exports.public_key(base, base + 32)

    return memory.slice(base + 32, base + 64)
  })
}

export function ed25519SignWasm(seed: Uint8Array, message: Uint8Array): Uint8Array | undefined {
  return call(message, (exports, memory, base, offset) => {
    memory.set(seed, base)
    exports.sign(base, offset, message.length, base + 64)

    return memory.slice(base + 64, base + 128)
  })
}

export function ed25519VerifyWasm(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean | undefined {
  return call(message, (exports, memory, base, offset) => {
    memory.set(publicKey, base + 32)
    memory.set(signature, base + 64)

    return exports.verify(base + 32, offset, message.length, base + 64) === 1
  })
}
