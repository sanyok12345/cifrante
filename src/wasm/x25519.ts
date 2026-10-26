import { lazy } from '../lazy.js'
import { wasm } from './module.js'
import source from '../../build/wasm/x25519.wasm'

type X25519Exports = WebAssembly.Exports & {
  memory: WebAssembly.Memory
  scalar_ptr(): number
  point_ptr(): number
  output_ptr(): number
  scalarmult(): void
  clear(): void
}

const load = /* @__PURE__ */ wasm<X25519Exports>(source)
const prepare = /* @__PURE__ */ lazy(() => {
  const engine = load()

  if (!engine) {
    return undefined
  }

  return {
    engine,
    memory: new Uint8Array(engine.memory.buffer),
    scalarOffset: engine.scalar_ptr(),
    pointOffset: engine.point_ptr(),
    outputOffset: engine.output_ptr(),
  }
})

export function scalarMultWasm(scalar: Uint8Array, point: Uint8Array): Uint8Array | undefined {
  const context = prepare()

  if (!context) {
    return undefined
  }

  const { engine, memory, scalarOffset, pointOffset, outputOffset } = context

  try {
    memory.set(scalar, scalarOffset)
    memory.set(point, pointOffset)
    engine.scalarmult()

    return memory.slice(outputOffset, outputOffset + 32)
  } finally {
    engine.clear()
  }
}
