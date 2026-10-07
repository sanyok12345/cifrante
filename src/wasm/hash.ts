import { CifranteError, InvalidInputError } from '../errors.js'
import { lazy } from '../lazy.js'
import { wasm } from './module.js'
import type { DigestState } from '../hash/hash.js'

type HashExports = WebAssembly.Exports & {
  memory: WebAssembly.Memory
  state_ptr(): number
  state_size(): number
  input_ptr(): number
  input_capacity(): number
  output_ptr(): number
  init(): void
  update(length: number): number
  finalize(): number
}

type Context = {
  engine: HashExports
  name: string
  outputLength: number
  memory: Uint8Array
  stateView: Uint8Array
  outputView: Uint8Array
  stateOffset: number
  stateSize: number
  inputOffset: number
  inputCapacity: number
  outputOffset: number
}

function check(status: number, name: string): void {
  if (status === 1) {
    throw new InvalidInputError('Message is too long for this hash')
  }

  if (status !== 0) {
    throw new CifranteError(`WASM ${name} operation failed`)
  }
}

class WasmHash implements DigestState {
  private readonly state: Uint8Array

  constructor(private readonly context: Context) {
    const { engine, stateView } = context
    engine.init()
    this.state = stateView.slice()
    stateView.fill(0)
  }

  private use<T>(operation: () => T, inputLength = 0): T {
    const { memory, stateView, outputView, stateOffset, inputOffset } = this.context
    memory.set(this.state, stateOffset)

    try {
      return operation()
    } catch (error) {
      this.state.fill(0)
      throw error
    } finally {
      stateView.fill(0)
      memory.fill(0, inputOffset, inputOffset + inputLength)
      outputView.fill(0)
    }
  }

  update(data: Uint8Array): void {
    const { engine, name, memory, stateView, inputOffset, inputCapacity } = this.context

    this.use(() => {
      for (let offset = 0; offset < data.length; offset += inputCapacity) {
        const chunk = data.subarray(offset, offset + inputCapacity)
        memory.set(chunk, inputOffset)
        check(engine.update(chunk.length), name)
      }

      this.state.set(stateView)
    }, Math.min(data.length, inputCapacity))
  }

  digest(): Uint8Array {
    try {
      return this.use(() => {
        const { engine, name, outputView } = this.context
        check(engine.finalize(), name)
        return outputView.slice()
      })
    } finally {
      this.state.fill(0)
    }
  }
}

export type WasmHashFactory = (() => DigestState | undefined) & {
  once(data: Uint8Array): Uint8Array | undefined
}

export function wasmHash(
  source: string,
  name: string,
  outputLength: number,
): WasmHashFactory {
  const load = wasm<HashExports>(source)
  const prepare = lazy((): Context | undefined => {
    const engine = load()

    if (!engine) {
      return undefined
    }

    const memory = new Uint8Array(engine.memory.buffer)
    const stateOffset = engine.state_ptr()
    const stateSize = engine.state_size()
    const outputOffset = engine.output_ptr()

    return {
      engine,
      name,
      outputLength,
      memory,
      stateView: memory.subarray(stateOffset, stateOffset + stateSize),
      outputView: memory.subarray(outputOffset, outputOffset + outputLength),
      stateOffset,
      stateSize,
      inputOffset: engine.input_ptr(),
      inputCapacity: engine.input_capacity(),
      outputOffset,
    }
  })

  const once = (data: Uint8Array): Uint8Array | undefined => {
    const context = prepare()

    if (!context) {
      return undefined
    }

    const { engine, memory, stateView, outputView, inputOffset, inputCapacity } = context
    engine.init()

    try {
      for (let offset = 0; offset < data.length; offset += inputCapacity) {
        const chunk = data.subarray(offset, offset + inputCapacity)
        memory.set(chunk, inputOffset)
        check(engine.update(chunk.length), name)
      }

      check(engine.finalize(), name)
      return outputView.slice()
    } finally {
      stateView.fill(0)
      memory.fill(0, inputOffset, inputOffset + Math.min(data.length, inputCapacity))
      outputView.fill(0)
    }
  }

  return Object.assign(() => {
    const context = prepare()
    return context ? new WasmHash(context) : undefined
  }, { once })
}
