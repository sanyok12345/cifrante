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
    const { engine, stateOffset, stateSize } = context
    engine.init()

    const memory = this.memory()
    this.state = memory.slice(stateOffset, stateOffset + stateSize)
    memory.fill(0, stateOffset, stateOffset + stateSize)
  }

  private memory(): Uint8Array {
    return new Uint8Array(this.context.engine.memory.buffer)
  }

  private use<T>(operation: () => T, inputLength = 0): T {
    const { stateOffset, stateSize, inputOffset, outputOffset, outputLength } = this.context
    this.memory().set(this.state, stateOffset)

    try {
      return operation()
    } catch (error) {
      this.state.fill(0)
      throw error
    } finally {
      const memory = this.memory()
      memory.fill(0, stateOffset, stateOffset + stateSize)
      memory.fill(0, inputOffset, inputOffset + inputLength)
      memory.fill(0, outputOffset, outputOffset + outputLength)
    }
  }

  update(data: Uint8Array): void {
    const { engine, name, stateOffset, stateSize, inputOffset, inputCapacity } = this.context

    this.use(() => {
      for (let offset = 0; offset < data.length; offset += inputCapacity) {
        const chunk = data.subarray(offset, offset + inputCapacity)
        this.memory().set(chunk, inputOffset)
        check(engine.update(chunk.length), name)
      }

      this.state.set(this.memory().subarray(stateOffset, stateOffset + stateSize))
    }, Math.min(data.length, inputCapacity))
  }

  digest(): Uint8Array {
    try {
      return this.use(() => {
        const { engine, name, outputOffset, outputLength } = this.context
        check(engine.finalize(), name)
        return this.memory().slice(outputOffset, outputOffset + outputLength)
      })
    } finally {
      this.state.fill(0)
    }
  }
}

export function wasmHash(
  source: string,
  name: string,
  outputLength: number,
): () => DigestState | undefined {
  const load = wasm<HashExports>(source)
  const prepare = lazy((): Context | undefined => {
    const engine = load()

    if (!engine) {
      return undefined
    }

    return {
      engine,
      name,
      outputLength,
      stateOffset: engine.state_ptr(),
      stateSize: engine.state_size(),
      inputOffset: engine.input_ptr(),
      inputCapacity: engine.input_capacity(),
      outputOffset: engine.output_ptr(),
    }
  })

  return () => {
    const context = prepare()
    return context ? new WasmHash(context) : undefined
  }
}
