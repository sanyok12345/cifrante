import { CifranteError, InvalidInputError } from '../errors.js'
import { lazy } from '../lazy.js'
import { PBKDF2_SLICE, SLICE, yieldNow } from '../yield.js'
import { wasm } from './module.js'
import type { HashName } from '../kdf.js'
import source from '../../build/wasm/pbkdf2.wasm'

type Pbkdf2Exports = WebAssembly.Exports & {
  memory: WebAssembly.Memory
  state_ptr(): number
  state_size(): number
  input_ptr(): number
  input_capacity(): number
  output_ptr(): number
  init(algorithm: number, hashPassword: number): number
  password_update(length: number): number
  password_finalize(): number
  salt_update(length: number): number
  derive(index: number, iterationsLow: number, iterationsHigh: number): number
  derive_begin(index: number): number
  derive_rounds(countLow: number, countHigh: number): number
  derive_end(): number
  clear(): void
}

const load = /* @__PURE__ */ wasm<Pbkdf2Exports>(source)
const prepare = /* @__PURE__ */ lazy(() => {
  const engine = load()

  if (!engine) {
    return undefined
  }

  return {
    engine,
    memory: new Uint8Array(engine.memory.buffer),
    stateOffset: engine.state_ptr(),
    stateSize: engine.state_size(),
    inputOffset: engine.input_ptr(),
    inputCapacity: engine.input_capacity(),
    outputOffset: engine.output_ptr(),
  }
})

function check(status: number): void {
  if (status === 1) {
    throw new InvalidInputError('Message is too long for this hash')
  }

  if (status !== 0) {
    throw new CifranteError('WASM PBKDF2 operation failed')
  }
}

function parameters(hash: HashName) {
  return {
    algorithm: hash === 'sha1' ? 1 : hash === 'sha256' ? 256 : 512,
    size: hash === 'sha1' ? 20 : hash === 'sha256' ? 32 : 64,
    blockSize: hash === 'sha512' ? 128 : 64,
  }
}

export function pbkdf2Wasm(
  hash: HashName,
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  length: number,
): Uint8Array | undefined {
  const context = prepare()

  if (!context) {
    return undefined
  }

  const { engine, memory, inputOffset, inputCapacity, outputOffset } = context
  const { algorithm, size, blockSize } = parameters(hash)
  const output = new Uint8Array(length)

  function update(data: Uint8Array, operation: (length: number) => number): void {
    for (let offset = 0; offset < data.length; offset += inputCapacity) {
      const chunk = data.subarray(offset, offset + inputCapacity)
      memory.set(chunk, inputOffset)
      check(operation(chunk.length))
    }
  }

  try {
    check(engine.init(algorithm, password.length > blockSize ? 1 : 0))
    update(password, engine.password_update)
    check(engine.password_finalize())
    update(salt, engine.salt_update)

    const iterationsLow = iterations >>> 0
    const iterationsHigh = Math.floor(iterations / 0x100000000)

    for (let index = 1, offset = 0; offset < length; index++, offset += size) {
      check(engine.derive(index, iterationsLow, iterationsHigh))
      output.set(memory.subarray(outputOffset, outputOffset + Math.min(size, length - offset)), offset)
    }

    return output
  } catch (error) {
    output.fill(0)
    throw error
  } finally {
    engine.clear()
  }
}

export async function pbkdf2WasmAsync(
  hash: HashName,
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  length: number,
): Promise<Uint8Array | undefined> {
  const context = prepare()

  if (!context) {
    return undefined
  }

  const { engine, memory, stateOffset, stateSize, inputOffset, inputCapacity, outputOffset } = context
  const { algorithm, size, blockSize } = parameters(hash)
  const output = new Uint8Array(length)
  const working = new Uint8Array(stateSize)

  function restore(): void {
    memory.set(working, stateOffset)
  }

  function suspend(): void {
    working.set(memory.subarray(stateOffset, stateOffset + stateSize))
    engine.clear()
  }

  async function pause(): Promise<void> {
    suspend()
    await yieldNow()
    restore()
  }

  function update(data: Uint8Array, operation: (length: number) => number): void {
    for (let offset = 0; offset < data.length; offset += inputCapacity) {
      const chunk = data.subarray(offset, offset + inputCapacity)
      memory.set(chunk, inputOffset)
      check(operation(chunk.length))
    }
  }

  try {
    check(engine.init(algorithm, password.length > blockSize ? 1 : 0))

    for (let offset = 0; offset < password.length; offset += SLICE) {
      if (offset > 0) {
        await pause()
      }

      update(password.subarray(offset, offset + SLICE), engine.password_update)
    }

    check(engine.password_finalize())

    for (let offset = 0; offset < salt.length; offset += SLICE) {
      if (offset > 0) {
        await pause()
      }

      update(salt.subarray(offset, offset + SLICE), engine.salt_update)
    }

    for (let index = 1, offset = 0; offset < length; index++, offset += size) {
      check(engine.derive_begin(index))

      for (let remaining = iterations - 1; remaining > 0;) {
        const count = Math.min(remaining, PBKDF2_SLICE)

        check(engine.derive_rounds(count, 0))
        remaining -= count

        if (remaining > 0) {
          await pause()
        }
      }

      check(engine.derive_end())
      output.set(memory.subarray(outputOffset, outputOffset + Math.min(size, length - offset)), offset)

      if (offset + size < length) {
        await pause()
      }
    }

    return output
  } catch (error) {
    output.fill(0)
    throw error
  } finally {
    working.fill(0)
    engine.clear()
  }
}
