import { AuthenticationError, CifranteError } from '../errors.js'
import { SLICE, yieldNow } from '../yield.js'
import { wasm } from './module.js'
import portable from '../../build/wasm/aes.wasm'
import simd from '../../build/wasm/aes.simd.wasm'
import relaxed from '../../build/wasm/aes.relaxed.wasm'

type AesExports = WebAssembly.Exports & {
  memory: WebAssembly.Memory
  state_ptr(): number
  state_size(): number
  state_cipher_size(): number
  key_ptr(): number
  iv_ptr(): number
  tag_ptr(): number
  input_ptr(): number
  input_capacity(): number
  init(length: number): number
  ige_encrypt(length: number): number
  ige_decrypt(length: number): number
  cbc_encrypt(length: number): number
  cbc_decrypt(length: number): number
  ctr_transform(length: number): number
  gcm_prepare(): number
  gcm_begin(shortNonce: number): number
  gcm_nonce(length: number): number
  gcm_nonce_end(): number
  gcm_aad(length: number): number
  gcm_encrypt(length: number): number
  gcm_authenticate(length: number): number
  gcm_tag(): number
  gcm_verify(length: number): number
  gcm_decrypt(length: number): number
}

export type AesMode = 'ige' | 'cbc' | 'ctr'

export interface WasmSealed {
  ciphertext: Uint8Array<ArrayBuffer>
  tag: Uint8Array<ArrayBuffer>
}

const load = /* @__PURE__ */ wasm<AesExports>(relaxed, simd, portable)

function check(status: number): void {
  if (status === 4) {
    throw new AuthenticationError('Invalid AES-GCM authentication tag')
  }

  if (status !== 0) {
    throw new CifranteError('WASM AES operation failed')
  }
}

export function createAesWasm(key: Uint8Array) {
  const loaded = load()

  if (!loaded) {
    return undefined
  }

  const engine: AesExports = loaded

  const stateOffset = engine.state_ptr()
  const stateSize = engine.state_size()
  const cipherSize = engine.state_cipher_size()
  const keyOffset = engine.key_ptr()
  const ivOffset = engine.iv_ptr()
  const tagOffset = engine.tag_ptr()
  const inputOffset = engine.input_ptr()
  const inputCapacity = engine.input_capacity()
  const memory = new Uint8Array(engine.memory.buffer)
  let state: Uint8Array<ArrayBuffer>
  let cipherState: Uint8Array<ArrayBuffer>
  let inputUsed = 0
  let gcmReady = false

  try {
    memory.set(key, keyOffset)
    check(engine.init(key.length))
    state = memory.slice(stateOffset, stateOffset + stateSize)
    cipherState = state.subarray(0, cipherSize)
  } finally {
    memory.fill(0, keyOffset, keyOffset + 32)
    memory.fill(0, stateOffset, stateOffset + stateSize)
  }

  const operations = {
    ige: [engine.ige_encrypt, engine.ige_decrypt],
    cbc: [engine.cbc_encrypt, engine.cbc_decrypt],
    ctr: [engine.ctr_transform, engine.ctr_transform],
  }

  function clear(size: number): void {
    memory.fill(0, stateOffset, stateOffset + size)
    memory.fill(0, inputOffset, inputOffset + inputUsed)
    inputUsed = 0
  }

  function run<T>(source: Uint8Array, operation: () => T): T {
    try {
      memory.set(source, stateOffset)
      return operation()
    } finally {
      clear(source.length)
    }
  }

  function step<T>(working: Uint8Array, operation: () => T): T {
    try {
      memory.set(working, stateOffset)

      const result = operation()

      working.set(memory.subarray(stateOffset, stateOffset + working.length))
      return result
    } finally {
      clear(working.length)
    }
  }

  function write(data: Uint8Array): void {
    inputUsed = Math.max(inputUsed, data.length)
    memory.set(data, inputOffset)
  }

  function update(
    data: Uint8Array,
    operation: (length: number) => number,
    output?: Uint8Array,
  ): void {
    for (let offset = 0; offset < data.length; offset += inputCapacity) {
      const chunk = data.subarray(offset, offset + inputCapacity)
      write(chunk)
      check(operation(chunk.length))
      output?.set(memory.subarray(inputOffset, inputOffset + chunk.length), offset)
    }
  }

  function updateSingle(
    data: Uint8Array,
    operation: (length: number) => number,
  ): Uint8Array<ArrayBuffer> {
    write(data)
    check(operation(data.length))
    return memory.slice(inputOffset, inputOffset + data.length)
  }

  async function feed(
    working: Uint8Array,
    data: Uint8Array,
    operation: (length: number) => number,
    output?: Uint8Array,
  ): Promise<void> {
    for (let offset = 0; offset < data.length; offset += SLICE) {
      const slice = data.subarray(offset, offset + SLICE)

      step(working, () => update(slice, operation, output?.subarray(offset)))

      if (offset + SLICE < data.length) {
        await yieldNow()
      }
    }
  }

  function beginGcm(nonce: Uint8Array, aad: Uint8Array): void {
    if (nonce.length === 12) {
      memory.set(nonce, ivOffset)
      check(engine.gcm_begin(1))
    } else {
      check(engine.gcm_begin(0))
      update(nonce, engine.gcm_nonce)
      check(engine.gcm_nonce_end())
    }

    update(aad, engine.gcm_aad)
  }

  async function beginGcmAsync(working: Uint8Array, nonce: Uint8Array, aad: Uint8Array): Promise<void> {
    if (nonce.length === 12) {
      step(working, () => {
        memory.set(nonce, ivOffset)
        check(engine.gcm_begin(1))
      })
    } else {
      step(working, () => check(engine.gcm_begin(0)))
      await feed(working, nonce, engine.gcm_nonce)
      step(working, () => check(engine.gcm_nonce_end()))
    }

    await feed(working, aad, engine.gcm_aad)
  }

  function prepareGcm(): void {
    if (gcmReady) {
      return
    }

    run(state, () => {
      check(engine.gcm_prepare())
      state.set(memory.subarray(stateOffset, stateOffset + stateSize))
    })
    gcmReady = true
  }

  function tag(length: number): Uint8Array<ArrayBuffer> {
    check(engine.gcm_tag())
    return memory.slice(tagOffset, tagOffset + length)
  }

  function verify(expected: Uint8Array): void {
    check(engine.gcm_tag())
    write(expected)
    check(engine.gcm_verify(expected.length))
  }

  return {
    transform(
      mode: AesMode,
      data: Uint8Array,
      iv: Uint8Array,
      decrypt: boolean,
    ): Uint8Array<ArrayBuffer> {
      const operation = operations[mode][decrypt ? 1 : 0]
      let output: Uint8Array<ArrayBuffer> | undefined

      try {
        return run(cipherState, () => {
          memory.set(iv, ivOffset)

          if (data.length <= inputCapacity) {
            output = updateSingle(data, operation)
          } else {
            output = new Uint8Array(data.length)
            update(data, operation, output)
          }

          return output
        })
      } catch (error) {
        output?.fill(0)
        throw error
      }
    },

    async transformAsync(
      mode: AesMode,
      data: Uint8Array,
      iv: Uint8Array,
      decrypt: boolean,
    ): Promise<Uint8Array<ArrayBuffer>> {
      const operation = operations[mode][decrypt ? 1 : 0]
      const output = new Uint8Array(data.length)
      const working = cipherState.slice()

      try {
        step(working, () => memory.set(iv, ivOffset))
        await feed(working, data, operation, output)
        return output
      } catch (error) {
        output.fill(0)
        throw error
      } finally {
        working.fill(0)
      }
    },

    ctrState(iv: Uint8Array) {
      const working = cipherState.slice()

      working.set(iv, ivOffset - stateOffset)

      return {
        update(data: Uint8Array): Uint8Array<ArrayBuffer> {
          const output = new Uint8Array(data.length)

          step(working, () => update(data, engine.ctr_transform, output))
          return output
        },
        dispose(): void {
          working.fill(0)
        },
      }
    },

    encryptGcm(
      data: Uint8Array,
      nonce: Uint8Array,
      aad: Uint8Array,
      tagLength: number,
    ): WasmSealed {
      prepareGcm()
      const ciphertext = new Uint8Array(data.length)

      try {
        return run(state, () => {
          beginGcm(nonce, aad)
          update(data, engine.gcm_encrypt, ciphertext)
          return { ciphertext, tag: tag(tagLength) }
        })
      } catch (error) {
        ciphertext.fill(0)
        throw error
      }
    },

    async encryptGcmAsync(
      data: Uint8Array,
      nonce: Uint8Array,
      aad: Uint8Array,
      tagLength: number,
    ): Promise<WasmSealed> {
      prepareGcm()
      const ciphertext = new Uint8Array(data.length)
      const working = state.slice()

      try {
        await beginGcmAsync(working, nonce, aad)
        await feed(working, data, engine.gcm_encrypt, ciphertext)
        return { ciphertext, tag: step(working, () => tag(tagLength)) }
      } catch (error) {
        ciphertext.fill(0)
        throw error
      } finally {
        working.fill(0)
      }
    },

    decryptGcm(
      data: Uint8Array,
      nonce: Uint8Array,
      aad: Uint8Array,
      expected: Uint8Array,
    ): Uint8Array<ArrayBuffer> {
      prepareGcm()
      let output: Uint8Array<ArrayBuffer> | undefined

      try {
        return run(state, () => {
          beginGcm(nonce, aad)
          update(data, engine.gcm_authenticate)
          verify(expected)
          output = new Uint8Array(data.length)
          update(data, engine.gcm_decrypt, output)
          return output
        })
      } catch (error) {
        output?.fill(0)
        throw error
      }
    },

    async decryptGcmAsync(
      data: Uint8Array,
      nonce: Uint8Array,
      aad: Uint8Array,
      expected: Uint8Array,
    ): Promise<Uint8Array<ArrayBuffer>> {
      prepareGcm()
      const working = state.slice()
      let output: Uint8Array<ArrayBuffer> | undefined

      try {
        await beginGcmAsync(working, nonce, aad)
        await feed(working, data, engine.gcm_authenticate)
        step(working, () => verify(expected))
        output = new Uint8Array(data.length)
        await feed(working, data, engine.gcm_decrypt, output)
        return output
      } catch (error) {
        output?.fill(0)
        throw error
      } finally {
        working.fill(0)
      }
    },
  }
}
