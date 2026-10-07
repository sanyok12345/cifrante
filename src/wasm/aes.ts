import { AuthenticationError, CifranteError } from '../errors.js'
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
  const engine = load()

  if (!engine) {
    return undefined
  }

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

  try {
    memory.set(key, keyOffset)
    check(engine.init(key.length))
    state = memory.slice(stateOffset, stateOffset + stateSize)
    cipherState = state.subarray(0, cipherSize)
  } finally {
    memory.fill(0, keyOffset, keyOffset + 32)
    memory.fill(0, stateOffset, stateOffset + stateSize)
  }

  function run<T>(operation: () => T): T {
    try {
      memory.set(state, stateOffset)
      return operation()
    } finally {
      memory.fill(0, stateOffset, stateOffset + stateSize)
      memory.fill(0, inputOffset, inputOffset + inputUsed)
      inputUsed = 0
    }
  }

  const operations = {
    ige: [engine.ige_encrypt, engine.ige_decrypt],
    cbc: [engine.cbc_encrypt, engine.cbc_decrypt],
    ctr: [engine.ctr_transform, engine.ctr_transform],
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

  const beginGcm = (nonce: Uint8Array, aad: Uint8Array): void => {
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

  return {
    transform(
      mode: 'ige' | 'cbc' | 'ctr',
      data: Uint8Array,
      iv: Uint8Array,
      decrypt: boolean,
    ): Uint8Array<ArrayBuffer> {
      const operation = operations[mode][decrypt ? 1 : 0]
      let output: Uint8Array<ArrayBuffer> | undefined

      try {
        memory.set(cipherState, stateOffset)
        memory.set(iv, ivOffset)

        if (data.length <= inputCapacity) {
          output = updateSingle(data, operation)
        } else {
          output = new Uint8Array(data.length)
          update(data, operation, output)
        }

        return output
      } catch (error) {
        output?.fill(0)
        throw error
      } finally {
        memory.fill(0, stateOffset, stateOffset + cipherSize)
        memory.fill(0, inputOffset, inputOffset + inputUsed)
        inputUsed = 0
      }
    },

    encryptGcm(
      data: Uint8Array,
      nonce: Uint8Array,
      aad: Uint8Array,
      tagLength: number,
    ): { ciphertext: Uint8Array<ArrayBuffer>, tag: Uint8Array<ArrayBuffer> } {
      const ciphertext = new Uint8Array(data.length)

      try {
        return run(() => {
          beginGcm(nonce, aad)
          update(data, engine.gcm_encrypt, ciphertext)
          check(engine.gcm_tag())
          return { ciphertext, tag: memory.slice(tagOffset, tagOffset + tagLength) }
        })
      } catch (error) {
        ciphertext.fill(0)
        throw error
      }
    },

    decryptGcm(
      data: Uint8Array,
      nonce: Uint8Array,
      aad: Uint8Array,
      tag: Uint8Array,
    ): Uint8Array<ArrayBuffer> {
      let output: Uint8Array<ArrayBuffer> | undefined

      try {
        return run(() => {
          beginGcm(nonce, aad)
          update(data, engine.gcm_authenticate)
          check(engine.gcm_tag())
          write(tag)
          check(engine.gcm_verify(tag.length))
          output = new Uint8Array(data.length)
          update(data, engine.gcm_decrypt, output)
          return output
        })
      } catch (error) {
        output?.fill(0)
        throw error
      }
    },
  }
}
