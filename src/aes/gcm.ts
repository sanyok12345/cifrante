import { toBinary, toBinaryView, toBytes, toBytesView } from '../bytes.js'
import { AuthenticationError, InvalidInputError, InvalidNonceError } from '../errors.js'
import { lazy } from '../lazy.js'
import { createAesWasm } from '../wasm/aes.js'
import { nativeGcm } from '../native/web.js'
import type { Binary, Data } from '../types.js'
import { AesBlock, keyBytes } from './block.js'

export interface GcmOptions {
  tagLength?: 96 | 104 | 112 | 120 | 128
}

export interface GcmOperationOptions {
  nonce: Binary
  aad?: Data
}

export interface Sealed {
  ciphertext: Uint8Array
  tag: Uint8Array
}

export interface AeadCipher {
  encrypt(data: Data, options: GcmOperationOptions): Promise<Sealed>
  decrypt(data: Sealed, options: GcmOperationOptions): Promise<Uint8Array>
}

class GHash {
  private readonly h = new Uint32Array(4)
  private readonly state = new Uint32Array(4)

  constructor(hashKey: Uint8Array) {
    for (let i = 0; i < 16; i++) {
      this.h[i >>> 2] |= hashKey[i] << (24 - (i & 3) * 8)
    }
  }

  update(data: Uint8Array): this {
    for (let offset = 0; offset < data.length; offset += 16) {
      for (let i = 0; i < Math.min(16, data.length - offset); i++) {
        this.state[i >>> 2] ^= data[offset + i] << (24 - (i & 3) * 8)
      }

      let a = 0,
        b = 0,
        c = 0,
        d = 0

      let v0 = this.h[0],
        v1 = this.h[1],
        v2 = this.h[2],
        v3 = this.h[3]

      for (let bit = 0; bit < 128; bit++) {
        const mask = -((this.state[bit >>> 5] >>> (31 - (bit & 31))) & 1)
        a ^= v0 & mask
        b ^= v1 & mask
        c ^= v2 & mask
        d ^= v3 & mask

        const reduction = -(v3 & 1) & 0xe1000000
        v3 = (v3 >>> 1) | (v2 << 31)
        v2 = (v2 >>> 1) | (v1 << 31)
        v1 = (v1 >>> 1) | (v0 << 31)
        v0 = (v0 >>> 1) ^ reduction
      }

      this.state[0] = a
      this.state[1] = b
      this.state[2] = c
      this.state[3] = d
    }

    return this
  }

  finish(firstLength: number, secondLength: number): Uint8Array<ArrayBuffer> {
    const lengths = new Uint8Array(16)
    const view = new DataView(lengths.buffer)
    view.setUint32(0, Math.floor(firstLength / 0x20000000))
    view.setUint32(4, (firstLength * 8) >>> 0)
    view.setUint32(8, Math.floor(secondLength / 0x20000000))
    view.setUint32(12, (secondLength * 8) >>> 0)
    this.update(lengths)

    for (let i = 0; i < 4; i++) {
      view.setUint32(i * 4, this.state[i])
    }

    return lengths
  }
}

function nonceBytes(nonce: Binary): Uint8Array {
  let bytes: Uint8Array

  try {
    bytes = toBinaryView(nonce)
  } catch (error) {
    if (error instanceof InvalidInputError) {
      throw new InvalidNonceError('AES-GCM nonce must be binary data')
    }

    throw error
  }

  if (bytes.length === 0) {
    throw new InvalidNonceError('AES-GCM nonce must not be empty')
  }

  return bytes
}

function checkLength(length: number): void {
  if (length > 2 ** 36 - 32) {
    throw new InvalidInputError('AES-GCM input exceeds the 2^39 - 256 bit limit')
  }
}

function operationBytes(options: GcmOperationOptions): {
  nonce: Uint8Array
  aad: Uint8Array
} {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new InvalidInputError('AES-GCM operation requires nonce options')
  }

  const nonce = nonceBytes(options.nonce)
  const aad = options.aad === undefined ? new Uint8Array(0) : toBytesView(options.aad)
  return { nonce, aad }
}

export function gcm(
  key: Binary,
  options: GcmOptions = {},
): AeadCipher {
  const secret = keyBytes(key)

  if (
    options === null ||
    typeof options !== 'object' ||
    Array.isArray(options)
  ) {
    throw new InvalidInputError('Invalid AES-GCM options')
  }

  const tagBits = options.tagLength === undefined ? 128 : options.tagLength

  if (![96, 104, 112, 120, 128].includes(tagBits)) {
    throw new InvalidInputError('AES-GCM tagLength must be 96, 104, 112, 120 or 128 bits')
  }

  const tagLength = tagBits / 8
  const native = nativeGcm(secret)
  const prepareWasm = lazy(() => createAesWasm(secret))
  let block: AesBlock | undefined
  let hashKey: Uint8Array<ArrayBuffer>

  function prepare(): AesBlock {
    if (block !== undefined) {
      return block
    }

    block = new AesBlock(secret)
    hashKey = block.encrypt(new Uint8Array(16))
    return block
  }

  function initialCounter(nonce: Uint8Array): Uint8Array<ArrayBuffer> {
    prepare()

    if (nonce.length === 12) {
      const j0 = new Uint8Array(16)
      j0.set(nonce)
      j0[15] = 1
      return j0
    }

    return new GHash(hashKey).update(nonce).finish(0, nonce.length)
  }

  function authenticationTag(
    ciphertext: Uint8Array,
    aad: Uint8Array,
    j0: Uint8Array,
  ): Uint8Array<ArrayBuffer> {
    const cipher = prepare()
    const hash = new GHash(hashKey)
      .update(aad)
      .update(ciphertext)
      .finish(aad.length, ciphertext.length)

    const mask = cipher.encrypt(j0)

    for (let i = 0; i < 16; i++) {
      hash[i] ^= mask[i]
    }

    return hash.slice(0, tagLength)
  }

  function transform(
    data: Uint8Array,
    j0: Uint8Array,
  ): Uint8Array<ArrayBuffer> {
    const cipher = prepare()
    const counter = j0.slice()
    const output = new Uint8Array(data.length)

    for (let offset = 0; offset < data.length; offset += 16) {
      for (let i = 15; i >= 12; i--) {
        counter[i] = (counter[i] + 1) & 255

        if (counter[i] !== 0) {
          break
        }
      }

      const stream = cipher.encrypt(counter)

      for (let i = 0; i < Math.min(16, data.length - offset); i++) {
        output[offset + i] = data[offset + i] ^ stream[i]
      }
    }

    return output
  }

  return {
    async encrypt(data, options) {
      const view = operationBytes(options)
      const useNative = native.available(view.nonce)
      const input = useNative ? toBytes(data) : toBytesView(data)
      const nonce = useNative ? Uint8Array.from(view.nonce) : view.nonce
      const aad = useNative ? Uint8Array.from(view.aad) : view.aad
      checkLength(input.length)

      if (useNative) {
        const result = await native.encrypt(nonce, input, aad, tagLength)

        if (result !== undefined) {
          return result
        }
      }

      const wasm = prepareWasm()

      if (wasm) {
        return wasm.encryptGcm(input, nonce, aad, tagLength)
      }

      const j0 = initialCounter(nonce)
      const ciphertext = transform(input, j0)
      return { ciphertext, tag: authenticationTag(ciphertext, aad, j0) }
    },

    async decrypt(data, options) {
      if (data === null || typeof data !== 'object') {
        throw new InvalidInputError('AES-GCM requires ciphertext and tag')
      }

      const view = operationBytes(options)
      const useNative = native.available(view.nonce)
      const ciphertext = useNative ? toBinary(data.ciphertext) : toBinaryView(data.ciphertext)
      const tag = useNative ? toBinary(data.tag) : toBinaryView(data.tag)
      const nonce = useNative ? Uint8Array.from(view.nonce) : view.nonce
      const aad = useNative ? Uint8Array.from(view.aad) : view.aad

      if (tag.length !== tagLength) {
        throw new AuthenticationError('Invalid AES-GCM authentication tag')
      }

      checkLength(ciphertext.length)

      if (useNative) {
        const result = await native.decrypt(nonce, ciphertext, aad, tag)

        if (result !== undefined) {
          return result
        }
      }

      const wasm = prepareWasm()

      if (wasm) {
        return wasm.decryptGcm(ciphertext, nonce, aad, tag)
      }

      const j0 = initialCounter(nonce)
      const expected = authenticationTag(ciphertext, aad, j0)
      let difference = 0

      for (let i = 0; i < tagLength; i++) {
        difference |= expected[i] ^ tag[i]
      }

      if (difference !== 0) {
        throw new AuthenticationError('Invalid AES-GCM authentication tag')
      }

      return transform(ciphertext, j0)
    },
  }
}
