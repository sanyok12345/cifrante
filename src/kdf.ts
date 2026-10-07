import { assertLength, toBytes } from './bytes.js'
import { InvalidInputError, UnsupportedError } from './errors.js'
import { sha1Sync } from './hash/sha1.js'
import { createSyncHmac, hmacSha256Sync, hmacSha512Sync, macAsync } from './hmac.js'
import type { SyncHmac } from './hmac.js'
import { nativeHkdf, nativePbkdf2 } from './native/web.js'
import type { Data } from './types.js'
import { pbkdf2Wasm, pbkdf2WasmAsync } from './wasm/pbkdf2.js'
import { PBKDF2_SLICE, SLICE, yieldNow } from './yield.js'

export type HashName = 'sha1' | 'sha256' | 'sha512'

export interface Pbkdf2Options {
  hash?: HashName
  iterations: number
  length: number
}

export interface HkdfOptions {
  hash?: HashName
  salt?: Data
  info?: Data
  length: number
}

export interface KDF {
  pbkdf2(password: Data, salt: Data, options: Pbkdf2Options): Promise<Uint8Array>
  hkdf(input: Data, options: HkdfOptions): Promise<Uint8Array>
}

const hmacSha1 = /* @__PURE__ */ createSyncHmac('sha1', sha1Sync, 64)

function resolveHash(name: HashName | undefined): {
  name: HashName
  size: number
  mac: SyncHmac
} {
  switch (name) {
    case undefined:
    case 'sha256': {
      return { name: 'sha256', size: 32, mac: hmacSha256Sync }
    }

    case 'sha512': {
      return { name: 'sha512', size: 64, mac: hmacSha512Sync }
    }

    case 'sha1': {
      return { name: 'sha1', size: 20, mac: hmacSha1 }
    }

    default: {
      throw new UnsupportedError('Unsupported KDF hash; expected sha1, sha256 or sha512')
    }
  }
}

async function pbkdf2(password: Data, salt: Data, options: Pbkdf2Options): Promise<Uint8Array> {
  if (!options || typeof options !== 'object') {
    throw new InvalidInputError('PBKDF2 options are required')
  }

  const { name, size, mac } = resolveHash(options.hash)
  const { iterations, length } = options

  if (!Number.isSafeInteger(iterations) || iterations <= 0) {
    throw new InvalidInputError('PBKDF2 iterations must be a positive safe integer')
  }

  assertLength(length)

  if (length > 0xffffffff * size) {
    throw new InvalidInputError('PBKDF2 output exceeds the block counter limit')
  }

  const key = toBytes(password)
  const saltBytes = toBytes(salt)

  try {
    if (length === 0) {
      return new Uint8Array()
    }

    const native = await nativePbkdf2(name, key, saltBytes, iterations, length)

    if (native !== undefined) {
      return Uint8Array.from(native)
    }

    const wasm = iterations > PBKDF2_SLICE || key.length + saltBytes.length > SLICE
      ? await pbkdf2WasmAsync(name, key, saltBytes, iterations, length)
      : pbkdf2Wasm(name, key, saltBytes, iterations, length)

    if (wasm !== undefined) {
      return wasm
    }

    const output = new Uint8Array(length)
    const counter = new Uint8Array(4)
    const view = new DataView(counter.buffer)

    for (let index = 1, offset = 0; offset < length; index++, offset += size) {
      view.setUint32(0, index)

      let u = mac.create(key)
        .update(saltBytes)
        .update(counter)
        .digest()
      const block = Uint8Array.from(u)

      for (let round = 1; round < iterations; round++) {
        const next = mac(key, u)

        u.fill(0)
        u = next

        for (let i = 0; i < size; i++) {
          block[i] ^= u[i]
        }

        if (round % PBKDF2_SLICE === 0) {
          await yieldNow()
        }
      }

      output.set(block.subarray(0, Math.min(size, length - offset)), offset)
      block.fill(0)
      u.fill(0)
    }

    return output
  } finally {
    key.fill(0)
  }
}

async function hkdf(input: Data, options: HkdfOptions): Promise<Uint8Array> {
  if (!options || typeof options !== 'object') {
    throw new InvalidInputError('HKDF options are required')
  }

  const { name, size, mac } = resolveHash(options.hash)
  const { length } = options

  assertLength(length)

  if (length > 255 * size) {
    throw new InvalidInputError('HKDF output exceeds 255 hash blocks')
  }

  const key = toBytes(input)
  const salt = options.salt === undefined
    ? new Uint8Array(size)
    : toBytes(options.salt)
  const info = options.info === undefined
    ? new Uint8Array()
    : toBytes(options.info)

  try {
    if (length === 0) {
      return new Uint8Array()
    }

    const native = await nativeHkdf(name, key, salt, info, length)

    if (native !== undefined) {
      return Uint8Array.from(native)
    }

    const output = new Uint8Array(length)
    const prk = key.length > SLICE ? await macAsync(mac, salt, key) : mac(salt, key)
    let previous: Uint8Array = new Uint8Array()
    const counter = new Uint8Array(1)

    try {
      for (let index = 1, offset = 0; offset < length; index++, offset += size) {
        counter[0] = index

        const block = mac.create(prk)
          .update(previous)
          .update(info)
          .update(counter)
          .digest()

        previous.fill(0)
        previous = block
        output.set(block.subarray(0, Math.min(size, length - offset)), offset)
      }

      return output
    } finally {
      prk.fill(0)
      previous.fill(0)
    }
  } finally {
    key.fill(0)
  }
}

export const kdf: KDF = { pbkdf2, hkdf }
