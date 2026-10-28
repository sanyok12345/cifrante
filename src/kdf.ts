import { assertLength, toBytes } from './bytes.js'
import { InvalidInputError, UnsupportedError } from './errors.js'
import { hmacSha1Sync, hmacSha256Sync, hmacSha384Sync, hmacSha512Sync, macAsync } from './hmac.js'
import type { SyncHmac } from './hmac.js'
import { nativeHkdf, nativeHkdfSync, nativePbkdf2, nativePbkdf2Sync } from './native/web.js'
import type { AbortOptions, Data } from './types.js'
import { pbkdf2Wasm, pbkdf2WasmAsync } from './wasm/pbkdf2.js'
import { PBKDF2_SLICE, SLICE, pacer, watch } from './yield.js'

export type HashName = 'sha1' | 'sha256' | 'sha384' | 'sha512'

export interface Pbkdf2Options extends AbortOptions {
  hash?: HashName
  iterations: number
  length: number
}

export interface HkdfOptions extends AbortOptions {
  hash?: HashName
  salt?: Data
  info?: Data
  length: number
}

export interface Pbkdf2 {
  (password: Data, salt: Data, options: Pbkdf2Options): Promise<Uint8Array>
  sync(password: Data, salt: Data, options: Omit<Pbkdf2Options, 'signal'>): Uint8Array
}

export interface Hkdf {
  (input: Data, options: HkdfOptions): Promise<Uint8Array>
  sync(input: Data, options: Omit<HkdfOptions, 'signal'>): Uint8Array
}

export interface KDF {
  pbkdf2: Pbkdf2
  hkdf: Hkdf
}

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

    case 'sha384': {
      return { name: 'sha384', size: 48, mac: hmacSha384Sync }
    }

    case 'sha512': {
      return { name: 'sha512', size: 64, mac: hmacSha512Sync }
    }

    case 'sha1': {
      return { name: 'sha1', size: 20, mac: hmacSha1Sync }
    }

    default: {
      throw new UnsupportedError('Unsupported KDF hash; expected sha1, sha256, sha384 or sha512')
    }
  }
}

function pbkdf2Parameters(options: Omit<Pbkdf2Options, 'signal'>) {
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

  return { name, size, mac, iterations, length }
}

function pbkdf2Block(
  mac: SyncHmac,
  key: Uint8Array,
  salt: Uint8Array,
  index: number,
): { block: Uint8Array, u: Uint8Array } {
  const counter = new Uint8Array(4)

  new DataView(counter.buffer).setUint32(0, index)

  const u = mac.create(key)
    .update(salt)
    .update(counter)
    .digest()

  return { block: Uint8Array.from(u), u }
}

function pbkdf2Round(mac: SyncHmac, key: Uint8Array, u: Uint8Array, block: Uint8Array): Uint8Array {
  const next = mac(key, u)

  u.fill(0)

  for (let i = 0; i < block.length; i++) {
    block[i] ^= next[i]
  }

  return next
}

async function pbkdf2(password: Data, salt: Data, options: Pbkdf2Options): Promise<Uint8Array> {
  const guard = watch(options)

  guard()

  const { name, size, mac, iterations, length } = pbkdf2Parameters(options)
  const key = toBytes(password)
  const saltBytes = toBytes(salt)

  try {
    if (length === 0) {
      return new Uint8Array()
    }

    const native = await nativePbkdf2(name, key, saltBytes, iterations, length)

    guard()

    if (native !== undefined) {
      return Uint8Array.from(native)
    }

    const wasm = iterations > PBKDF2_SLICE || key.length + saltBytes.length > SLICE
      ? await pbkdf2WasmAsync(name, key, saltBytes, iterations, length, guard)
      : pbkdf2Wasm(name, key, saltBytes, iterations, length)

    if (wasm !== undefined) {
      return wasm
    }

    const output = new Uint8Array(length)

    for (let index = 1, offset = 0; offset < length; index++, offset += size) {
      let { block, u } = pbkdf2Block(mac, key, saltBytes, index)
      const pace = pacer(guard)

      for (let round = 1; round < iterations; round++) {
        u = pbkdf2Round(mac, key, u, block)

        if ((round & 255) === 0 && pace.due()) {
          await pace.pause()
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

function pbkdf2Sync(password: Data, salt: Data, options: Omit<Pbkdf2Options, 'signal'>): Uint8Array {
  const { name, size, mac, iterations, length } = pbkdf2Parameters(options)
  const key = toBytes(password)
  const saltBytes = toBytes(salt)

  try {
    if (length === 0) {
      return new Uint8Array()
    }

    const native = nativePbkdf2Sync(name, key, saltBytes, iterations, length)

    if (native !== undefined) {
      return native
    }

    const wasm = pbkdf2Wasm(name, key, saltBytes, iterations, length)

    if (wasm !== undefined) {
      return wasm
    }

    const output = new Uint8Array(length)

    for (let index = 1, offset = 0; offset < length; index++, offset += size) {
      let { block, u } = pbkdf2Block(mac, key, saltBytes, index)

      for (let round = 1; round < iterations; round++) {
        u = pbkdf2Round(mac, key, u, block)
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

function hkdfParameters(options: Omit<HkdfOptions, 'signal'>) {
  if (!options || typeof options !== 'object') {
    throw new InvalidInputError('HKDF options are required')
  }

  const { name, size, mac } = resolveHash(options.hash)
  const { length } = options

  assertLength(length)

  if (length > 255 * size) {
    throw new InvalidInputError('HKDF output exceeds 255 hash blocks')
  }

  const salt = options.salt === undefined
    ? new Uint8Array(size)
    : toBytes(options.salt)
  const info = options.info === undefined
    ? new Uint8Array()
    : toBytes(options.info)

  return { name, size, mac, length, salt, info }
}

function hkdfExpand(
  mac: SyncHmac,
  size: number,
  prk: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  const output = new Uint8Array(length)
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
}

async function hkdf(input: Data, options: HkdfOptions): Promise<Uint8Array> {
  const guard = watch(options)

  guard()

  const { name, size, mac, length, salt, info } = hkdfParameters(options)
  const key = toBytes(input)

  try {
    if (length === 0) {
      return new Uint8Array()
    }

    const native = await nativeHkdf(name, key, salt, info, length)

    guard()

    if (native !== undefined) {
      return Uint8Array.from(native)
    }

    const prk = key.length > SLICE ? await macAsync(mac, salt, key, guard) : mac(salt, key)

    return hkdfExpand(mac, size, prk, info, length)
  } finally {
    key.fill(0)
  }
}

function hkdfSync(input: Data, options: Omit<HkdfOptions, 'signal'>): Uint8Array {
  const { name, size, mac, length, salt, info } = hkdfParameters(options)
  const key = toBytes(input)

  try {
    if (length === 0) {
      return new Uint8Array()
    }

    const native = nativeHkdfSync(name, key, salt, info, length)

    if (native !== undefined) {
      return native
    }

    return hkdfExpand(mac, size, mac(salt, key), info, length)
  } finally {
    key.fill(0)
  }
}

export const kdf: KDF = {
  pbkdf2: /* @__PURE__ */ Object.assign(pbkdf2, { sync: pbkdf2Sync }),
  hkdf: /* @__PURE__ */ Object.assign(hkdf, { sync: hkdfSync }),
}
