import { fillRandom } from './native/web.js'
import { assertLength, bytesToBigInt, encodeHex, encodeBase64, toBinaryView } from './bytes.js'
import { InvalidInputError, UnsupportedError } from './errors.js'
import type { Binary } from './types.js'

export interface Random {
  (length: number): Uint8Array
  hex(length: number): string
  base64(length: number): string
  uint32(): number
  int(max: number): number
  int(max: bigint): bigint
  fill<T extends Binary>(buffer: T, offset?: number, length?: number): T
  uuid(): string
}

const UINT32_RANGE = 0x100000000

function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  assertLength(length, 'Random byte length')

  const bytes = new Uint8Array(length)
  fillRandom(bytes)
  return bytes
}

function uint32(): number {
  return new DataView(randomBytes(4).buffer).getUint32(0)
}

export function randomBelow(limit: bigint): bigint {
  if (limit <= 0n) {
    throw new InvalidInputError('Random integer limit must be positive')
  }

  if (limit === 1n) {
    return 0n
  }

  const bits = (limit - 1n).toString(2).length
  const length = Math.ceil(bits / 8)
  const mask = 0xff >>> (length * 8 - bits)

  for (let attempt = 0; attempt < 128; attempt++) {
    const data = randomBytes(length)
    data[0] &= mask
    const value = bytesToBigInt(data)

    if (value < limit) {
      return value
    }
  }

  throw new UnsupportedError('Cryptographic random sampling failed')
}

function int(max: number): number
function int(max: bigint): bigint
function int(max: number | bigint): number | bigint {
  if (typeof max === 'bigint') {
    return randomBelow(max)
  }

  if (!Number.isSafeInteger(max) || max <= 0) {
    throw new InvalidInputError('Random integer limit must be a positive safe integer')
  }

  if (max <= UINT32_RANGE) {
    const limit = UINT32_RANGE - (UINT32_RANGE % max)

    for (let attempt = 0; attempt < 128; attempt++) {
      const value = uint32()

      if (value < limit) {
        return value % max
      }
    }
  } else {
    const high = Math.floor((max - 1) / UINT32_RANGE)
    const mask = 2 ** Math.ceil(Math.log2(high + 1)) - 1

    for (let attempt = 0; attempt < 128; attempt++) {
      const value = (uint32() & mask) * UINT32_RANGE + uint32()

      if (value < max) {
        return value
      }
    }
  }

  throw new UnsupportedError('Cryptographic random sampling failed')
}

function fill<T extends Binary>(buffer: T, offset = 0, length?: number): T {
  const view = toBinaryView(buffer)
  const size = (buffer as { BYTES_PER_ELEMENT?: number }).BYTES_PER_ELEMENT ?? 1

  assertLength(offset, 'Random fill offset')

  if (length !== undefined) {
    assertLength(length, 'Random fill length')
  }

  const start = offset * size
  const end = length === undefined ? view.length : start + length * size

  if (start > view.length || end > view.length) {
    throw new InvalidInputError('Random fill range exceeds the buffer')
  }

  fillRandom(view.subarray(start, end))
  return buffer
}

export const random: Random = /* @__PURE__ */ Object.assign(randomBytes, {
  hex(length: number): string {
    return encodeHex(randomBytes(length))
  },

  base64(length: number): string {
    return encodeBase64(randomBytes(length))
  },

  uint32,
  int,
  fill,

  uuid(): string {
    const value = randomBytes(16)
    value[6] = (value[6] & 0x0f) | 0x40
    value[8] = (value[8] & 0x3f) | 0x80

    const hex = encodeHex(value)
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
  },
})
