import type { Binary, Data } from './types.js'
import { InvalidInputError } from './errors.js'
import { nativeEqual } from './platform/web.js'

export interface Codec {
  encode(data: Binary): string
  decode(data: string): Uint8Array
}

export interface Utf8Codec {
  encode(data: string): Uint8Array
  decode(data: Binary): string
}

export interface BytesAPI {
  concat(...values: Binary[]): Uint8Array
  xor(a: Binary, b: Binary): Uint8Array
  equal(a: Binary, b: Binary): boolean
  slice(data: Binary, start?: number, end?: number): Uint8Array
  hex: Codec
  base64: Codec
  utf8: Utf8Codec
}

export function assertLength(value: number, name = 'Length'): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new InvalidInputError(`${name} must be a non-negative safe integer`)
  }
}

const arrayBufferLength = Object.getOwnPropertyDescriptor(
  ArrayBuffer.prototype,
  'byteLength',
)!.get!

export function toBinary(data: Binary): Uint8Array<ArrayBuffer> {
  try {
    if (ArrayBuffer.isView(data)) {
      return new Uint8Array(new Uint8Array(data.buffer, data.byteOffset, data.byteLength))
    }

    arrayBufferLength.call(data)
    return new Uint8Array(new Uint8Array(data as ArrayBuffer))
  } catch {
    throw new InvalidInputError('Expected an ArrayBuffer or an ArrayBuffer view')
  }
}

export function toBytes(data: Data): Uint8Array<ArrayBuffer> {
  return typeof data === 'string' ? encodeUtf8(data) : toBinary(data)
}

export function bytesToBigInt(data: Uint8Array): bigint {
  let value = 0n

  for (const byte of data) {
    value = (value << 8n) | BigInt(byte)
  }

  return value
}

export function bigIntToBytes(
  value: bigint,
  length = Math.ceil(value.toString(16).length / 2),
): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(length)

  for (let i = length - 1; i >= 0; i--) {
    result[i] = Number(value & 0xffn)
    value >>= 8n
  }

  return result
}

export function encodeHex(data: Binary): string {
  let result = ''

  for (const byte of toBinary(data)) {
    result += byte.toString(16).padStart(2, '0')
  }

  return result
}

function decodeHex(data: string): Uint8Array<ArrayBuffer> {
  if (typeof data !== 'string' || data.length % 2 !== 0 || /[^0-9a-f]/i.test(data)) {
    throw new InvalidInputError('Expected an even number of hexadecimal characters')
  }

  const result = new Uint8Array(data.length / 2)

  for (let i = 0; i < result.length; i++) {
    result[i] = Number.parseInt(data.slice(i * 2, i * 2 + 2), 16)
  }

  return result
}

const BASE64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

export function encodeBase64(data: Binary): string {
  const value = toBinary(data)
  let result = ''

  for (let i = 0; i < value.length; i += 3) {
    const a = value[i]
    const b = value[i + 1] ?? 0
    const c = value[i + 2] ?? 0

    result += BASE64[a >>> 2]
    result += BASE64[((a & 3) << 4) | (b >>> 4)]
    result += i + 1 < value.length ? BASE64[((b & 15) << 2) | (c >>> 6)] : '='
    result += i + 2 < value.length ? BASE64[c & 63] : '='
  }

  return result
}

function decodeBase64(data: string): Uint8Array<ArrayBuffer> {
  if (typeof data !== 'string' || data.length % 4 !== 0) {
    throw new InvalidInputError('Expected standard Base64 with canonical padding')
  }

  const padding = data.endsWith('==') ? 2 : data.endsWith('=') ? 1 : 0

  if (/[^A-Za-z0-9+/]/.test(data.slice(0, data.length - padding))) {
    throw new InvalidInputError('Expected standard Base64 with canonical padding')
  }
  if (
    (padding === 2 && (BASE64.indexOf(data[data.length - 3]) & 15) !== 0) ||
    (padding === 1 && (BASE64.indexOf(data[data.length - 2]) & 3) !== 0)
  ) {
    throw new InvalidInputError('Base64 has non-zero padding bits')
  }

  const result = new Uint8Array(data.length / 4 * 3 - padding)
  let offset = 0

  for (let i = 0; i < data.length; i += 4) {
    const a = BASE64.indexOf(data[i])
    const b = BASE64.indexOf(data[i + 1])
    const c = Math.max(0, BASE64.indexOf(data[i + 2]))
    const d = Math.max(0, BASE64.indexOf(data[i + 3]))

    result[offset++] = (a << 2) | (b >>> 4)

    if (offset < result.length) {
      result[offset++] = (b << 4) | (c >>> 2)
    }

    if (offset < result.length) {
      result[offset++] = (c << 6) | d
    }
  }

  return result
}

function encodeUtf8(data: string): Uint8Array<ArrayBuffer> {
  if (typeof data !== 'string') {
    throw new InvalidInputError('Expected a string')
  }

  if (typeof TextEncoder === 'function') {
    return new TextEncoder().encode(data)
  }

  const result: number[] = []

  for (const character of data) {
    let point = character.codePointAt(0)!

    if (point >= 0xd800 && point <= 0xdfff) {
      point = 0xfffd
    }

    if (point < 0x80) {
      result.push(point)
    } else if (point < 0x800) {
      result.push(0xc0 | (point >>> 6), 0x80 | (point & 63))
    } else if (point < 0x10000) {
      result.push(
        0xe0 | (point >>> 12),
        0x80 | ((point >>> 6) & 63),
        0x80 | (point & 63),
      )
    } else {
      result.push(
        0xf0 | (point >>> 18),
        0x80 | ((point >>> 12) & 63),
        0x80 | ((point >>> 6) & 63),
        0x80 | (point & 63),
      )
    }
  }

  return Uint8Array.from(result)
}

function decodeUtf8(data: Binary): string {
  const value = toBinary(data)

  if (typeof TextDecoder === 'function') {
    return new TextDecoder('utf-8', { ignoreBOM: true }).decode(value)
  }

  let result = ''
  let i = 0

  while (i < value.length) {
    const first = value[i++]

    if (first < 0x80) {
      result += String.fromCharCode(first)
      continue
    }

    const count = first >= 0xc2 && first <= 0xdf
      ? 1
      : first >= 0xe0 && first <= 0xef
        ? 2
        : first >= 0xf0 && first <= 0xf4
          ? 3
          : 0

    if (!count) {
      result += '\ufffd'
      continue
    }

    let point = first & (0x7f >>> count)
    let valid = true

    for (let j = 0; j < count; j++) {
      const next = value[i]
      const lower = j === 0 && first === 0xe0 ? 0xa0 : j === 0 && first === 0xf0 ? 0x90 : 0x80
      const upper = j === 0 && first === 0xed ? 0x9f : j === 0 && first === 0xf4 ? 0x8f : 0xbf

      if (i === value.length || next < lower || next > upper) {
        valid = false
        break
      }

      point = (point << 6) | (next & 63)
      i++
    }

    result += valid ? String.fromCodePoint(point) : '\ufffd'
  }

  return result
}

export function equalBinary(a: Binary, b: Binary): boolean {
  const left = toBinary(a)
  const right = toBinary(b)

  if (left.length !== right.length) {
    return false
  }

  const native = nativeEqual(left, right)

  if (native !== undefined) {
    return native
  }

  let difference = 0

  for (let i = 0; i < left.length; i++) {
    difference |= left[i] ^ right[i]
  }

  return difference === 0
}

export const bytes: BytesAPI = {
  concat(...values) {
    const parts = values.map(toBinary)
    const length = parts.reduce((sum, part) => sum + part.length, 0)
    assertLength(length)

    const result = new Uint8Array(length)
    let offset = 0

    for (const part of parts) {
      result.set(part, offset)
      offset += part.length
    }

    return result
  },

  xor(a, b) {
    const left = toBinary(a)
    const right = toBinary(b)

    if (left.length !== right.length) {
      throw new InvalidInputError('XOR inputs must have equal lengths')
    }

    for (let i = 0; i < left.length; i++) {
      left[i] ^= right[i]
    }

    return left
  },

  equal: equalBinary,

  slice(data, start, end) {
    if (
      (start !== undefined && typeof start !== 'number') ||
      (end !== undefined && typeof end !== 'number')
    ) {
      throw new InvalidInputError('Slice bounds must be numbers')
    }

    return toBinary(data).slice(start, end)
  },

  hex: { encode: encodeHex, decode: decodeHex },
  base64: { encode: encodeBase64, decode: decodeBase64 },
  utf8: { encode: encodeUtf8, decode: decodeUtf8 },
}
