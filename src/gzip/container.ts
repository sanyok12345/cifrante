import { InvalidInputError } from '../errors.js'
import { crc32 } from './crc32.js'
import { deflate } from './deflate.js'
import { inflate } from './inflate.js'

const FLAG_HCRC = 0x02
const FLAG_EXTRA = 0x04
const FLAG_NAME = 0x08
const FLAG_COMMENT = 0x10
const FLAG_RESERVED = 0xe0

function invalid(): never {
  throw new InvalidInputError('Invalid gzip data')
}

function readUint32(data: Uint8Array, offset: number): number {
  if (offset + 4 > data.length) {
    invalid()
  }

  return (data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24)) >>> 0
}

function writeUint32(data: Uint8Array, offset: number, value: number): void {
  data[offset] = value & 0xff
  data[offset + 1] = (value >>> 8) & 0xff
  data[offset + 2] = (value >>> 16) & 0xff
  data[offset + 3] = (value >>> 24) & 0xff
}

function skipString(data: Uint8Array, offset: number): number {
  const end = data.indexOf(0, offset)

  if (end < 0) {
    invalid()
  }

  return end + 1
}

function header(data: Uint8Array, offset: number): number {
  if (offset + 10 > data.length || data[offset] !== 0x1f || data[offset + 1] !== 0x8b || data[offset + 2] !== 8) {
    invalid()
  }

  const flags = data[offset + 3]

  if (flags & FLAG_RESERVED) {
    invalid()
  }

  offset += 10

  if (flags & FLAG_EXTRA) {
    if (offset + 2 > data.length) {
      invalid()
    }

    offset += 2 + (data[offset] | (data[offset + 1] << 8))
  }

  if (flags & FLAG_NAME) {
    offset = skipString(data, offset)
  }

  if (flags & FLAG_COMMENT) {
    offset = skipString(data, offset)
  }

  if (flags & FLAG_HCRC) {
    offset += 2
  }

  if (offset > data.length) {
    invalid()
  }

  return offset
}

export function compressGzip(data: Uint8Array): Uint8Array {
  const body = deflate(data)
  const output = new Uint8Array(10 + body.length + 8)

  output.set([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff])
  output.set(body, 10)
  writeUint32(output, 10 + body.length, crc32(data))
  writeUint32(output, 14 + body.length, data.length >>> 0)

  return output
}

export function decompressGzip(data: Uint8Array, limit: number): Uint8Array {
  const members: Uint8Array[] = []
  let total = 0
  let offset = 0

  do {
    const { output, end } = inflate(data, header(data, offset), limit - total)

    if (readUint32(data, end) !== crc32(output) || readUint32(data, end + 4) !== output.length >>> 0) {
      invalid()
    }

    members.push(output)
    total += output.length
    offset = end + 8
  } while (offset < data.length)

  if (members.length === 1) {
    return members[0]
  }

  const result = new Uint8Array(total)

  for (let i = 0, position = 0; i < members.length; position += members[i].length, i++) {
    result.set(members[i], position)
  }

  return result
}
