import { adler32Update } from '../adler32.js'
import { crc32Update } from '../crc32.js'
import { InvalidInputError } from '../errors.js'
import { deflateWasm, inflateWasm } from '../wasm/deflate.js'
import { deflate } from './deflate.js'
import { inflate } from './inflate.js'
import { CORRUPT_DATA, MAX_RATIO } from './tables.js'

export type Format = 'gzip' | 'deflate' | 'zlib'

export interface Container {
  encode(data: Uint8Array): Uint8Array
  decode(data: Uint8Array, limit: number): Uint8Array
}

const FLAG_HCRC = 0x02
const FLAG_EXTRA = 0x04
const FLAG_NAME = 0x08
const FLAG_COMMENT = 0x10
const FLAG_RESERVED = 0xe0
const ZLIB_DICTIONARY = 0x20

function corrupt(): never {
  throw new InvalidInputError(CORRUPT_DATA)
}

function deflateRaw(data: Uint8Array): Uint8Array {
  return deflateWasm(data) ?? deflate(data)
}

function inflateRaw(data: Uint8Array, offset: number, limit: number, hint: number): { output: Uint8Array, end: number } {
  const bounded = Math.min(hint, (data.length - offset) * MAX_RATIO + 1024)

  return inflateWasm(data, offset, limit, bounded) ?? inflate(data, offset, limit, bounded)
}

function readLittle32(data: Uint8Array, offset: number): number {
  if (offset + 4 > data.length) {
    corrupt()
  }

  return (data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24)) >>> 0
}

function readBig32(data: Uint8Array, offset: number): number {
  if (offset + 4 > data.length) {
    corrupt()
  }

  return ((data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]) >>> 0
}

function wrap(header: number[], body: Uint8Array, trailer: number[]): Uint8Array {
  const output = new Uint8Array(header.length + body.length + trailer.length)

  output.set(header)
  output.set(body, header.length)
  output.set(trailer, header.length + body.length)

  return output
}

function skipString(data: Uint8Array, offset: number): number {
  const end = data.indexOf(0, offset)

  if (end < 0) {
    corrupt()
  }

  return end + 1
}

function gzipHeader(data: Uint8Array, offset: number): number {
  if (offset + 10 > data.length || data[offset] !== 0x1f || data[offset + 1] !== 0x8b || data[offset + 2] !== 8) {
    corrupt()
  }

  const flags = data[offset + 3]

  if (flags & FLAG_RESERVED) {
    corrupt()
  }

  offset += 10

  if (flags & FLAG_EXTRA) {
    if (offset + 2 > data.length) {
      corrupt()
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
    corrupt()
  }

  return offset
}

function little32(value: number): number[] {
  return [value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff]
}

function big32(value: number): number[] {
  return little32(value).reverse()
}

const gzip: Container = {
  encode(data) {
    return wrap([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff], deflateRaw(data), [...little32(crc32Update(data)), ...little32(data.length)])
  },

  decode(data, limit) {
    const members: Uint8Array[] = []
    const size = data.length >= 18 ? readLittle32(data, data.length - 4) : 0
    let total = 0
    let offset = 0

    do {
      const start = gzipHeader(data, offset)
      const { output, end } = inflateRaw(data, start, limit - total, size)

      if (readLittle32(data, end) !== crc32Update(output) || readLittle32(data, end + 4) !== output.length >>> 0) {
        corrupt()
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
  },
}

const zlib: Container = {
  encode(data) {
    return wrap([0x78, 0x9c], deflateRaw(data), big32(adler32Update(data)))
  },

  decode(data, limit) {
    if (data.length < 6) {
      corrupt()
    }

    const method = data[0]
    const flags = data[1]

    if ((method & 0x0f) !== 8 || method >> 4 > 7 || ((method << 8) | flags) % 31 !== 0 || flags & ZLIB_DICTIONARY) {
      corrupt()
    }

    const { output, end } = inflateRaw(data, 2, limit, data.length * 4)

    if (end + 4 !== data.length || readBig32(data, end) !== adler32Update(output)) {
      corrupt()
    }

    return output
  },
}

const raw: Container = {
  encode: deflateRaw,

  decode(data, limit) {
    const { output, end } = inflateRaw(data, 0, limit, data.length * 4)

    if (end !== data.length) {
      corrupt()
    }

    return output
  },
}

export const containers: Record<Format, Container> = { gzip, deflate: raw, zlib }
