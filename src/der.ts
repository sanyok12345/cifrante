import { bytesToBigInt } from './bytes.js'
import { InvalidInputError } from './errors.js'

export const TAG = {
  integer: 0x02,
  bitString: 0x03,
  octetString: 0x04,
  oid: 0x06,
  sequence: 0x30,
} as const

function malformed(): never {
  throw new InvalidInputError('Malformed DER encoding')
}

export class DerReader {
  private offset = 0

  constructor(private readonly data: Uint8Array) {}

  read(tag: number): Uint8Array {
    const { data } = this

    if (this.offset + 2 > data.length || data[this.offset++] !== tag) {
      malformed()
    }

    let length = data[this.offset++]

    if (length & 0x80) {
      const count = length & 0x7f

      if (count === 0 || count > 4 || this.offset + count > data.length) {
        malformed()
      }

      length = 0

      for (let i = 0; i < count; i++) {
        length = length * 256 + data[this.offset++]
      }

      if (length < 0x80) {
        malformed()
      }
    }

    if (this.offset + length > data.length) {
      malformed()
    }

    this.offset += length

    return data.subarray(this.offset - length, this.offset)
  }

  sequence(): DerReader {
    return new DerReader(this.read(TAG.sequence))
  }

  integer(): bigint {
    const value = this.read(TAG.integer)

    if (!value.length || value[0] & 0x80) {
      throw new InvalidInputError('Expected a non-negative DER integer')
    }

    return bytesToBigInt(value)
  }

  oid(): string {
    const value = this.read(TAG.oid)
    const parts: number[] = []
    let part = 0

    for (const byte of value) {
      part = part * 128 + (byte & 0x7f)

      if (!(byte & 0x80)) {
        parts.push(part)
        part = 0
      }
    }

    if (!parts.length || value[value.length - 1] & 0x80) {
      malformed()
    }

    const first = Math.min(Math.floor(parts[0] / 40), 2)

    return [first, parts[0] - first * 40, ...parts.slice(1)].join('.')
  }

  bitString(): Uint8Array {
    const value = this.read(TAG.bitString)

    if (value[0] !== 0) {
      throw new InvalidInputError('Expected a byte-aligned DER bit string')
    }

    return value.subarray(1)
  }

  end(): void {
    if (this.offset !== this.data.length) {
      malformed()
    }
  }
}

function element(tag: number, content: Uint8Array): Uint8Array {
  const header = [tag]

  if (content.length < 0x80) {
    header.push(content.length)
  } else {
    const length: number[] = []

    for (let value = content.length; value > 0; value = Math.floor(value / 256)) {
      length.unshift(value & 0xff)
    }

    header.push(0x80 | length.length, ...length)
  }

  const output = new Uint8Array(header.length + content.length)

  output.set(header)
  output.set(content, header.length)

  return output
}

export function derSequence(...children: Uint8Array[]): Uint8Array {
  const content = new Uint8Array(children.reduce((sum, child) => sum + child.length, 0))
  let offset = 0

  for (const child of children) {
    content.set(child, offset)
    offset += child.length
  }

  return element(TAG.sequence, content)
}

export function derInteger(value: bigint): Uint8Array {
  let hex = value.toString(16)

  if (hex.length % 2) {
    hex = `0${hex}`
  }

  if (parseInt(hex.slice(0, 2), 16) & 0x80) {
    hex = `00${hex}`
  }

  return element(TAG.integer, Uint8Array.from(hex.match(/../g)!, byte => parseInt(byte, 16)))
}

export function derOid(dotted: string): Uint8Array {
  const [first, second, ...rest] = dotted.split('.').map(Number)
  const bytes: number[] = []

  for (const part of [first * 40 + second, ...rest]) {
    const chunk = [part & 0x7f]

    for (let value = part >>> 7; value > 0; value >>>= 7) {
      chunk.unshift(0x80 | (value & 0x7f))
    }

    bytes.push(...chunk)
  }

  return element(TAG.oid, Uint8Array.from(bytes))
}

export function derNull(): Uint8Array {
  return Uint8Array.of(0x05, 0x00)
}

export function derBitString(data: Uint8Array): Uint8Array {
  const content = new Uint8Array(data.length + 1)

  content.set(data, 1)

  return element(TAG.bitString, content)
}

export function derOctetString(data: Uint8Array): Uint8Array {
  return element(TAG.octetString, data)
}
