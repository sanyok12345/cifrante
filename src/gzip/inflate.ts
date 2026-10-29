import { InvalidInputError } from '../errors.js'
import { lazy } from '../lazy.js'
import {
  DISTANCE_BASE,
  DISTANCE_EXTRA,
  END_OF_BLOCK,
  LENGTH_BASE,
  LENGTH_EXTRA,
  fixedDistanceLengths,
  fixedLiteralLengths,
} from './tables.js'

const CODE_LENGTH_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]

type Huffman = { counts: Uint16Array, symbols: Uint16Array }

function invalid(): never {
  throw new InvalidInputError('Invalid gzip data')
}

function huffman(lengths: Uint8Array): Huffman {
  const counts = new Uint16Array(16)
  const offsets = new Uint16Array(16)
  const symbols = new Uint16Array(lengths.length)

  for (const length of lengths) {
    counts[length]++
  }

  counts[0] = 0

  for (let length = 1, left = 1; length < 16; length++) {
    left = left * 2 - counts[length]

    if (left < 0) {
      invalid()
    }
  }

  for (let length = 1; length < 15; length++) {
    offsets[length + 1] = offsets[length] + counts[length]
  }

  for (let symbol = 0; symbol < lengths.length; symbol++) {
    if (lengths[symbol]) {
      symbols[offsets[lengths[symbol]]++] = symbol
    }
  }

  return { counts, symbols }
}

const fixed = /* @__PURE__ */ lazy(() => ({
  literals: huffman(fixedLiteralLengths()),
  distances: huffman(fixedDistanceLengths()),
}))

class BitReader {
  private buffer = 0
  private count = 0

  constructor(private readonly data: Uint8Array, public offset: number) {}

  bits(count: number): number {
    while (this.count < count) {
      if (this.offset >= this.data.length) {
        invalid()
      }

      this.buffer |= this.data[this.offset++] << this.count
      this.count += 8
    }

    const value = this.buffer & ((1 << count) - 1)

    this.buffer >>>= count
    this.count -= count

    return value
  }

  symbol({ counts, symbols }: Huffman): number {
    let code = 0
    let first = 0
    let index = 0

    for (let length = 1; length < 16; length++) {
      code |= this.bits(1)

      const count = counts[length]

      if (code - first < count) {
        return symbols[index + code - first]
      }

      index += count
      first = (first + count) * 2
      code *= 2
    }

    return invalid()
  }

  align(): void {
    this.buffer = 0
    this.count = 0
  }

  bytes(length: number): Uint8Array {
    if (this.offset + length > this.data.length) {
      invalid()
    }

    this.offset += length

    return this.data.subarray(this.offset - length, this.offset)
  }
}

class Output {
  private buffer: Uint8Array
  length = 0

  constructor(private readonly limit: number, sizeHint: number) {
    this.buffer = new Uint8Array(Math.max(256, Math.min(sizeHint, limit)))
  }

  private reserve(count: number): void {
    const required = this.length + count

    if (required > this.limit) {
      throw new InvalidInputError('Decompressed data exceeds maxLength')
    }

    if (required > this.buffer.length) {
      const next = new Uint8Array(Math.min(Math.max(required, this.buffer.length * 2), this.limit))

      next.set(this.buffer.subarray(0, this.length))
      this.buffer = next
    }
  }

  byte(value: number): void {
    this.reserve(1)
    this.buffer[this.length++] = value
  }

  bytes(data: Uint8Array): void {
    this.reserve(data.length)
    this.buffer.set(data, this.length)
    this.length += data.length
  }

  copy(distance: number, length: number): void {
    if (distance > this.length) {
      invalid()
    }

    this.reserve(length)

    for (let i = 0; i < length; i++, this.length++) {
      this.buffer[this.length] = this.buffer[this.length - distance]
    }
  }

  result(): Uint8Array {
    return this.buffer.slice(0, this.length)
  }
}

function stored(reader: BitReader, output: Output): void {
  reader.align()

  const header = reader.bytes(4)
  const length = header[0] | (header[1] << 8)
  const complement = header[2] | (header[3] << 8)

  if ((length ^ 0xffff) !== complement) {
    invalid()
  }

  output.bytes(reader.bytes(length))
}

function dynamic(reader: BitReader): { literals: Huffman, distances: Huffman } {
  const literalCount = reader.bits(5) + 257
  const distanceCount = reader.bits(5) + 1
  const codeCount = reader.bits(4) + 4

  if (literalCount > 286 || distanceCount > 30) {
    invalid()
  }

  const codeLengths = new Uint8Array(19)

  for (let i = 0; i < codeCount; i++) {
    codeLengths[CODE_LENGTH_ORDER[i]] = reader.bits(3)
  }

  const codes = huffman(codeLengths)
  const lengths = new Uint8Array(literalCount + distanceCount)

  for (let i = 0; i < lengths.length;) {
    const symbol = reader.symbol(codes)

    if (symbol < 16) {
      lengths[i++] = symbol
      continue
    }

    let value = 0
    let repeat: number

    if (symbol === 16) {
      if (i === 0) {
        invalid()
      }

      value = lengths[i - 1]
      repeat = 3 + reader.bits(2)
    } else if (symbol === 17) {
      repeat = 3 + reader.bits(3)
    } else {
      repeat = 11 + reader.bits(7)
    }

    if (i + repeat > lengths.length) {
      invalid()
    }

    lengths.fill(value, i, i + repeat)
    i += repeat
  }

  if (!lengths[END_OF_BLOCK]) {
    invalid()
  }

  return {
    literals: huffman(lengths.subarray(0, literalCount)),
    distances: huffman(lengths.subarray(literalCount)),
  }
}

function compressed(reader: BitReader, output: Output, literals: Huffman, distances: Huffman): void {
  for (;;) {
    const symbol = reader.symbol(literals)

    if (symbol < 256) {
      output.byte(symbol)
      continue
    }

    if (symbol === END_OF_BLOCK) {
      return
    }

    const lengthCode = symbol - 257

    if (lengthCode >= 29) {
      invalid()
    }

    const length = LENGTH_BASE[lengthCode] + reader.bits(LENGTH_EXTRA[lengthCode])
    const distanceCode = reader.symbol(distances)

    if (distanceCode >= 30) {
      invalid()
    }

    output.copy(DISTANCE_BASE[distanceCode] + reader.bits(DISTANCE_EXTRA[distanceCode]), length)
  }
}

export function inflate(
  data: Uint8Array,
  offset: number,
  limit: number,
  hint: number,
): { output: Uint8Array, end: number } {
  const reader = new BitReader(data, offset)
  const output = new Output(limit, hint || (data.length - offset) * 4)
  let final = 0

  while (!final) {
    final = reader.bits(1)

    switch (reader.bits(2)) {
      case 0:
        stored(reader, output)
        break

      case 1: {
        const { literals, distances } = fixed()
        compressed(reader, output, literals, distances)
        break
      }

      case 2: {
        const { literals, distances } = dynamic(reader)
        compressed(reader, output, literals, distances)
        break
      }

      default:
        invalid()
    }
  }

  return { output: output.result(), end: reader.offset }
}
