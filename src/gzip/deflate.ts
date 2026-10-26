import { lazy } from '../lazy.js'
import {
  DISTANCE_BASE,
  DISTANCE_EXTRA,
  END_OF_BLOCK,
  LENGTH_BASE,
  LENGTH_EXTRA,
  MAX_MATCH,
  MIN_MATCH,
  WINDOW_SIZE,
} from './tables.js'

const HASH_BITS = 15
const MAX_CHAIN = 64

const lengthCodes = /* @__PURE__ */ lazy(() => {
  const codes = new Uint8Array(MAX_MATCH + 1)

  for (let code = 0; code < LENGTH_BASE.length; code++) {
    const end = code + 1 < LENGTH_BASE.length ? LENGTH_BASE[code + 1] : MAX_MATCH + 1
    codes.fill(code, LENGTH_BASE[code], end)
  }

  codes[MAX_MATCH] = LENGTH_BASE.length - 1

  return codes
})

function distanceCode(distance: number): number {
  let code = 0

  while (code + 1 < DISTANCE_BASE.length && DISTANCE_BASE[code + 1] <= distance) {
    code++
  }

  return code
}

function reverse(code: number, length: number): number {
  let result = 0

  for (let i = 0; i < length; i++) {
    result = (result << 1) | ((code >>> i) & 1)
  }

  return result
}

class BitWriter {
  private buffer: Uint8Array
  private length = 0
  private bits = 0
  private count = 0

  constructor(sizeHint: number) {
    this.buffer = new Uint8Array(Math.max(64, sizeHint))
  }

  write(value: number, count: number): void {
    this.bits |= value << this.count
    this.count += count

    while (this.count >= 8) {
      if (this.length === this.buffer.length) {
        const next = new Uint8Array(this.buffer.length * 2)

        next.set(this.buffer)
        this.buffer = next
      }

      this.buffer[this.length++] = this.bits & 0xff
      this.bits >>>= 8
      this.count -= 8
    }
  }

  code(code: number, length: number): void {
    this.write(reverse(code, length), length)
  }

  finish(): Uint8Array {
    if (this.count) {
      this.write(0, 8 - this.count)
    }

    return this.buffer.slice(0, this.length)
  }
}

function literal(writer: BitWriter, symbol: number): void {
  if (symbol < 144) {
    writer.code(0x30 + symbol, 8)
  } else if (symbol < 256) {
    writer.code(0x190 + symbol - 144, 9)
  } else if (symbol < 280) {
    writer.code(symbol - 256, 7)
  } else {
    writer.code(0xc0 + symbol - 280, 8)
  }
}

function match(writer: BitWriter, length: number, distance: number): void {
  const lengthCode = lengthCodes()[length]
  const code = distanceCode(distance)

  literal(writer, 257 + lengthCode)
  writer.write(length - LENGTH_BASE[lengthCode], LENGTH_EXTRA[lengthCode])
  writer.code(code, 5)
  writer.write(distance - DISTANCE_BASE[code], DISTANCE_EXTRA[code])
}

function hash(data: Uint8Array, position: number): number {
  return ((data[position] << 10) ^ (data[position + 1] << 5) ^ data[position + 2]) & ((1 << HASH_BITS) - 1)
}

export function deflate(data: Uint8Array): Uint8Array {
  const writer = new BitWriter(data.length / 2)
  const head = new Int32Array(1 << HASH_BITS).fill(-1)
  const previous = new Int32Array(WINDOW_SIZE)

  writer.write(1, 1)
  writer.write(1, 2)

  const insert = (position: number): void => {
    const key = hash(data, position)

    previous[position % WINDOW_SIZE] = head[key]
    head[key] = position
  }

  let position = 0

  while (position < data.length) {
    let bestLength = 0
    let bestDistance = 0

    if (position + MIN_MATCH <= data.length) {
      const limit = Math.min(MAX_MATCH, data.length - position)
      let candidate = head[hash(data, position)]

      for (let chain = 0; candidate >= 0 && position - candidate <= WINDOW_SIZE && chain < MAX_CHAIN; chain++) {
        let length = 0

        while (length < limit && data[candidate + length] === data[position + length]) {
          length++
        }

        if (length > bestLength) {
          bestLength = length
          bestDistance = position - candidate

          if (length === limit) {
            break
          }
        }

        candidate = previous[candidate % WINDOW_SIZE]
      }
    }

    if (bestLength >= MIN_MATCH) {
      match(writer, bestLength, bestDistance)

      for (const end = position + bestLength; position < end; position++) {
        if (position + MIN_MATCH <= data.length) {
          insert(position)
        }
      }
    } else {
      literal(writer, data[position])

      if (position + MIN_MATCH <= data.length) {
        insert(position)
      }

      position++
    }
  }

  literal(writer, END_OF_BLOCK)

  return writer.finish()
}
