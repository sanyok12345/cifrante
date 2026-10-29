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
const HASH_SIZE = 1 << HASH_BITS
const MAX_CHAIN = 96
const NICE_LENGTH = 160
const BLOCK_SYMBOLS = 16384
const CODE_LENGTH_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]
const RUN_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7]

type Code = { lengths: Uint8Array, codes: Uint16Array }

const codesOf = /* @__PURE__ */ lazy(() => {
  const lengthCodes = new Uint8Array(MAX_MATCH + 1)
  const distanceCodes = new Uint8Array(512)

  for (let code = 0; code < LENGTH_BASE.length; code++) {
    const end = code === LENGTH_BASE.length - 1 ? MAX_MATCH + 1 : LENGTH_BASE[code + 1]
    lengthCodes.fill(code, LENGTH_BASE[code], end)
  }

  lengthCodes[MAX_MATCH] = LENGTH_BASE.length - 1

  for (let code = 0; code < DISTANCE_BASE.length; code++) {
    const end = DISTANCE_BASE[code] + (1 << DISTANCE_EXTRA[code])

    for (let distance = DISTANCE_BASE[code]; distance < end; distance++) {
      distanceCodes[distance <= 256 ? distance - 1 : 256 + ((distance - 1) >> 7)] = code
    }
  }

  return { lengthCodes, distanceCodes }
})

function distanceCode(distanceCodes: Uint8Array, distance: number): number {
  return distanceCodes[distance <= 256 ? distance - 1 : 256 + ((distance - 1) >> 7)]
}

function reverse(code: number, length: number): number {
  let result = 0

  for (let i = 0; i < length; i++) {
    result = (result << 1) | ((code >>> i) & 1)
  }

  return result
}

function treeDepths(frequencies: ArrayLike<number>, count: number, lengths: Uint8Array): void {
  const order: number[] = []

  lengths.fill(0, 0, count)

  for (let i = 0; i < count; i++) {
    if (frequencies[i]) {
      order.push(i)
    }
  }

  if (order.length === 0) {
    return
  }

  if (order.length === 1) {
    lengths[order[0]] = 1
    lengths[order[0] === 0 ? 1 : 0] = 1
    return
  }

  order.sort((a, b) => frequencies[a] - frequencies[b] || a - b)

  const used = order.length
  const weights = new Float64Array(2 * used)
  const parents = new Uint16Array(2 * used)
  const depths = new Uint8Array(2 * used)
  let leaf = 0
  let internal = used
  let created = used

  for (let i = 0; i < used; i++) {
    weights[i] = frequencies[order[i]]
  }

  while (created < 2 * used - 1) {
    const pick = [0, 0]

    for (let k = 0; k < 2; k++) {
      pick[k] = leaf < used && (internal >= created || weights[leaf] <= weights[internal]) ? leaf++ : internal++
    }

    weights[created] = weights[pick[0]] + weights[pick[1]]
    parents[pick[0]] = created
    parents[pick[1]] = created
    created++
  }

  for (let node = created - 2; node >= 0; node--) {
    depths[node] = depths[parents[node]] + 1
  }

  for (let i = 0; i < used; i++) {
    lengths[order[i]] = depths[i]
  }
}

function limitedCode(frequencies: ArrayLike<number>, count: number, limit: number): Code {
  const scaled = Array.from({ length: count }, (_, i) => frequencies[i])
  const lengths = new Uint8Array(count)

  for (;;) {
    treeDepths(scaled, count, lengths)

    if (lengths.every(length => length <= limit)) {
      break
    }

    for (let i = 0; i < count; i++) {
      if (scaled[i]) {
        scaled[i] = (scaled[i] >>> 1) | 1
      }
    }
  }

  return canonical(lengths)
}

function canonical(lengths: Uint8Array): Code {
  const counts = new Uint16Array(16)
  const next = new Uint16Array(16)
  const codes = new Uint16Array(lengths.length)

  for (const length of lengths) {
    counts[length]++
  }

  counts[0] = 0

  for (let length = 1; length < 15; length++) {
    next[length + 1] = (next[length] + counts[length]) << 1
  }

  for (let i = 0; i < lengths.length; i++) {
    codes[i] = lengths[i] ? reverse(next[lengths[i]]++, lengths[i]) : 0
  }

  return { lengths, codes }
}

const fixedCode = /* @__PURE__ */ lazy(() => {
  const lengths = new Uint8Array(288)

  lengths.fill(8, 0, 144)
  lengths.fill(9, 144, 256)
  lengths.fill(7, 256, 280)
  lengths.fill(8, 280, 288)

  return { literal: canonical(lengths), distance: canonical(new Uint8Array(30).fill(5)) }
})

class BitWriter {
  private buffer: Uint8Array
  private bits = 0
  private count = 0
  length = 0

  constructor(capacity: number) {
    this.buffer = new Uint8Array(capacity)
  }

  put(value: number, count: number): void {
    this.bits |= value << this.count
    this.count += count

    while (this.count >= 8) {
      this.buffer[this.length++] = this.bits & 0xff
      this.bits >>>= 8
      this.count -= 8
    }
  }

  align(): void {
    if (this.count > 0) {
      this.put(0, 8 - this.count)
    }
  }

  bytes(data: Uint8Array): void {
    this.buffer.set(data, this.length)
    this.length += data.length
  }

  result(): Uint8Array {
    return this.buffer.slice(0, this.length)
  }
}

function runs(lengths: Uint8Array): [number, number][] {
  const result: [number, number][] = []

  for (let i = 0; i < lengths.length;) {
    const value = lengths[i]
    let run = 1

    while (i + run < lengths.length && lengths[i + run] === value) {
      run++
    }

    i += run

    if (value === 0) {
      while (run >= 11) {
        const n = Math.min(run, 138)
        result.push([18, n - 11])
        run -= n
      }

      if (run >= 3) {
        result.push([17, run - 3])
        run = 0
      }
    } else {
      result.push([value, 0])
      run--

      while (run >= 3) {
        const n = Math.min(run, 6)
        result.push([16, n - 3])
        run -= n
      }
    }

    for (; run > 0; run--) {
      result.push([value, 0])
    }
  }

  return result
}

export function deflateBound(length: number): number {
  return length + 6 * (Math.floor(length / 16384) + 2) + 64
}

export function deflate(input: Uint8Array): Uint8Array {
  const { lengthCodes, distanceCodes } = codesOf()
  const writer = new BitWriter(deflateBound(input.length))
  const head = new Int32Array(HASH_SIZE).fill(-1)
  const previous = new Int32Array(WINDOW_SIZE)
  const values = new Uint16Array(BLOCK_SYMBOLS)
  const distances = new Uint16Array(BLOCK_SYMBOLS)
  const literalFrequencies = new Uint32Array(286)
  const distanceFrequencies = new Uint32Array(30)
  const length = input.length
  let symbols = 0
  let blockStart = 0
  let covered = 0

  function writeSymbols(literal: Code, distance: Code): void {
    for (let i = 0; i < symbols; i++) {
      const value = values[i]
      const span = distances[i]

      if (span === 0) {
        writer.put(literal.codes[value], literal.lengths[value])
        continue
      }

      const code = lengthCodes[value]
      const distanceSymbol = distanceCode(distanceCodes, span)

      writer.put(literal.codes[257 + code], literal.lengths[257 + code])
      writer.put(value - LENGTH_BASE[code], LENGTH_EXTRA[code])
      writer.put(distance.codes[distanceSymbol], distance.lengths[distanceSymbol])
      writer.put(span - DISTANCE_BASE[distanceSymbol], DISTANCE_EXTRA[distanceSymbol])
    }

    writer.put(literal.codes[END_OF_BLOCK], literal.lengths[END_OF_BLOCK])
  }

  function writeStored(final: boolean): void {
    let start = blockStart

    do {
      const size = Math.min(covered - start, 65535)

      writer.put(final && start + size === covered ? 1 : 0, 1)
      writer.put(0, 2)
      writer.align()
      writer.put(size, 16)
      writer.put(size ^ 0xffff, 16)
      writer.bytes(input.subarray(start, start + size))
      start += size
    } while (start < covered)
  }

  function flush(final: boolean): void {
    literalFrequencies[END_OF_BLOCK] = 1

    const usedDistance = distanceFrequencies.some(value => value !== 0)
    const literal = limitedCode(literalFrequencies, 286, 15)
    const distance = usedDistance
      ? limitedCode(distanceFrequencies, 30, 15)
      : canonical(Uint8Array.from({ length: 30 }, (_, i) => (i < 2 ? 1 : 0)))
    let literalCount = 257
    let distanceCount = 1
    let extraBits = 0
    let fixedBits = 3
    let dynamicBits = 17
    const fixed = fixedCode()

    for (let i = 0; i < 286; i++) {
      if (literal.lengths[i]) {
        literalCount = Math.max(literalCount, i + 1)
      }

      if (i >= 257) {
        extraBits += literalFrequencies[i] * LENGTH_EXTRA[i - 257]
      }

      dynamicBits += literalFrequencies[i] * literal.lengths[i]
      fixedBits += literalFrequencies[i] * fixed.literal.lengths[i]
    }

    for (let i = 0; i < 30; i++) {
      if (distance.lengths[i]) {
        distanceCount = Math.max(distanceCount, i + 1)
      }

      extraBits += distanceFrequencies[i] * DISTANCE_EXTRA[i]
      dynamicBits += distanceFrequencies[i] * distance.lengths[i]
      fixedBits += distanceFrequencies[i] * 5
    }

    const combined = new Uint8Array(literalCount + distanceCount)
    combined.set(literal.lengths.subarray(0, literalCount))
    combined.set(distance.lengths.subarray(0, distanceCount), literalCount)

    const encoded = runs(combined)
    const runFrequencies = new Uint32Array(19)

    for (const [symbol] of encoded) {
      runFrequencies[symbol]++
    }

    const lengths = limitedCode(runFrequencies, 19, 7)
    let lengthCount = 4

    for (let i = 0; i < 19; i++) {
      if (lengths.lengths[CODE_LENGTH_ORDER[i]]) {
        lengthCount = Math.max(lengthCount, i + 1)
      }

      dynamicBits += runFrequencies[i] * (lengths.lengths[i] + RUN_EXTRA[i])
    }

    dynamicBits += 3 * lengthCount + extraBits
    fixedBits += extraBits

    const storedBytes = covered - blockStart
    const storedBits = (Math.floor(storedBytes / 65535) + 1) * 42 + 8 * storedBytes

    if (storedBits <= fixedBits && storedBits <= dynamicBits) {
      writeStored(final)
    } else if (fixedBits <= dynamicBits) {
      writer.put(final ? 1 : 0, 1)
      writer.put(1, 2)
      writeSymbols(fixed.literal, fixed.distance)
    } else {
      writer.put(final ? 1 : 0, 1)
      writer.put(2, 2)
      writer.put(literalCount - 257, 5)
      writer.put(distanceCount - 1, 5)
      writer.put(lengthCount - 4, 4)

      for (let i = 0; i < lengthCount; i++) {
        writer.put(lengths.lengths[CODE_LENGTH_ORDER[i]], 3)
      }

      for (const [symbol, extra] of encoded) {
        writer.put(lengths.codes[symbol], lengths.lengths[symbol])
        writer.put(extra, RUN_EXTRA[symbol])
      }

      writeSymbols(literal, distance)
    }

    literalFrequencies.fill(0)
    distanceFrequencies.fill(0)
    symbols = 0
    blockStart = covered
  }

  function literal(value: number): void {
    values[symbols] = value
    distances[symbols++] = 0
    literalFrequencies[value]++
    covered++

    if (symbols === BLOCK_SYMBOLS) {
      flush(false)
    }
  }

  function match(size: number, span: number): void {
    values[symbols] = size
    distances[symbols++] = span
    literalFrequencies[257 + lengthCodes[size]]++
    distanceFrequencies[distanceCode(distanceCodes, span)]++
    covered += size

    if (symbols === BLOCK_SYMBOLS) {
      flush(false)
    }
  }

  function hash(position: number): number {
    const value = input[position] | (input[position + 1] << 8) | (input[position + 2] << 16)
    return Math.imul(value, 0x9e3779b1) >>> (32 - HASH_BITS)
  }

  function insert(position: number, key: number): void {
    previous[position & (WINDOW_SIZE - 1)] = head[key]
    head[key] = position
  }

  let found = 0

  function find(position: number, key: number): number {
    const limit = Math.min(MAX_MATCH, length - position)
    const floor = position - WINDOW_SIZE
    let best = 0
    let candidate = head[key]

    for (let chain = 0; candidate >= 0 && candidate >= floor && chain < MAX_CHAIN; chain++) {
      if (input[candidate + best] === input[position + best] && input[candidate] === input[position] && input[candidate + 1] === input[position + 1]) {
        let size = 2

        while (size < limit && input[candidate + size] === input[position + size]) {
          size++
        }

        if (size > best) {
          best = size
          found = position - candidate

          if (size >= NICE_LENGTH || size === limit) {
            break
          }
        }
      }

      const next = previous[candidate & (WINDOW_SIZE - 1)]

      if (next >= candidate) {
        break
      }

      candidate = next
    }

    return best >= MIN_MATCH ? best : 0
  }

  let position = 0
  let pending = false
  let pendingLength = 0
  let pendingDistance = 0

  while (position < length) {
    let current = 0
    let distance = 0

    if (position + MIN_MATCH <= length) {
      const key = hash(position)

      if (!(pending && pendingLength >= NICE_LENGTH)) {
        current = find(position, key)
        distance = found
      }

      insert(position, key)
    }

    if (pending && pendingLength >= MIN_MATCH && current <= pendingLength) {
      const end = position - 1 + pendingLength

      match(pendingLength, pendingDistance)

      for (position++; position < end; position++) {
        if (position + MIN_MATCH <= length) {
          insert(position, hash(position))
        }
      }

      pending = false
      continue
    }

    if (pending) {
      literal(input[position - 1])
    }

    pending = true
    pendingLength = current
    pendingDistance = distance
    position++
  }

  if (pending) {
    if (pendingLength >= MIN_MATCH) {
      match(pendingLength, pendingDistance)
    } else {
      literal(input[position - 1])
    }
  }

  flush(true)
  writer.align()

  return writer.result()
}
