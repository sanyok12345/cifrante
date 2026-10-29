import { toBytesView } from './bytes.js'
import { lazy } from './lazy.js'
import { nativeCrc32 } from './native/web.js'
import type { Data } from './types.js'

export interface ChecksumState {
  update(data: Data): this
  digest(): number
}

export interface Checksum {
  (data: Data): number
  create(): ChecksumState
}

const tables = /* @__PURE__ */ lazy(() => {
  const table = new Int32Array(2048)

  for (let n = 0; n < 256; n++) {
    let c = n

    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    }

    table[n] = c
  }

  for (let n = 0; n < 256; n++) {
    for (let k = 256; k < 2048; k += 256) {
      const previous = table[k - 256 + n]
      table[k + n] = (previous >>> 8) ^ table[previous & 0xff]
    }
  }

  return table
})

function compute(data: Uint8Array, previous: number): number {
  const t = tables()
  const length = data.length
  let crc = ~previous
  let i = 0

  for (; i + 8 <= length; i += 8) {
    const a = crc ^ (data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24))

    crc = t[1792 + (a & 0xff)] ^ t[1536 + ((a >>> 8) & 0xff)] ^ t[1280 + ((a >>> 16) & 0xff)] ^ t[1024 + (a >>> 24)]
      ^ t[768 + data[i + 4]] ^ t[512 + data[i + 5]] ^ t[256 + data[i + 6]] ^ t[data[i + 7]]
  }

  for (; i < length; i++) {
    crc = t[(crc ^ data[i]) & 0xff] ^ (crc >>> 8)
  }

  return ~crc >>> 0
}

export function crc32Update(data: Uint8Array, previous = 0): number {
  return nativeCrc32(data, previous) ?? compute(data, previous)
}

class State implements ChecksumState {
  private value = 0

  update(data: Data): this {
    this.value = crc32Update(toBytesView(data), this.value)

    return this
  }

  digest(): number {
    return this.value
  }
}

export const crc32: Checksum = /* @__PURE__ */ Object.assign(
  (data: Data): number => crc32Update(toBytesView(data)),
  { create: (): ChecksumState => new State() },
)
