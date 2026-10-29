import { toBytesView } from './bytes.js'
import type { Checksum, ChecksumState } from './crc32.js'
import type { Data } from './types.js'

const MODULUS = 65521
const CHUNK = 5552

export function adler32Update(data: Uint8Array, previous = 1): number {
  let a = previous & 0xffff
  let b = previous >>> 16

  for (let i = 0; i < data.length;) {
    const end = Math.min(i + CHUNK, data.length)

    for (; i < end; i++) {
      a += data[i]
      b += a
    }

    a %= MODULUS
    b %= MODULUS
  }

  return ((b << 16) | a) >>> 0
}

class State implements ChecksumState {
  private value = 1

  update(data: Data): this {
    this.value = adler32Update(toBytesView(data), this.value)

    return this
  }

  digest(): number {
    return this.value
  }
}

export const adler32: Checksum = /* @__PURE__ */ Object.assign(
  (data: Data): number => adler32Update(toBytesView(data)),
  { create: (): ChecksumState => new State() },
)
