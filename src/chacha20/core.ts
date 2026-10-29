const SIGMA = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

export interface Session {
  update(input: Uint8Array, output: Uint8Array): void
  seal(): Uint8Array
  open(tag: Uint8Array): boolean
}

function load32(bytes: Uint8Array, offset: number): number {
  return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0
}

function store32(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = value & 0xff
  bytes[offset + 1] = (value >>> 8) & 0xff
  bytes[offset + 2] = (value >>> 16) & 0xff
  bytes[offset + 3] = (value >>> 24) & 0xff
}

function rounds(x: Uint32Array): void {
  const quarter = (a: number, b: number, c: number, d: number): void => {
    x[a] += x[b]
    x[d] = ((x[d] ^ x[a]) << 16) | ((x[d] ^ x[a]) >>> 16)
    x[c] += x[d]
    x[b] = ((x[b] ^ x[c]) << 12) | ((x[b] ^ x[c]) >>> 20)
    x[a] += x[b]
    x[d] = ((x[d] ^ x[a]) << 8) | ((x[d] ^ x[a]) >>> 24)
    x[c] += x[d]
    x[b] = ((x[b] ^ x[c]) << 7) | ((x[b] ^ x[c]) >>> 25)
  }

  for (let i = 0; i < 10; i++) {
    quarter(0, 4, 8, 12)
    quarter(1, 5, 9, 13)
    quarter(2, 6, 10, 14)
    quarter(3, 7, 11, 15)
    quarter(0, 5, 10, 15)
    quarter(1, 6, 11, 12)
    quarter(2, 7, 8, 13)
    quarter(3, 4, 9, 14)
  }
}

function setup(key: Uint8Array, counter: number, nonce: Uint8Array): Uint32Array {
  const input = new Uint32Array(16)

  input.set(SIGMA)

  for (let i = 0; i < 8; i++) {
    input[4 + i] = load32(key, 4 * i)
  }

  input[12] = counter
  input[13] = load32(nonce, 0)
  input[14] = load32(nonce, 4)
  input[15] = load32(nonce, 8)

  return input
}

function block(input: Uint32Array, output: Uint8Array, x: Uint32Array): void {
  x.set(input)
  rounds(x)

  for (let i = 0; i < 16; i++) {
    store32(output, 4 * i, (x[i] + input[i]) >>> 0)
  }
}

export function hchacha20(key: Uint8Array, nonce: Uint8Array): Uint8Array<ArrayBuffer> {
  const x = setup(key, load32(nonce, 0), nonce.subarray(4))
  const output = new Uint8Array(32)

  rounds(x)

  for (let i = 0; i < 4; i++) {
    store32(output, 4 * i, x[i])
    store32(output, 16 + 4 * i, x[12 + i])
  }

  x.fill(0)
  return output
}

class Poly1305 {
  private readonly r = new Float64Array(10)
  private readonly h = new Float64Array(10)
  private readonly pad = new Uint8Array(16)
  private readonly pending = new Uint8Array(16)
  private readonly product = new Float64Array(10)
  private pendingLength = 0

  constructor(key: Uint8Array) {
    const clamped = key.slice(0, 16)

    clamped[3] &= 15
    clamped[7] &= 15
    clamped[11] &= 15
    clamped[15] &= 15
    clamped[4] &= 252
    clamped[8] &= 252
    clamped[12] &= 252

    for (let i = 0; i < 10; i++) {
      this.r[i] = this.bits(clamped, 13 * i, 13)
    }

    this.pad.set(key.subarray(16, 32))
    clamped.fill(0)
  }

  private bits(bytes: Uint8Array, start: number, count: number): number {
    let value = 0

    for (let i = 0; i < count; i++) {
      const bit = start + i
      const byte = bit >> 3

      if (byte < bytes.length) {
        value += ((bytes[byte] >> (bit & 7)) & 1) * 2 ** i
      }
    }

    return value
  }

  private blocks(data: Uint8Array, offset: number, length: number): void {
    const { r, h, product: d } = this

    for (let position = offset; position + 16 <= offset + length; position += 16) {
      const m = data.subarray(position, position + 16)

      for (let i = 0; i < 10; i++) {
        h[i] += this.bits(m, 13 * i, 13)
      }

      h[9] += 2 ** 11

      for (let i = 0; i < 10; i++) {
        let sum = 0

        for (let j = 0; j < 10; j++) {
          sum += h[j] * (j <= i ? r[i - j] : 5 * r[i + 10 - j])
        }

        d[i] = sum
      }

      let carry = 0

      for (let i = 0; i < 10; i++) {
        d[i] += carry
        carry = Math.floor(d[i] / 8192)
        h[i] = d[i] - carry * 8192
      }

      h[0] += carry * 5
      carry = Math.floor(h[0] / 8192)
      h[0] -= carry * 8192
      h[1] += carry
    }
  }

  update(data: Uint8Array): void {
    let offset = 0

    if (this.pendingLength > 0) {
      while (offset < data.length && this.pendingLength < 16) {
        this.pending[this.pendingLength++] = data[offset++]
      }

      if (this.pendingLength < 16) {
        return
      }

      this.blocks(this.pending, 0, 16)
      this.pendingLength = 0
    }

    const whole = (data.length - offset) & ~15

    this.blocks(data, offset, whole)

    for (let i = offset + whole; i < data.length; i++) {
      this.pending[this.pendingLength++] = data[i]
    }
  }

  align(): void {
    if (this.pendingLength > 0) {
      this.pending.fill(0, this.pendingLength)
      this.blocks(this.pending, 0, 16)
      this.pendingLength = 0
    }
  }

  finish(): Uint8Array {
    const h = this.h
    const g = new Float64Array(10)
    let carry = 0

    for (let pass = 0; pass < 2; pass++) {
      for (let i = 0; i < 10; i++) {
        h[i] += carry
        carry = Math.floor(h[i] / 8192)
        h[i] -= carry * 8192
      }

      h[0] += carry * 5
      carry = 0
    }

    carry = 5

    for (let i = 0; i < 10; i++) {
      g[i] = h[i] + carry
      carry = Math.floor(g[i] / 8192)
      g[i] -= carry * 8192
    }

    const select = new Float64Array(10)

    for (let i = 0; i < 10; i++) {
      select[i] = h[i] + (g[i] - h[i]) * carry
    }

    const tag = new Uint8Array(16)
    let accumulator = 0
    let bitsHeld = 0
    let position = 0
    let padCarry = 0

    for (let i = 0; i < 10 && position < 16; i++) {
      accumulator += select[i] * 2 ** bitsHeld
      bitsHeld += 13

      while (bitsHeld >= 8 && position < 16) {
        const byte = accumulator % 256
        const sum = byte + this.pad[position] + padCarry
        tag[position++] = sum & 0xff
        padCarry = sum >> 8
        accumulator = (accumulator - byte) / 256
        bitsHeld -= 8
      }
    }

    h.fill(0)
    g.fill(0)
    select.fill(0)
    this.r.fill(0)
    this.pad.fill(0)
    this.product.fill(0)

    return tag
  }
}

export function chacha20Poly1305Js(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, decrypting: boolean): Session {
  const input = setup(key, 0, nonce)
  const keystream = new Uint8Array(64)
  const x = new Uint32Array(16)

  block(input, keystream, x)
  input[12] = 1

  const poly = new Poly1305(keystream)
  let length = 0

  poly.update(aad)
  poly.align()

  function finish(): Uint8Array {
    const lengths = new Uint8Array(16)

    store32(lengths, 0, aad.length >>> 0)
    store32(lengths, 4, Math.floor(aad.length / 2 ** 32))
    store32(lengths, 8, length >>> 0)
    store32(lengths, 12, Math.floor(length / 2 ** 32))
    poly.align()
    poly.update(lengths)

    const tag = poly.finish()

    input.fill(0)
    keystream.fill(0)
    x.fill(0)

    return tag
  }

  return {
    update(source, target) {
      if (decrypting) {
        poly.update(source)
      }

      for (let offset = 0; offset < source.length; offset += 64) {
        block(input, keystream, x)
        input[12]++

        const count = Math.min(64, source.length - offset)

        for (let i = 0; i < count; i++) {
          target[offset + i] = source[offset + i] ^ keystream[i]
        }
      }

      if (!decrypting) {
        poly.update(target.subarray(0, source.length))
      }

      length += source.length
    },

    seal: finish,

    open(tag) {
      const expected = finish()
      let difference = expected.length ^ tag.length

      for (let i = 0; i < expected.length; i++) {
        difference |= expected[i] ^ tag[i]
      }

      return difference === 0
    },
  }
}
