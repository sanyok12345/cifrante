export type Field = Float64Array

export function field(value = 0): Field {
  const result = new Float64Array(16)
  result[0] = value
  return result
}

export function carry(o: Field): void {
  let c = 1

  for (let i = 0; i < 16; i++) {
    const v = o[i] + c + 65535
    c = Math.floor(v / 65536)
    o[i] = v - c * 65536
  }

  o[0] += c - 1 + 37 * (c - 1)
}

export function select(p: Field, q: Field, bit: number): void {
  const mask = ~(bit - 1)

  for (let i = 0; i < 16; i++) {
    const t = mask & (p[i] ^ q[i])
    p[i] ^= t
    q[i] ^= t
  }
}

export function pack(output: Uint8Array, n: Field): void {
  const m = field()
  const t = Float64Array.from(n)

  carry(t)
  carry(t)
  carry(t)

  for (let j = 0; j < 2; j++) {
    m[0] = t[0] - 0xffed

    for (let i = 1; i < 15; i++) {
      m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1)
      m[i - 1] &= 0xffff
    }

    m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1)
    const borrow = (m[15] >> 16) & 1
    m[14] &= 0xffff
    select(t, m, 1 - borrow)
  }

  for (let i = 0; i < 16; i++) {
    output[2 * i] = t[i] & 0xff
    output[2 * i + 1] = t[i] >> 8
  }
}

export function unpack(output: Field, n: Uint8Array): void {
  for (let i = 0; i < 16; i++) {
    output[i] = n[2 * i] + (n[2 * i + 1] << 8)
  }

  output[15] &= 0x7fff
}

export function add(o: Field, a: Field, b: Field): void {
  for (let i = 0; i < 16; i++) {
    o[i] = a[i] + b[i]
  }
}

export function subtract(o: Field, a: Field, b: Field): void {
  for (let i = 0; i < 16; i++) {
    o[i] = a[i] - b[i]
  }
}

const product = /* @__PURE__ */ new Float64Array(31)

export function multiply(o: Field, a: Field, b: Field): void {
  const t = product

  t.fill(0)

  for (let i = 0; i < 16; i++) {
    for (let j = 0; j < 16; j++) {
      t[i + j] += a[i] * b[j]
    }
  }

  for (let i = 0; i < 15; i++) {
    t[i] += 38 * t[i + 16]
  }

  for (let i = 0; i < 16; i++) {
    o[i] = t[i]
  }

  carry(o)
  carry(o)
}

export function invert(o: Field, input: Field): void {
  const c = Float64Array.from(input)

  for (let a = 253; a >= 0; a--) {
    multiply(c, c, c)

    if (a !== 2 && a !== 4) {
      multiply(c, c, input)
    }
  }

  o.set(c)
}

export function square(o: Field, a: Field): void {
  multiply(o, a, a)
}

export function pow22523(o: Field, input: Field): void {
  const c = Float64Array.from(input)

  for (let a = 250; a >= 0; a--) {
    multiply(c, c, c)

    if (a !== 1) {
      multiply(c, c, input)
    }
  }

  o.set(c)
  c.fill(0)
}

export function negate(o: Field, a: Field): void {
  for (let i = 0; i < 16; i++) {
    o[i] = -a[i]
  }
}

export function move(f: Field, g: Field, bit: number): void {
  const mask = ~(bit - 1)

  for (let i = 0; i < 16; i++) {
    f[i] ^= mask & (f[i] ^ g[i])
  }
}

export function isNegative(f: Field): number {
  const bytes = new Uint8Array(32)

  pack(bytes, f)

  const result = bytes[0] & 1

  bytes.fill(0)
  return result
}

export function isZero(f: Field): boolean {
  const bytes = new Uint8Array(32)
  let difference = 0

  pack(bytes, f)

  for (const byte of bytes) {
    difference |= byte
  }

  return difference === 0
}

export function equal(f: Field, g: Field): boolean {
  const difference = field()

  subtract(difference, f, g)
  return isZero(difference)
}

export function wipe(...fields: Float64Array[]): void {
  for (const value of fields) {
    value.fill(0)
  }

  product.fill(0)
}
