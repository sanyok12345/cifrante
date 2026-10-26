type Field = Float64Array

function field(value = 0): Field {
  const result = new Float64Array(16)
  result[0] = value
  return result
}

function carry(o: Field): void {
  let c = 1

  for (let i = 0; i < 16; i++) {
    const v = o[i] + c + 65535
    c = Math.floor(v / 65536)
    o[i] = v - c * 65536
  }

  o[0] += c - 1 + 37 * (c - 1)
}

function select(p: Field, q: Field, bit: number): void {
  const mask = ~(bit - 1)

  for (let i = 0; i < 16; i++) {
    const t = mask & (p[i] ^ q[i])
    p[i] ^= t
    q[i] ^= t
  }
}

function pack(output: Uint8Array, n: Field): void {
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

function unpack(output: Field, n: Uint8Array): void {
  for (let i = 0; i < 16; i++) {
    output[i] = n[2 * i] + (n[2 * i + 1] << 8)
  }

  output[15] &= 0x7fff
}

function add(o: Field, a: Field, b: Field): void {
  for (let i = 0; i < 16; i++) {
    o[i] = a[i] + b[i]
  }
}

function subtract(o: Field, a: Field, b: Field): void {
  for (let i = 0; i < 16; i++) {
    o[i] = a[i] - b[i]
  }
}

const product = /* @__PURE__ */ new Float64Array(31)

function multiply(o: Field, a: Field, b: Field): void {
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

function invert(o: Field, input: Field): void {
  const c = Float64Array.from(input)

  for (let a = 253; a >= 0; a--) {
    multiply(c, c, c)

    if (a !== 2 && a !== 4) {
      multiply(c, c, input)
    }
  }

  o.set(c)
}

export function scalarMult(scalar: Uint8Array, point: Uint8Array): Uint8Array {
  const z = Uint8Array.from(scalar)
  const x = field()
  const a = field(1)
  const b = field()
  const c = field()
  const d = field(1)
  const e = field()
  const f = field()
  const constant = field(0xdb41)

  constant[1] = 1
  z[31] = (z[31] & 127) | 64
  z[0] &= 248
  unpack(x, point)
  b.set(x)

  for (let i = 254; i >= 0; i--) {
    const bit = (z[i >>> 3] >>> (i & 7)) & 1

    select(a, b, bit)
    select(c, d, bit)
    add(e, a, c)
    subtract(a, a, c)
    add(c, b, d)
    subtract(b, b, d)
    multiply(d, e, e)
    multiply(f, a, a)
    multiply(a, c, a)
    multiply(c, b, e)
    add(e, a, c)
    subtract(a, a, c)
    multiply(b, a, a)
    subtract(c, d, f)
    multiply(a, c, constant)
    add(a, a, d)
    multiply(c, c, a)
    multiply(a, d, f)
    multiply(d, b, x)
    multiply(b, e, e)
    select(a, b, bit)
    select(c, d, bit)
  }

  invert(c, c)
  multiply(a, a, c)

  const output = new Uint8Array(32)
  pack(output, a)

  for (const value of [z, x, a, b, c, d, e, f, product]) {
    value.fill(0)
  }

  return output
}
