import { add, field, invert, multiply, pack, select, subtract, unpack, wipe } from '../curve25519/field.js'

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

  z.fill(0)
  wipe(x, a, b, c, d, e, f)

  return output
}
