import {
  add,
  equal,
  field,
  invert,
  isNegative,
  isZero,
  move,
  multiply,
  negate,
  pack,
  pow22523,
  square,
  subtract,
  unpack,
  wipe,
} from '../curve25519/field.js'
import type { Field } from '../curve25519/field.js'
import { sha512Sync } from '../hash/sha512.js'
import { lazy } from '../lazy.js'

type Point = [Field, Field, Field, Field]

const ORDER = [0xd3ed, 0x5cf5, 0x631a, 0x5812, 0x9cd6, 0xa2f7, 0xf9de, 0x14de, 0, 0, 0, 0, 0, 0, 0, 0x1000]

function point(): Point {
  return [field(), field(1), field(1), field()]
}

function copy(r: Point, p: Point): void {
  for (let i = 0; i < 4; i++) {
    r[i].set(p[i])
  }
}

function choose(r: Point, p: Point, bit: number): void {
  for (let i = 0; i < 4; i++) {
    move(r[i], p[i], bit)
  }
}

function addPoints(r: Point, p: Point, q: Point, d2: Field): void {
  const a = field()
  const b = field()
  const c = field()
  const d = field()
  const e = field()
  const f = field()
  const g = field()
  const h = field()
  const t = field()

  subtract(a, p[1], p[0])
  subtract(t, q[1], q[0])
  multiply(a, a, t)
  add(b, p[1], p[0])
  add(t, q[1], q[0])
  multiply(b, b, t)
  multiply(c, p[3], q[3])
  multiply(c, c, d2)
  multiply(d, p[2], q[2])
  add(d, d, d)
  subtract(e, b, a)
  subtract(f, d, c)
  add(g, d, c)
  add(h, b, a)
  multiply(r[0], e, f)
  multiply(r[1], g, h)
  multiply(r[3], e, h)
  multiply(r[2], f, g)
}

function double(r: Point, p: Point): void {
  const a = field()
  const b = field()
  const c = field()
  const e = field()
  const f = field()
  const g = field()
  const h = field()
  const t = field()

  square(a, p[0])
  square(b, p[1])
  square(c, p[2])
  add(c, c, c)
  add(h, a, b)
  add(t, p[0], p[1])
  square(t, t)
  subtract(e, h, t)
  subtract(g, a, b)
  add(f, c, g)
  multiply(r[0], e, f)
  multiply(r[1], g, h)
  multiply(r[3], e, h)
  multiply(r[2], f, g)
}

function decode(p: Point, input: Uint8Array, d: Field, root: Field): boolean {
  const bytes = Uint8Array.from(input)
  const sign = bytes[31] >> 7
  const canonical = new Uint8Array(32)
  const u = field()
  const v = field()
  const v3 = field()
  const check = field()
  const one = field(1)

  bytes[31] &= 127
  unpack(p[1], bytes)
  pack(canonical, p[1])

  if (canonical.some((byte, i) => byte !== bytes[i])) {
    return false
  }

  p[2].set(one)
  square(u, p[1])
  multiply(v, u, d)
  subtract(u, u, one)
  add(v, v, one)
  square(v3, v)
  multiply(v3, v3, v)
  square(p[0], v3)
  multiply(p[0], p[0], v)
  multiply(p[0], p[0], u)
  pow22523(p[0], p[0])
  multiply(p[0], p[0], v3)
  multiply(p[0], p[0], u)
  square(check, p[0])
  multiply(check, check, v)

  if (!equal(check, u)) {
    negate(u, u)

    if (!equal(check, u)) {
      return false
    }

    multiply(p[0], p[0], root)
  }

  if (isZero(p[0]) && sign) {
    return false
  }

  if (isNegative(p[0]) !== sign) {
    negate(p[0], p[0])
  }

  multiply(p[3], p[0], p[1])
  return true
}

const constants = /* @__PURE__ */ lazy(() => {
  const d = field()
  const d2 = field()
  const root = field()
  const t = field(121666)
  const y = field(4)
  const bytes = new Uint8Array(32)
  const base = point()

  invert(t, t)
  multiply(d, field(-121665), t)
  add(d2, d, d)
  multiply(d2, d2, field(1))
  pow22523(root, field(2))
  square(root, root)
  multiply(root, root, field(2))
  invert(t, field(5))
  multiply(y, y, t)
  pack(bytes, y)
  decode(base, bytes, d, root)

  return { d, d2, root, base }
})

function scalarMultiply(r: Point, scalar: Uint8Array, p: Point): void {
  const { d2 } = constants()
  const q = point()
  const s = point()

  q[1].set(field(1))

  for (let i = 255; i >= 0; i--) {
    const bit = (scalar[i >> 3] >> (i & 7)) & 1

    double(q, q)
    addPoints(s, q, p, d2)
    choose(q, s, bit)
  }

  copy(r, q)
  wipe(...q, ...s)
}

function encode(output: Uint8Array, p: Point): void {
  const inverse = field()
  const x = field()
  const y = field()

  invert(inverse, p[2])
  multiply(x, p[0], inverse)
  multiply(y, p[1], inverse)
  pack(output, y)
  output[31] ^= isNegative(x) << 7
  wipe(inverse, x, y)
}

function reduce(input: Uint8Array): Uint8Array {
  const r = new Uint32Array(16)
  const s = new Uint32Array(16)

  for (let i = input.length * 8 - 1; i >= 0; i--) {
    let carry = (input[i >> 3] >> (i & 7)) & 1
    let borrow = 0

    for (let k = 0; k < 16; k++) {
      const next = r[k] >> 15
      r[k] = ((r[k] << 1) | carry) & 0xffff
      carry = next
    }

    for (let k = 0; k < 16; k++) {
      const difference = r[k] - ORDER[k] - borrow
      s[k] = difference & 0xffff
      borrow = (difference >> 16) & 1
    }

    const mask = (borrow - 1) & 0xffff

    for (let k = 0; k < 16; k++) {
      r[k] = (r[k] & ~mask & 0xffff) | (s[k] & mask)
    }
  }

  const output = new Uint8Array(32)

  for (let k = 0; k < 16; k++) {
    output[2 * k] = r[k] & 0xff
    output[2 * k + 1] = r[k] >> 8
  }

  r.fill(0)
  s.fill(0)
  return output
}

function multiplyAdd(a: Uint8Array, b: Uint8Array, c: Uint8Array): Uint8Array {
  const product = new Float64Array(33)
  const bytes = new Uint8Array(68)

  for (let i = 0; i < 16; i++) {
    const x = a[2 * i] | (a[2 * i + 1] << 8)

    for (let j = 0; j < 16; j++) {
      product[i + j] += x * (b[2 * j] | (b[2 * j + 1] << 8))
    }
  }

  for (let i = 0; i < 16; i++) {
    product[i] += c[2 * i] | (c[2 * i + 1] << 8)
  }

  for (let i = 0; i < 32; i++) {
    const carry = Math.floor(product[i] / 65536)
    product[i] -= carry * 65536
    product[i + 1] += carry
  }

  for (let i = 0; i < 33; i++) {
    bytes[2 * i] = product[i] & 0xff
    bytes[2 * i + 1] = (product[i] >> 8) & 0xff
  }

  const output = reduce(bytes)

  product.fill(0)
  bytes.fill(0)
  return output
}

function expand(seed: Uint8Array): { scalar: Uint8Array, prefix: Uint8Array } {
  const digest = sha512Sync(seed)
  const scalar = digest.slice(0, 32)
  const prefix = digest.slice(32)

  scalar[0] &= 248
  scalar[31] &= 127
  scalar[31] |= 64
  digest.fill(0)

  return { scalar, prefix }
}

function challenge(r: Uint8Array, a: Uint8Array, message: Uint8Array): Uint8Array {
  const digest = sha512Sync.create().update(r).update(a).update(message).digest()
  const output = reduce(digest)

  digest.fill(0)
  return output
}

export function publicKeyJs(seed: Uint8Array): Uint8Array {
  const { scalar, prefix } = expand(seed)
  const a = point()
  const output = new Uint8Array(32)

  scalarMultiply(a, scalar, constants().base)
  encode(output, a)
  scalar.fill(0)
  prefix.fill(0)
  wipe(...a)

  return output
}

export function signJs(seed: Uint8Array, message: Uint8Array): Uint8Array {
  const { base } = constants()
  const { scalar, prefix } = expand(seed)
  const p = point()
  const publicKey = new Uint8Array(32)
  const signature = new Uint8Array(64)

  scalarMultiply(p, scalar, base)
  encode(publicKey, p)

  const nonceDigest = sha512Sync.create().update(prefix).update(message).digest()
  const nonce = reduce(nonceDigest)

  scalarMultiply(p, nonce, base)
  encode(signature, p)
  signature.set(multiplyAdd(challenge(signature.subarray(0, 32), publicKey, message), scalar, nonce), 32)

  scalar.fill(0)
  prefix.fill(0)
  nonce.fill(0)
  nonceDigest.fill(0)
  wipe(...p)

  return signature
}

export function verifyJs(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  const { d, root, base } = constants()
  const a = point()

  if (!decode(a, publicKey, d, root)) {
    return false
  }

  const k = challenge(signature.subarray(0, 32), publicKey, message)
  const left = point()
  const right = point()
  const encoded = new Uint8Array(32)

  negate(a[0], a[0])
  negate(a[3], a[3])
  scalarMultiply(left, signature.subarray(32), base)
  scalarMultiply(right, k, a)
  addPoints(left, left, right, constants().d2)
  encode(encoded, left)

  let difference = 0

  for (let i = 0; i < 32; i++) {
    difference |= encoded[i] ^ signature[i]
  }

  return difference === 0
}
