import { InvalidKeyError } from './errors.js'
import type { NativeRsaKey } from './native/types.js'

export function inverseMod(value: bigint, modulus: bigint): bigint {
  let a = modulus
  let b = value
  let x = 0n
  let y = 1n

  while (b !== 0n) {
    const quotient = a / b
    ;[a, b] = [b, a - quotient * b]
    ;[x, y] = [y, x - quotient * y]
  }

  if (a !== 1n) {
    throw new InvalidKeyError('Invalid RSA factors or private exponent')
  }

  return ((x % modulus) + modulus) % modulus
}

export function rsaJwk(
  key: NativeRsaKey,
  encode: (value: bigint) => string,
): JsonWebKey | undefined {
  const { n, e, d, p, q } = key

  if (d === undefined) {
    return e === undefined ? undefined : { kty: 'RSA', n: encode(n), e: encode(e) }
  }

  if (p === undefined || q === undefined) {
    return undefined
  }

  let a = p - 1n
  let b = q - 1n

  while (b !== 0n) {
    [a, b] = [b, a % b]
  }

  const lambda = (p - 1n) / a * (q - 1n)

  return {
    kty: 'RSA',
    n: encode(n),
    e: encode(inverseMod(d, lambda)),
    d: encode(d),
    p: encode(p),
    q: encode(q),
    dp: encode(d % (p - 1n)),
    dq: encode(d % (q - 1n)),
    qi: encode(inverseMod(q, p)),
  }
}
