import { InvalidKeyError } from '../errors.js'

export interface NativeHash {
  update(data: Uint8Array): void
  digest(): Uint8Array
}

export interface NativeSealed {
  ciphertext: Uint8Array
  tag: Uint8Array
}

export interface NativeCipher {
  encrypt(iv: Uint8Array, data: Uint8Array): Promise<Uint8Array | undefined>
  decrypt(iv: Uint8Array, data: Uint8Array): Promise<Uint8Array | undefined>
}

export interface NativeAead {
  encrypt(
    nonce: Uint8Array,
    data: Uint8Array,
    aad: Uint8Array,
    tagLength: number,
  ): Promise<NativeSealed | undefined>
  decrypt(
    nonce: Uint8Array,
    data: Uint8Array,
    aad: Uint8Array,
    tag: Uint8Array,
  ): Promise<Uint8Array | undefined>
}

export interface NativeRsaKey {
  n: bigint
  e?: bigint
  d?: bigint
  p?: bigint
  q?: bigint
}

export interface NativeOaep {
  encrypt(data: Uint8Array): Promise<Uint8Array | undefined>
  decrypt(data: Uint8Array): Promise<Uint8Array | undefined>
}

export function lazy<T>(create: () => T): () => T {
  let initialized = false
  let value: T

  return () => {
    if (!initialized) {
      value = create()
      initialized = true
    }

    return value
  }
}

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
