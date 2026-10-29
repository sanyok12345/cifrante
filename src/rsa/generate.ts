import { bytesToBigInt } from '../bytes.js'
import { InvalidInputError } from '../errors.js'
import { math } from '../math.js'
import { nativeRsaGenerate, nativeRsaGenerateSync } from '../native/web.js'
import { random } from '../random.js'
import { inverseMod } from './key.js'
import type { RsaPrivateKey, RsaPublicKey } from './rsa.js'

export interface RsaKeyOptions {
  bits?: number
  exponent?: bigint
}

export interface RsaKeyPair {
  publicKey: RsaPublicKey
  privateKey: RsaPrivateKey
}

const SIEVE = /* @__PURE__ */ (() => {
  const primes: bigint[] = []

  for (let candidate = 3; candidate < 2000; candidate += 2) {
    if (primes.every(prime => candidate % Number(prime) !== 0)) {
      primes.push(BigInt(candidate))
    }
  }

  return primes
})()

function parameters(options: RsaKeyOptions | undefined): { bits: number, exponent: bigint } {
  if (options !== undefined && (options === null || typeof options !== 'object')) {
    throw new InvalidInputError('Invalid RSA key options')
  }

  const bits = options?.bits ?? 2048
  const exponent = options?.exponent ?? 65537n

  if (!Number.isInteger(bits) || bits < 1024 || bits > 16384) {
    throw new InvalidInputError('RSA key size must be an integer between 1024 and 16384 bits')
  }

  if (typeof exponent !== 'bigint' || exponent < 3n || !(exponent & 1n) || exponent >= 1n << 256n) {
    throw new InvalidInputError('RSA public exponent must be an odd bigint between 3 and 2^256')
  }

  return { bits, exponent }
}

function prime(bits: number, exponent: bigint): bigint {
  const length = Math.ceil(bits / 8)
  const excess = length * 8 - bits

  for (;;) {
    const bytes = random(length)

    bytes[0] &= 0xff >>> excess
    bytes[0] |= 0xc0 >>> excess
    bytes[length - 1] |= 1

    const candidate = bytesToBigInt(bytes)

    if (SIEVE.some(small => candidate % small === 0n)) {
      continue
    }

    if (math.gcd(candidate - 1n, exponent) === 1n && math.isPrime(candidate)) {
      return candidate
    }
  }
}

function pair({ n, e, d, p, q }: { n: bigint, e: bigint, d: bigint, p?: bigint, q?: bigint }): RsaKeyPair {
  return { publicKey: { n, e }, privateKey: { n, d, p, q } }
}

function generateJs(bits: number, exponent: bigint): RsaKeyPair {
  const p = prime(Math.ceil(bits / 2), exponent)
  let q = prime(Math.floor(bits / 2), exponent)

  while (q === p) {
    q = prime(Math.floor(bits / 2), exponent)
  }

  const lambda = (p - 1n) / math.gcd(p - 1n, q - 1n) * (q - 1n)

  return pair({ n: p * q, e: exponent, d: inverseMod(exponent, lambda), p, q })
}

export function keysSync(options?: RsaKeyOptions): RsaKeyPair {
  const { bits, exponent } = parameters(options)
  const native = nativeRsaGenerateSync(bits, exponent)

  return native ? pair(native) : generateJs(bits, exponent)
}

export async function keys(options?: RsaKeyOptions): Promise<RsaKeyPair> {
  const { bits, exponent } = parameters(options)
  const native = await nativeRsaGenerate(bits, exponent)

  return native ? pair(native) : generateJs(bits, exponent)
}
