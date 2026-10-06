import { InvalidInputError, UnsupportedError } from './errors.js'
import { bytesToBigInt } from './bytes.js'
import { random } from './random.js'

export interface Factors {
  p: bigint
  q: bigint
}

export interface MathCrypto {
  modPow(base: bigint, exponent: bigint, modulus: bigint): bigint
  gcd(a: bigint, b: bigint): bigint
  factor(value: bigint): Factors
  isPrime(value: bigint): boolean
  isSafePrime(value: bigint): boolean
}

const UINT64_LIMIT = 1n << 64n
const SMALL_PRIMES = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]
const WITNESSES_64 = [2n, 325n, 9375n, 28178n, 450775n, 9780504n, 1795265022n]

function integer(value: bigint): void {
  if (typeof value !== 'bigint') {
    throw new InvalidInputError('Expected a bigint')
  }
}

function gcd(a: bigint, b: bigint): bigint {
  integer(a)
  integer(b)

  if (a < 0n) {
    a = -a
  }

  if (b < 0n) {
    b = -b
  }

  while (b !== 0n) {
    [a, b] = [b, a % b]
  }

  return a
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  integer(base)
  integer(exponent)
  integer(modulus)

  if (exponent < 0n) {
    throw new InvalidInputError('Exponent must be non-negative')
  }

  if (modulus <= 0n) {
    throw new InvalidInputError('Modulus must be positive')
  }

  base = ((base % modulus) + modulus) % modulus
  let result = 1n % modulus

  while (exponent > 0n) {
    if (exponent & 1n) {
      result = (result * base) % modulus
    }

    exponent >>= 1n

    if (exponent > 0n) {
      base = (base * base) % modulus
    }
  }

  return result
}

export function randomBelow(limit: bigint): bigint {
  if (limit <= 0n) {
    throw new InvalidInputError('Random integer limit must be positive')
  }

  if (limit === 1n) {
    return 0n
  }

  const bits = (limit - 1n).toString(2).length
  const length = Math.ceil(bits / 8)
  const mask = 0xff >>> (length * 8 - bits)

  for (let attempt = 0; attempt < 128; attempt++) {
    const data = random(length)
    data[0] &= mask
    const value = bytesToBigInt(data)

    if (value < limit) {
      return value
    }
  }

  throw new UnsupportedError('Cryptographic random sampling failed')
}

function isPrime(value: bigint): boolean {
  integer(value)

  if (value < 2n) {
    return false
  }

  for (const prime of SMALL_PRIMES) {
    if (value === prime) {
      return true
    }

    if (value % prime === 0n) {
      return false
    }
  }

  let exponent = value - 1n
  let powers = 0

  while ((exponent & 1n) === 0n) {
    exponent >>= 1n
    powers++
  }

  function passes(witness: bigint): boolean {
    witness %= value

    if (witness < 2n) {
      return true
    }

    let x = modPow(witness, exponent, value)

    if (x === 1n || x === value - 1n) {
      return true
    }

    for (let i = 1; i < powers; i++) {
      x = (x * x) % value

      if (x === value - 1n) {
        return true
      }

      if (x === 1n) {
        return false
      }
    }

    return false
  }

  if (value < UINT64_LIMIT) {
    return WITNESSES_64.every(passes)
  }

  for (let round = 0; round < 64; round++) {
    if (!passes(2n + randomBelow(value - 3n))) {
      return false
    }
  }

  return true
}

function factors(value: bigint, divisor: bigint): Factors {
  const other = value / divisor

  if (!isPrime(divisor) || !isPrime(other)) {
    throw new InvalidInputError('Factorization requires a product of two primes')
  }

  return divisor <= other
    ? {
      p: divisor,
      q: other,
    }
    : {
      p: other,
      q: divisor,
    }
}

function factor(value: bigint): Factors {
  integer(value)

  if (value < 4n) {
    throw new InvalidInputError('Factorization requires a semiprime')
  }

  if (value >= UINT64_LIMIT) {
    throw new UnsupportedError('Factorization supports integers below 2^64')
  }

  for (const prime of SMALL_PRIMES) {
    if (value % prime === 0n) {
      return factors(value, prime)
    }
  }

  if (isPrime(value)) {
    throw new InvalidInputError('A prime has no non-trivial factors')
  }

  let remaining = 2_000_000

  for (let attempt = 1; attempt <= 32 && remaining > 0; attempt++) {
    const constant = BigInt(attempt * 2 + 1)
    let y = BigInt(attempt + 1)
    let x = y
    let saved = y
    let divisor = 1n
    let span = 1
    let work = 0

    const step = (n: bigint): bigint => {
      remaining--
      work++

      return (n * n + constant) % value
    }

    while (divisor === 1n && remaining > 0 && work < 250_000) {
      x = y

      for (let i = 0; i < span && remaining > 0 && work < 250_000; i++) {
        y = step(y)
      }

      let offset = 0

      while (
        offset < span &&
        divisor === 1n &&
        remaining > 0 &&
        work < 250_000
      ) {
        saved = y
        let product = 1n
        const batch = Math.min(64, span - offset)

        for (let i = 0; i < batch && remaining > 0 && work < 250_000; i++) {
          y = step(y)
          const difference = x > y ? x - y : y - x
          product = (product * difference) % value
        }

        divisor = gcd(product, value)
        offset += batch
      }

      span *= 2
    }

    if (divisor === value) {
      do {
        if (remaining <= 0 || work >= 250_000) {
          break
        }

        saved = step(saved)
        divisor = gcd(x > saved ? x - saved : saved - x, value)
      } while (divisor === 1n)
    }

    if (divisor > 1n && divisor < value) {
      return factors(value, divisor)
    }
  }

  throw new UnsupportedError('Factorization exceeded its iteration budget')
}

export const math: MathCrypto = {
  modPow,
  gcd,
  factor,
  isPrime,

  isSafePrime(value: bigint): boolean {
    integer(value)

    return value >= 5n && isPrime(value) && isPrime((value - 1n) / 2n)
  },
}
