import type { HashName } from '../kdf.js'
import { bigIntToBytes } from '../bytes.js'
import { InvalidKeyError, UnsupportedError } from '../errors.js'
import { sha1Sync } from '../hash/sha1.js'
import { sha256Sync } from '../hash/sha256.js'
import { sha384Sync, sha512Sync } from '../hash/sha512.js'
import { math } from '../math.js'
import { nativeRsaPrivate, nativeRsaPublic } from '../native/web.js'
import { randomBelow } from '../random.js'
import type { Data } from '../types.js'
import { inverseMod } from './key.js'
import type { RsaPrivateKey, RsaPublicKey } from './rsa.js'

export type CheckedKey = {
  n: bigint
  exponent: bigint
  length: number
  private: boolean
  p?: bigint
  q?: bigint
}

export type Digest = (data: Data) => Uint8Array

export function checkKey(key: RsaPublicKey | RsaPrivateKey): CheckedKey {
  if (
    !key ||
    typeof key !== 'object' ||
    typeof key.n !== 'bigint' ||
    key.n < 3n ||
    !(key.n & 1n)
  ) {
    throw new InvalidKeyError(
      'RSA modulus must be an odd positive bigint greater than two',
    )
  }

  const privateKey = 'd' in key
  const exponent = privateKey ? key.d : key.e

  if (
    typeof exponent !== 'bigint' ||
    exponent <= 0n ||
    exponent >= key.n ||
    !(exponent & 1n)
  ) {
    throw new InvalidKeyError(
      'RSA exponent must be an odd positive bigint below the modulus',
    )
  }

  if (!privateKey && exponent < 3n) {
    throw new InvalidKeyError('RSA public exponent must be at least three')
  }

  if (privateKey && (key.p !== undefined || key.q !== undefined)) {
    const { p, q } = key

    if (
      typeof p !== 'bigint' ||
      typeof q !== 'bigint' ||
      p <= 2n ||
      q <= 2n ||
      !(p & 1n) ||
      !(q & 1n) ||
      p === q ||
      p * q !== key.n ||
      math.gcd(p, q) !== 1n
    ) {
      throw new InvalidKeyError(
        'RSA factors must be a distinct odd pair whose product is n',
      )
    }

    const lambda = ((p - 1n) / math.gcd(p - 1n, q - 1n)) * (q - 1n)

    if (math.gcd(exponent, lambda) !== 1n) {
      throw new InvalidKeyError(
        'RSA private exponent must be coprime to the factors’ Carmichael value',
      )
    }
  }

  return {
    n: key.n,
    exponent,
    length: Math.ceil(key.n.toString(2).length / 8),
    private: privateKey,
    p: privateKey ? key.p : undefined,
    q: privateKey ? key.q : undefined,
  }
}

export function operate(key: CheckedKey, value: bigint): Uint8Array {
  if (!key.private) {
    const padded = bigIntToBytes(value, key.length)
    const native = nativeRsaPublic(key.n, key.exponent, padded)

    if (native !== undefined) {
      return native
    }

    return bigIntToBytes(math.modPow(value, key.exponent, key.n), key.length)
  }

  if (key.p !== undefined && key.q !== undefined) {
    const native = nativeRsaPrivate(
      key.n,
      key.exponent,
      key.p,
      key.q,
      bigIntToBytes(value, key.length),
    )

    if (native !== undefined) {
      return native
    }
  }

  for (let attempt = 0; attempt < 128; attempt++) {
    const r = 2n + randomBelow(key.n - 2n)

    if (math.gcd(r, key.n) !== 1n) {
      continue
    }

    const mask = math.modPow(r, key.exponent, key.n)
    const blinded = math.modPow((value * r) % key.n, key.exponent, key.n)

    return bigIntToBytes((blinded * inverseMod(mask, key.n)) % key.n, key.length)
  }

  throw new UnsupportedError('Unable to obtain an RSA blinding factor')
}

export function digest(name: HashName | undefined, algorithm: string): { name: HashName, hash: Digest, length: number } {
  switch (name ?? 'sha256') {
    case 'sha1':
      return { name: 'sha1', hash: sha1Sync, length: 20 }
    case 'sha256':
      return { name: 'sha256', hash: sha256Sync, length: 32 }
    case 'sha384':
      return { name: 'sha384', hash: sha384Sync, length: 48 }
    case 'sha512':
      return { name: 'sha512', hash: sha512Sync, length: 64 }
    default:
      throw new UnsupportedError(`Unsupported ${algorithm} hash`)
  }
}

export function mgf1(
  hash: Digest,
  seed: Uint8Array,
  length: number,
): Uint8Array<ArrayBuffer> {
  const output = new Uint8Array(length)
  const input = new Uint8Array(seed.length + 4)
  input.set(seed)

  const counter = new DataView(input.buffer, seed.length, 4)
  let offset = 0

  for (let i = 0; offset < length; i++) {
    counter.setUint32(0, i, false)
    const block = hash(input)
    const count = Math.min(block.length, length - offset)
    output.set(block.subarray(0, count), offset)
    offset += count
  }

  return output
}

export function xorInto(target: Uint8Array, mask: Uint8Array): void {
  for (let i = 0; i < target.length; i++) {
    target[i] ^= mask[i]
  }
}
