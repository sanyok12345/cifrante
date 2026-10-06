import type { Binary, Data } from './types.js'
import type { HashName } from './kdf.js'
import { bigIntToBytes, bytesToBigInt, toBinary, toBytes } from './bytes.js'
import {
  AuthenticationError,
  InvalidInputError,
  InvalidKeyError,
  UnsupportedError,
} from './errors.js'
import { sha1Sync } from './hash/sha1.js'
import { sha256Sync } from './hash/sha256.js'
import { sha512Sync } from './hash/sha512.js'
import { math, randomBelow } from './math.js'
import { inverseMod } from './platform/shared.js'
import { nativeOaep, nativeRsaPrivate, nativeRsaPublic } from './platform/web.js'
import { random } from './random.js'

export interface RsaPublicKey {
  n: bigint
  e: bigint
}

export interface RsaPrivateKey {
  n: bigint
  d: bigint
  p?: bigint
  q?: bigint
}

export interface RsaOaepOptions {
  hash?: HashName
  label?: Data
}

export interface RsaOaep {
  encrypt(data: Data): Promise<Uint8Array>
  decrypt(data: Binary): Promise<Uint8Array>
}

export interface RSA {
  raw(key: RsaPublicKey | RsaPrivateKey, data: Binary): Promise<Uint8Array>
  oaep(key: RsaPublicKey | RsaPrivateKey, options?: RsaOaepOptions): RsaOaep
}

type CheckedKey = {
  n: bigint
  exponent: bigint
  length: number
  private: boolean
  p?: bigint
  q?: bigint
}

type Digest = (data: Data) => Uint8Array

function checkKey(key: RsaPublicKey | RsaPrivateKey): CheckedKey {
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

function operate(key: CheckedKey, value: bigint): Uint8Array<ArrayBuffer> {
  if (!key.private) {
    const padded = bigIntToBytes(value, key.length)
    const native = nativeRsaPublic(key.n, key.exponent, padded)

    if (native !== undefined) {
      return new Uint8Array(native)
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
      return new Uint8Array(native)
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

async function raw(
  key: RsaPublicKey | RsaPrivateKey,
  data: Binary,
): Promise<Uint8Array> {
  const checked = checkKey(key)
  const input = toBinary(data)

  if (input.length > checked.length) {
    throw new InvalidInputError('RSA input exceeds the modulus length')
  }

  const value = bytesToBigInt(input)

  if (value >= checked.n) {
    throw new InvalidInputError('RSA representative must be below the modulus')
  }

  return operate(checked, value)
}

function mgf1(
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

function xorInto(target: Uint8Array, mask: Uint8Array): void {
  for (let i = 0; i < target.length; i++) {
    target[i] ^= mask[i]
  }
}

function oaep(
  key: RsaPublicKey | RsaPrivateKey,
  options: RsaOaepOptions = {},
): RsaOaep {
  const checked = checkKey(key)

  if (!options || typeof options !== 'object') {
    throw new InvalidInputError('Invalid RSA-OAEP options')
  }

  const name = options.hash === undefined ? 'sha256' : options.hash
  let hash: Digest
  let hLength: number

  switch (name) {
    case 'sha1':
      hash = sha1Sync
      hLength = 20
      break

    case 'sha256':
      hash = sha256Sync
      hLength = 32
      break

    case 'sha512':
      hash = sha512Sync
      hLength = 64
      break

    default:
      throw new UnsupportedError('Unsupported RSA-OAEP hash')
  }

  const label = options.label === undefined ? new Uint8Array(0) : toBytes(options.label)
  const length = checked.length

  if (length < 2 * hLength + 2) {
    throw new InvalidKeyError('RSA modulus is too short for the chosen OAEP hash')
  }

  const nativeKey = checked.private
    ? { n: checked.n, d: checked.exponent, p: checked.p, q: checked.q }
    : { n: checked.n, e: checked.exponent }
  const native = nativeOaep(nativeKey, name, label)
  let labelHash: Uint8Array | undefined

  return {
    async encrypt(data: Data): Promise<Uint8Array> {
      if (checked.private) {
        throw new InvalidKeyError('RSA-OAEP encryption requires a public key')
      }

      const message = toBytes(data)

      if (message.length > length - 2 * hLength - 2) {
        throw new InvalidInputError(
          'Message is too long for the RSA-OAEP modulus and hash',
        )
      }

      const result = await native.encrypt(message)

      if (result !== undefined) {
        return Uint8Array.from(result)
      }

      const encoded = new Uint8Array(length)
      const seed = encoded.subarray(1, 1 + hLength)
      const db = encoded.subarray(1 + hLength)

      db.set(labelHash ??= hash(label))
      db[db.length - message.length - 1] = 1
      db.set(message, db.length - message.length)
      seed.set(random(hLength))
      xorInto(db, mgf1(hash, seed, db.length))
      xorInto(seed, mgf1(hash, db, hLength))

      return operate(checked, bytesToBigInt(encoded))
    },

    async decrypt(data: Binary): Promise<Uint8Array> {
      if (!checked.private) {
        throw new InvalidKeyError('RSA-OAEP decryption requires a private key')
      }

      const ciphertext = toBinary(data)

      if (ciphertext.length !== length) {
        throw new AuthenticationError('RSA-OAEP decryption failed')
      }

      const value = bytesToBigInt(ciphertext)

      if (value >= checked.n) {
        throw new AuthenticationError('RSA-OAEP decryption failed')
      }

      const result = await native.decrypt(ciphertext)

      if (result !== undefined) {
        return Uint8Array.from(result)
      }

      const encoded = operate(checked, value)
      const seed = encoded.subarray(1, 1 + hLength)
      const db = encoded.subarray(1 + hLength)

      xorInto(seed, mgf1(hash, db, hLength))
      xorInto(db, mgf1(hash, seed, db.length))

      let invalid = encoded[0]
      const digest = labelHash ??= hash(label)

      for (let i = 0; i < hLength; i++) {
        invalid |= db[i] ^ digest[i]
      }

      let looking = 1
      let start = 0

      for (let i = hLength; i < db.length; i++) {
        const zero = Number(db[i] === 0)
        const one = Number(db[i] === 1)
        invalid |= looking & (1 - zero) & (1 - one)
        const separator = looking & one
        start += separator * (i + 1 - start)
        looking &= 1 - one
      }

      invalid |= looking

      if (invalid !== 0) {
        throw new AuthenticationError('RSA-OAEP decryption failed')
      }

      return db.slice(start)
    },
  }
}

export const rsa: RSA = {
  raw,
  oaep,
}
