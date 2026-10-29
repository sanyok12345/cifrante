import type { Binary, Data } from '../types.js'
import type { HashName } from '../kdf.js'
import { bytesToBigInt, toBinary, toBytes } from '../bytes.js'
import {
  AuthenticationError,
  InvalidInputError,
  InvalidKeyError,
} from '../errors.js'
import { decodePrivateKey, decodePublicKey, encodeKey } from './encoding.js'
import type { RsaEncodeOptions, RsaJsonWebKey, RsaKeyInput, RsaKeyType } from './encoding.js'
import { keys, keysSync } from './generate.js'
import type { RsaKeyOptions, RsaKeyPair } from './generate.js'
import { signature } from './signature.js'
import type { RsaPssOptions, RsaSignature, RsaSignatureOptions } from './signature.js'
import { checkKey, digest, mgf1, operate, xorInto } from './core.js'
import { nativeOaep } from '../native/web.js'
import { random } from '../random.js'

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
  encryptSync(data: Data): Uint8Array
  decryptSync(data: Binary): Uint8Array
}

export type { RsaEncodeOptions, RsaJsonWebKey, RsaKeyFormat, RsaKeyInput, RsaKeyType } from './encoding.js'
export type { RsaKeyOptions, RsaKeyPair } from './generate.js'
export type { RsaPssOptions, RsaSignature, RsaSignatureOptions } from './signature.js'

export interface RSA {
  publicKey(key: RsaKeyInput): RsaPublicKey
  privateKey(key: RsaKeyInput): RsaPrivateKey
  raw: {
    (key: RsaPublicKey | RsaPrivateKey, data: Binary): Promise<Uint8Array>
    sync(key: RsaPublicKey | RsaPrivateKey, data: Binary): Uint8Array
  }
  oaep(key: RsaPublicKey | RsaPrivateKey, options?: RsaOaepOptions): RsaOaep
  pss(key: RsaPublicKey | RsaPrivateKey, options?: RsaPssOptions): RsaSignature
  pkcs1(key: RsaPublicKey | RsaPrivateKey, options?: RsaSignatureOptions): RsaSignature
  encode(key: RsaPublicKey | RsaPrivateKey, options: { format: 'pem', type?: RsaKeyType }): string
  encode(key: RsaPublicKey | RsaPrivateKey, options: { format: 'der', type?: RsaKeyType }): Uint8Array
  encode(key: RsaPublicKey | RsaPrivateKey, options: { format: 'jwk' }): RsaJsonWebKey
  keys: {
    (options?: RsaKeyOptions): Promise<RsaKeyPair>
    sync(options?: RsaKeyOptions): RsaKeyPair
  }
}

function rawSync(
  key: RsaPublicKey | RsaPrivateKey,
  data: Binary,
): Uint8Array {
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

async function raw(
  key: RsaPublicKey | RsaPrivateKey,
  data: Binary,
): Promise<Uint8Array> {
  return rawSync(key, data)
}

function oaep(
  key: RsaPublicKey | RsaPrivateKey,
  options: RsaOaepOptions = {},
): RsaOaep {
  const checked = checkKey(key)

  if (!options || typeof options !== 'object') {
    throw new InvalidInputError('Invalid RSA-OAEP options')
  }

  const { name, hash, length: hLength } = digest(options.hash, 'RSA-OAEP')

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

  function message(data: Data): Uint8Array {
    if (checked.private) {
      throw new InvalidKeyError('RSA-OAEP encryption requires a public key')
    }

    const bytes = toBytes(data)

    if (bytes.length > length - 2 * hLength - 2) {
      throw new InvalidInputError(
        'Message is too long for the RSA-OAEP modulus and hash',
      )
    }

    return bytes
  }

  function ciphertext(data: Binary): { bytes: Uint8Array, value: bigint } {
    if (!checked.private) {
      throw new InvalidKeyError('RSA-OAEP decryption requires a private key')
    }

    const bytes = toBinary(data)

    if (bytes.length !== length) {
      throw new AuthenticationError('RSA-OAEP decryption failed')
    }

    const value = bytesToBigInt(bytes)

    if (value >= checked.n) {
      throw new AuthenticationError('RSA-OAEP decryption failed')
    }

    return { bytes, value }
  }

  function seal(data: Uint8Array): Uint8Array {
    const encoded = new Uint8Array(length)
    const seed = encoded.subarray(1, 1 + hLength)
    const db = encoded.subarray(1 + hLength)

    try {
      db.set(labelHash ??= hash(label))
      db[db.length - data.length - 1] = 1
      db.set(data, db.length - data.length)
      seed.set(random(hLength))
      xorInto(db, mgf1(hash, seed, db.length))
      xorInto(seed, mgf1(hash, db, hLength))

      return operate(checked, bytesToBigInt(encoded))
    } finally {
      encoded.fill(0)
    }
  }

  function open(value: bigint): Uint8Array {
    const encoded = operate(checked, value)
    const seed = encoded.subarray(1, 1 + hLength)
    const db = encoded.subarray(1 + hLength)

    try {
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
    } finally {
      encoded.fill(0)
    }
  }

  return {
    async encrypt(data: Data): Promise<Uint8Array> {
      const bytes = message(data)

      return await native.encrypt(bytes) ?? seal(bytes)
    },

    encryptSync(data: Data): Uint8Array {
      const bytes = message(data)

      return native.encryptSync?.(bytes) ?? seal(bytes)
    },

    async decrypt(data: Binary): Promise<Uint8Array> {
      const { bytes, value } = ciphertext(data)

      return await native.decrypt(bytes) ?? open(value)
    },

    decryptSync(data: Binary): Uint8Array {
      const { bytes, value } = ciphertext(data)

      return native.decryptSync?.(bytes) ?? open(value)
    },
  }
}

function publicKey(key: RsaKeyInput): RsaPublicKey {
  const parsed = decodePublicKey(key)

  checkKey(parsed)

  return parsed
}

function privateKey(key: RsaKeyInput): RsaPrivateKey {
  const parsed = decodePrivateKey(key)

  checkKey(parsed)

  return parsed
}

function encode(key: RsaPublicKey | RsaPrivateKey, options: { format: 'pem', type?: RsaKeyType }): string
function encode(key: RsaPublicKey | RsaPrivateKey, options: { format: 'der', type?: RsaKeyType }): Uint8Array
function encode(key: RsaPublicKey | RsaPrivateKey, options: { format: 'jwk' }): RsaJsonWebKey
function encode(key: RsaPublicKey | RsaPrivateKey, options: RsaEncodeOptions): string | Uint8Array | RsaJsonWebKey {
  checkKey(key)

  return encodeKey(key, options)
}

export const rsa: RSA = {
  publicKey,
  privateKey,
  raw: /* @__PURE__ */ Object.assign(raw, { sync: rawSync }),
  oaep,
  pss: (key, options) => signature('pss', key, options),
  pkcs1: (key, options) => signature('pkcs1', key, options),
  encode,
  keys: /* @__PURE__ */ Object.assign(keys, { sync: keysSync }),
}
