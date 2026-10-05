import * as crypto from 'node:crypto'
import {
  constants,
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  createSecretKey,
  getCiphers,
  getFips,
  getHashes,
  hkdf,
  pbkdf2,
  privateDecrypt,
  publicEncrypt,
  randomFillSync,
  timingSafeEqual,
  type KeyObject,
} from 'node:crypto'
import {
  AuthenticationError,
  UnsupportedError,
} from '../errors.js'
import { lazy, rsaJwk } from './shared.js'
import type {
  NativeAead,
  NativeCipher,
  NativeHash,
  NativeOaep,
  NativeRsaKey,
} from './shared.js'

export type {
  NativeAead,
  NativeCipher,
  NativeHash,
  NativeOaep,
  NativeRsaKey,
  NativeSealed,
} from './shared.js'

let hashes: Set<string> | undefined
let ciphers: Set<string> | undefined

function supports(name: string, available: Set<string>, kind: string): boolean {
  if (available.has(name)) {
    return true
  }

  if (getFips()) {
    throw new UnsupportedError(
      `${kind} ${name} is unavailable under the platform's FIPS policy`,
    )
  }

  return false
}

function supportsHash(name: string): boolean {
  hashes ??= new Set(getHashes().map(name => name.toLowerCase()))

  return supports(name, hashes, 'Hash')
}

function supportsCipher(name: string): boolean {
  ciphers ??= new Set(getCiphers().map(name => name.toLowerCase()))

  return supports(name, ciphers, 'Cipher')
}

export function fillRandom(bytes: Uint8Array<ArrayBuffer>): void {
  for (let offset = 0; offset < bytes.length; offset += 0x7fffffff) {
    randomFillSync(bytes.subarray(offset, offset + 0x7fffffff))
  }
}

function adaptHash(hash: crypto.Hash | crypto.Hmac): NativeHash {
  return {
    update(data) {
      hash.update(data)
    },

    digest() {
      return new Uint8Array(hash.digest())
    },
  }
}

export function nativeHash(name: string): NativeHash | undefined {
  return supportsHash(name) ? adaptHash(createHash(name)) : undefined
}

export function nativeHmac(name: string, key: Uint8Array): NativeHash | undefined {
  return supportsHash(name) ? adaptHash(createHmac(name, key)) : undefined
}

export async function nativeDigest(
  name: string,
  data: Uint8Array,
): Promise<Uint8Array | undefined> {
  if (!supportsHash(name)) {
    return undefined
  }

  const digest = Reflect.get(crypto, 'hash') as typeof crypto.hash | undefined
  const result = typeof digest === 'function'
    ? digest(name, data, 'buffer')
    : createHash(name).update(data).digest()

  return new Uint8Array(result)
}

export async function nativeMac(
  name: string,
  key: Uint8Array,
  data: Uint8Array,
): Promise<Uint8Array | undefined> {
  if (!supportsHash(name)) {
    return undefined
  }

  return new Uint8Array(createHmac(name, key).update(data).digest())
}

export function nativeEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && timingSafeEqual(a, b)
}

type BytesCallback = (error: Error | null, derived: Uint8Array | ArrayBuffer) => void

function callbackBytes(run: (callback: BytesCallback) => void): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    run((error, derived) => {
      if (error) {
        reject(error)
      } else {
        const bytes = ArrayBuffer.isView(derived)
          ? Uint8Array.from(derived)
          : new Uint8Array(derived)

        resolve(bytes)
      }
    })
  })
}

export async function nativePbkdf2(
  hash: string,
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  length: number,
): Promise<Uint8Array | undefined> {
  if (!supportsHash(hash) || iterations > 0x7fffffff || length > 0x7fffffff) {
    return undefined
  }

  if (!length) {
    return new Uint8Array()
  }

  return callbackBytes(callback =>
    pbkdf2(password, salt, iterations, length, hash, callback),
  )
}

export async function nativeHkdf(
  hash: string,
  input: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array | undefined> {
  if (!supportsHash(hash) || info.length > 1024) {
    return undefined
  }

  if (!length) {
    return new Uint8Array()
  }

  return callbackBytes(callback => hkdf(hash, input, salt, info, length, callback))
}

function concat(first: Uint8Array, second: Uint8Array): Uint8Array {
  const result = new Uint8Array(first.length + second.length)

  result.set(first)
  result.set(second, first.length)

  return result
}

export function nativeCipher(
  mode: 'cbc' | 'ctr',
  key: Uint8Array,
): NativeCipher {
  const name = `aes-${key.length * 8}-${mode}`
  const prepare = lazy(() => supportsCipher(name) ? createSecretKey(key) : undefined)

  async function operate(
    iv: Uint8Array,
    data: Uint8Array,
    decrypt: boolean,
  ): Promise<Uint8Array | undefined> {
    const secret = prepare()

    if (secret === undefined) {
      return undefined
    }

    const cipher = decrypt
      ? createDecipheriv(name, secret, iv)
      : createCipheriv(name, secret, iv)
    const output = cipher.update(data)

    try {
      return concat(output, cipher.final())
    } catch (error) {
      if (decrypt && mode === 'cbc') {
        output.fill(0)
        throw new AuthenticationError('Invalid CBC padding')
      }

      throw error
    }
  }

  return {
    encrypt: (iv, data) => operate(iv, data, false),
    decrypt: (iv, data) => operate(iv, data, true),
  }
}

export function nativeGcm(key: Uint8Array): NativeAead {
  const name = `aes-${key.length * 8}-gcm` as 'aes-128-gcm'
  const prepare = lazy(() => supportsCipher(name) ? createSecretKey(key) : undefined)

  return {
    async encrypt(nonce, data, aad, tagLength) {
      const secret = prepare()

      if (secret === undefined || nonce.length > 128) {
        return undefined
      }

      const cipher = createCipheriv(name, secret, nonce, { authTagLength: tagLength })
      cipher.setAAD(aad)

      const output = cipher.update(data)

      return {
        ciphertext: concat(output, cipher.final()),
        tag: new Uint8Array(cipher.getAuthTag()),
      }
    },

    async decrypt(nonce, data, aad, tag) {
      const secret = prepare()

      if (secret === undefined || nonce.length > 128) {
        return undefined
      }

      const cipher = createDecipheriv(name, secret, nonce, { authTagLength: tag.length })
      cipher.setAAD(aad)
      cipher.setAuthTag(tag)

      const output = cipher.update(data)

      try {
        return concat(output, cipher.final())
      } catch {
        output.fill(0)
        throw new AuthenticationError('GCM authentication failed')
      }
    },
  }
}

function integerBase64Url(value: bigint): string {
  const hex = value.toString(16)

  return Buffer.from(hex.length % 2 ? `0${hex}` : hex, 'hex').toString('base64url')
}

function createRsaKey(key: NativeRsaKey): KeyObject | undefined {
  if (key.n < (1n << 511n)) {
    return undefined
  }

  const jwk = rsaJwk(key, integerBase64Url)

  if (jwk === undefined) {
    return undefined
  }

  return key.d === undefined
    ? createPublicKey({ key: jwk, format: 'jwk' })
    : createPrivateKey({ key: jwk, format: 'jwk' })
}

export function nativeOaep(
  key: NativeRsaKey,
  hash: string,
  label: Uint8Array,
): NativeOaep {
  const prepare = lazy(() => supportsHash(hash) ? createRsaKey(key) : undefined)

  return {
    async encrypt(data) {
      const secret = prepare()

      if (secret === undefined) {
        return undefined
      }

      return new Uint8Array(publicEncrypt({
        key: secret,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: hash,
        oaepLabel: label,
      }, data))
    },

    async decrypt(data) {
      const secret = prepare()

      if (secret === undefined) {
        return undefined
      }

      try {
        return new Uint8Array(privateDecrypt({
          key: secret,
          padding: constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: hash,
          oaepLabel: label,
        }, data))
      } catch (error) {
        if (
          error !== null &&
          typeof error === 'object' &&
          'code' in error &&
          (
            error.code === 'ERR_OSSL_RSA_OAEP_DECODING_ERROR' ||
            error.code === 'ERR_OSSL_OAEP_DECODING_ERROR'
          )
        ) {
          throw new AuthenticationError('RSA-OAEP decryption failed')
        }

        throw error
      }
    },
  }
}

export function nativeRsaPublic(
  n: bigint,
  e: bigint,
  data: Uint8Array,
): Uint8Array | undefined {
  const key = createRsaKey({ n, e })

  return key === undefined ? undefined : new Uint8Array(
    publicEncrypt({ key, padding: constants.RSA_NO_PADDING }, data),
  )
}

export function nativeRsaPrivate(
  n: bigint,
  d: bigint,
  p: bigint,
  q: bigint,
  data: Uint8Array,
): Uint8Array | undefined {
  const key = createRsaKey({ n, d, p, q })

  return key === undefined ? undefined : new Uint8Array(
    privateDecrypt({ key, padding: constants.RSA_NO_PADDING }, data),
  )
}
