import { bigIntToBytes, encodeBase64 } from '../bytes.js'
import { AuthenticationError, UnsupportedError } from '../errors.js'
import { lazy } from '../lazy.js'
import { rsaJwk } from '../rsa-key.js'
import type {
  NativeAead,
  NativeCipher,
  NativeHash,
  NativeOaep,
  NativeRsaKey,
} from './types.js'

export type { NativeHash, NativeSealed } from './types.js'

type WebKey = { subtle: SubtleCrypto; key: CryptoKey }

let unsupported: WeakMap<SubtleCrypto, Set<string>> | undefined

function source(data: Uint8Array): Uint8Array<ArrayBuffer> {
  return data as Uint8Array<ArrayBuffer>
}

function errorName(error: unknown): unknown {
  return error !== null && typeof error === 'object' && 'name' in error
    ? error.name
    : undefined
}

function hashName(name: string): string | undefined {
  switch (name) {
    case 'sha1':
      return 'SHA-1'
    case 'sha256':
      return 'SHA-256'
    case 'sha512':
      return 'SHA-512'
    default:
      return undefined
  }
}

async function supported<T>(
  subtle: SubtleCrypto,
  capability: string,
  operation: () => Promise<T>,
  unavailable?: (error: unknown) => boolean,
): Promise<T | undefined> {
  if (unsupported?.get(subtle)?.has(capability)) {
    return undefined
  }

  try {
    return await operation()
  } catch (error) {
    if (errorName(error) !== 'NotSupportedError' && !unavailable?.(error)) {
      throw error
    }

    unsupported ??= new WeakMap()
    let capabilities = unsupported.get(subtle)

    if (!capabilities) {
      capabilities = new Set()
      unsupported.set(subtle, capabilities)
    }

    capabilities.add(capability)
    return undefined
  }
}

function aesKey(name: string, secret: Uint8Array): () => Promise<WebKey | undefined> {
  return lazy(async () => {
    const subtle = globalThis.crypto?.subtle

    if (!subtle) {
      return undefined
    }

    const key = await supported(
      subtle,
      `${name}:key:${secret.length}`,
      () => subtle.importKey('raw', source(secret), name, false, ['encrypt', 'decrypt']),
      error => secret.length === 24 &&
        errorName(error) === 'OperationError' &&
        (error as { message?: unknown }).message === '192-bit AES keys are not supported',
    )

    return key ? { subtle, key } : undefined
  })
}

async function decrypt(
  context: WebKey,
  algorithm: AesCbcParams | AesCtrParams | AesGcmParams | RsaOaepParams,
  data: Uint8Array,
  capability: string,
  authentication?: string,
  unavailable?: (error: unknown) => boolean,
): Promise<Uint8Array | undefined> {
  const { subtle, key } = context

  try {
    const output = await supported(
      subtle,
      capability,
      () => subtle.decrypt(algorithm, key, source(data)),
      unavailable,
    )

    return output === undefined ? undefined : new Uint8Array(output)
  } catch (error) {
    if (authentication && errorName(error) === 'OperationError') {
      throw new AuthenticationError(authentication)
    }

    throw error
  }
}

export function fillRandom(bytes: Uint8Array<ArrayBuffer>): void {
  const crypto = globalThis.crypto

  if (typeof crypto?.getRandomValues !== 'function') {
    throw new UnsupportedError('A cryptographically secure random generator is unavailable')
  }

  for (let offset = 0; offset < bytes.length; offset += 65_536) {
    crypto.getRandomValues(bytes.subarray(offset, offset + 65_536))
  }
}

export function nativeHash(_name: string): NativeHash | undefined {
  return undefined
}

export function nativeHmac(_name: string, _key: Uint8Array): NativeHash | undefined {
  return undefined
}

export function nativeEqual(_a: Uint8Array, _b: Uint8Array): boolean | undefined {
  return undefined
}

export function nativeDigestSync(_name: string, _data: Uint8Array): Uint8Array | undefined {
  return undefined
}

export function nativeDigestAvailable(name: string): boolean {
  const hash = hashName(name)
  const subtle = globalThis.crypto?.subtle

  return !!hash && !!subtle && !unsupported?.get(subtle)?.has(`digest:${hash}`)
}

export function nativeMacAvailable(name: string, secret: Uint8Array): boolean {
  const hash = hashName(name)
  const subtle = globalThis.crypto?.subtle

  return !!hash && !!subtle && secret.length > 0 && !unsupported?.get(subtle)?.has(`HMAC:${hash}`)
}

export async function nativeDigest(
  name: string,
  data: Uint8Array,
): Promise<Uint8Array | undefined> {
  const hash = hashName(name)
  const subtle = globalThis.crypto?.subtle

  if (!hash || !subtle) {
    return undefined
  }

  const output = await supported(subtle, `digest:${hash}`, () =>
    subtle.digest(hash, source(data)),
  )

  return output === undefined ? undefined : new Uint8Array(output)
}

export async function nativeMac(
  name: string,
  secret: Uint8Array,
  data: Uint8Array,
): Promise<Uint8Array | undefined> {
  const hash = hashName(name)
  const subtle = globalThis.crypto?.subtle

  if (!hash || !subtle || !secret.length) {
    return undefined
  }

  const output = await supported(subtle, `HMAC:${hash}`, async () => {
    const key = await subtle.importKey('raw', source(secret), { name: 'HMAC', hash }, false, ['sign'])
    return subtle.sign('HMAC', key, source(data))
  })

  return output === undefined ? undefined : new Uint8Array(output)
}

async function derive(
  secret: Uint8Array,
  algorithm: Pbkdf2Params | HkdfParams,
  length: number,
): Promise<Uint8Array | undefined> {
  const subtle = globalThis.crypto?.subtle

  if (!subtle || length > 0x1fffffff) {
    return undefined
  }

  if (!length) {
    return new Uint8Array()
  }

  const output = await supported(subtle, `${algorithm.name}:${algorithm.hash}`, async () => {
    const key = await subtle.importKey('raw', source(secret), algorithm.name, false, ['deriveBits'])
    return subtle.deriveBits(algorithm, key, length * 8)
  })

  return output === undefined ? undefined : new Uint8Array(output)
}

export async function nativePbkdf2(
  name: string,
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  length: number,
): Promise<Uint8Array | undefined> {
  const hash = hashName(name)

  if (!hash || iterations > 0x7fffffff) {
    return undefined
  }

  return derive(password, { name: 'PBKDF2', hash, salt: source(salt), iterations }, length)
}

export async function nativeHkdf(
  name: string,
  input: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array | undefined> {
  const hash = hashName(name)

  if (!hash || info.length > 1024) {
    return undefined
  }

  return derive(input, { name: 'HKDF', hash, salt: source(salt), info: source(info) }, length)
}

export function nativeCipher(mode: 'cbc' | 'ctr', secret: Uint8Array): NativeCipher {
  const name = mode === 'cbc' ? 'AES-CBC' : 'AES-CTR'
  const prepare = aesKey(name, secret)

  function parameters(iv: Uint8Array): AesCbcParams | AesCtrParams {
    return mode === 'cbc'
      ? { name, iv: source(iv) }
      : { name, counter: source(iv), length: 128 }
  }

  return {
    available() {
      const subtle = globalThis.crypto?.subtle

      return !!subtle && !unsupported?.get(subtle)?.has(`${name}:key:${secret.length}`)
    },

    async encrypt(iv, data) {
      const context = await prepare()

      if (!context) {
        return undefined
      }

      const { subtle, key } = context
      const output = await supported(subtle, `${name}:encrypt:${secret.length}`, () =>
        subtle.encrypt(parameters(iv), key, source(data)),
      )

      return output === undefined ? undefined : new Uint8Array(output)
    },

    async decrypt(iv, data) {
      const context = await prepare()

      if (!context) {
        return undefined
      }

      return decrypt(
        context,
        parameters(iv),
        data,
        `${name}:decrypt:${secret.length}`,
        mode === 'cbc' ? 'Invalid AES-CBC padding' : undefined,
      )
    },

    async encryptBlocks(iv, data) {
      if (mode !== 'cbc' || data.length % 16 !== 0) {
        return undefined
      }

      const context = await prepare()

      if (!context) {
        return undefined
      }

      const { subtle, key } = context
      const output = await supported(subtle, `${name}:encrypt:${secret.length}`, () =>
        subtle.encrypt(parameters(iv), key, source(data)),
      )

      return output === undefined ? undefined : new Uint8Array(output, 0, data.length)
    },
  }
}

export function nativeGcm(secret: Uint8Array): NativeAead {
  const prepare = aesKey('AES-GCM', secret)

  function parameters(nonce: Uint8Array, aad: Uint8Array, tagLength: number): AesGcmParams {
    return {
      name: 'AES-GCM',
      iv: source(nonce),
      additionalData: source(aad),
      tagLength: tagLength * 8,
    }
  }

  return {
    available(nonce) {
      const subtle = globalThis.crypto?.subtle

      return !!subtle && nonce.length >= 12 && nonce.length <= 128
        && !unsupported?.get(subtle)?.has(`AES-GCM:key:${secret.length}`)
    },

    async encrypt(nonce, data, aad, tagLength) {
      if (nonce.length < 12 || nonce.length > 128) {
        return undefined
      }

      const context = await prepare()

      if (!context) {
        return undefined
      }

      const { subtle, key } = context
      const output = await supported(subtle, `AES-GCM:encrypt:${secret.length}:${tagLength}`, () =>
        subtle.encrypt(parameters(nonce, aad, tagLength), key, source(data)),
      )

      if (output === undefined) {
        return undefined
      }

      const sealed = new Uint8Array(output)
      const length = sealed.length - tagLength

      return { ciphertext: sealed.slice(0, length), tag: sealed.slice(length) }
    },

    async decrypt(nonce, data, aad, tag) {
      if (nonce.length < 12 || nonce.length > 128) {
        return undefined
      }

      const context = await prepare()

      if (!context) {
        return undefined
      }

      const sealed = new Uint8Array(data.length + tag.length)
      sealed.set(data)
      sealed.set(tag, data.length)

      return decrypt(
        context,
        parameters(nonce, aad, tag.length),
        sealed,
        `AES-GCM:decrypt:${secret.length}:${tag.length}`,
        'GCM authentication failed',
        error => tag.length < 16 &&
          errorName(error) === 'TypeError' &&
          (error as { message?: unknown }).message === 'invalid tag length',
      )
    },
  }
}

export function nativeRsaPublic(
  _n: bigint,
  _e: bigint,
  _data: Uint8Array,
): Uint8Array | undefined {
  return undefined
}

export function nativeRsaPrivate(
  _n: bigint,
  _d: bigint,
  _p: bigint,
  _q: bigint,
  _data: Uint8Array,
): Uint8Array | undefined {
  return undefined
}

function integerBase64Url(value: bigint): string {
  return encodeBase64(bigIntToBytes(value))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

function supportsRsaLabel(label: Uint8Array): boolean {
  if (!label.length || !Reflect.has(globalThis, 'Deno')) {
    return true
  }

  if (typeof TextDecoder !== 'function') {
    return false
  }

  try {
    new TextDecoder('utf-8', { fatal: true }).decode(source(label))
    return true
  } catch {
    return false
  }
}

export function nativeOaep(
  key: NativeRsaKey,
  name: string,
  label: Uint8Array,
): NativeOaep {
  const hash = hashName(name)
  const prepare = lazy(async (): Promise<WebKey | undefined> => {
    const subtle = globalThis.crypto?.subtle

    if (!hash || !subtle || key.n < (1n << 511n) || !supportsRsaLabel(label)) {
      return undefined
    }

    const jwk = rsaJwk(key, integerBase64Url)

    if (!jwk) {
      return undefined
    }

    const imported = await supported(subtle, `RSA-OAEP:key:${hash}:${key.d === undefined}`, () =>
      subtle.importKey(
        'jwk',
        jwk,
        { name: 'RSA-OAEP', hash },
        false,
        [key.d === undefined ? 'encrypt' : 'decrypt'],
      ),
    )

    return imported ? { subtle, key: imported } : undefined
  })
  const algorithm = { name: 'RSA-OAEP', label: source(label) }

  return {
    async encrypt(data) {
      const context = await prepare()

      if (!context) {
        return undefined
      }

      const { subtle, key: imported } = context
      const output = await supported(subtle, `RSA-OAEP:encrypt:${hash}`, () =>
        subtle.encrypt(algorithm, imported, source(data)),
      )

      return output === undefined ? undefined : new Uint8Array(output)
    },

    async decrypt(data) {
      const context = await prepare()

      if (!context) {
        return undefined
      }

      return decrypt(context, algorithm, data, `RSA-OAEP:decrypt:${hash}`, 'RSA-OAEP decryption failed')
    },
  }
}
