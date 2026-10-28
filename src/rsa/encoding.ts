import { bytesToBigInt, decodeBase64, decodeBase64Url, toBinaryView } from '../bytes.js'
import { DerReader, TAG } from '../der.js'
import { InvalidInputError, InvalidKeyError, UnsupportedError } from '../errors.js'
import type { Binary } from '../types.js'
import type { RsaPrivateKey, RsaPublicKey } from './rsa.js'

export interface RsaJsonWebKey {
  kty?: string
  use?: string
  key_ops?: string[]
  alg?: string
  kid?: string
  ext?: boolean
  n?: string
  e?: string
  d?: string
  p?: string
  q?: string
  dp?: string
  dq?: string
  qi?: string
}

export type RsaKeyInput = string | Binary | RsaJsonWebKey

type Parser<T> = (der: Uint8Array) => T

const RSA_ALGORITHMS = new Set([
  '1.2.840.113549.1.1.1',
  '1.2.840.113549.1.1.10',
])

function algorithm(reader: DerReader): void {
  if (!RSA_ALGORITHMS.has(reader.sequence().oid())) {
    throw new UnsupportedError('Only RSA keys are supported')
  }
}

function pkcs1Public(der: Uint8Array): RsaPublicKey {
  const outer = new DerReader(der)
  const key = outer.sequence()
  const n = key.integer()
  const e = key.integer()

  key.end()
  outer.end()

  return { n, e }
}

function spkiPublic(der: Uint8Array): RsaPublicKey {
  const outer = new DerReader(der)
  const info = outer.sequence()

  algorithm(info)

  const key = info.bitString()

  info.end()
  outer.end()

  return pkcs1Public(key)
}

function pkcs1Private(der: Uint8Array): RsaPrivateKey {
  const outer = new DerReader(der)
  const key = outer.sequence()

  if (key.integer() !== 0n) {
    throw new UnsupportedError('Multi-prime RSA keys are not supported')
  }

  const n = key.integer()
  key.integer()
  const d = key.integer()
  const p = key.integer()
  const q = key.integer()

  outer.end()

  return { n, d, p, q }
}

function pkcs8Private(der: Uint8Array): RsaPrivateKey {
  const outer = new DerReader(der)
  const info = outer.sequence()

  if (info.integer() > 1n) {
    throw new UnsupportedError('Unsupported PKCS#8 version')
  }

  algorithm(info)

  const key = info.read(TAG.octetString)

  outer.end()

  return pkcs1Private(key)
}

function pem(input: string): { label: string, der: Uint8Array } {
  const match = /^\s*-----BEGIN ([A-Z0-9 ]+)-----([A-Za-z0-9+/=\s]*)-----END \1-----\s*$/.exec(input)

  if (!match) {
    throw new InvalidKeyError('Expected a single PEM block')
  }

  return { label: match[1], der: decodeBase64(match[2].replace(/\s+/g, '')) }
}

function jwkInteger(value: unknown): bigint {
  if (typeof value !== 'string') {
    throw new InvalidKeyError('Expected a base64url-encoded JWK integer')
  }

  return bytesToBigInt(decodeBase64Url(value))
}

function decode<T>(
  input: RsaKeyInput,
  pemLabels: Record<string, Parser<T>>,
  derFormats: Parser<T>[],
  jwk: (key: RsaJsonWebKey) => T,
): T {
  if (typeof input === 'string') {
    const { label, der } = pem(input)
    const parse = pemLabels[label]

    if (!parse) {
      throw new InvalidKeyError(`Unexpected PEM label: ${label}`)
    }

    return parse(der)
  }

  if (input instanceof ArrayBuffer || ArrayBuffer.isView(input)) {
    const der = toBinaryView(input)

    for (const parse of derFormats.slice(0, -1)) {
      try {
        return parse(der)
      } catch (error) {
        if (!(error instanceof InvalidInputError)) {
          throw error
        }
      }
    }

    return derFormats[derFormats.length - 1](der)
  }

  if (input !== null && typeof input === 'object') {
    if (input.kty !== 'RSA') {
      throw new UnsupportedError('Only RSA JSON Web Keys are supported')
    }

    return jwk(input)
  }

  throw new InvalidKeyError('Expected a PEM string, DER bytes or a JSON Web Key')
}

function invalidKey<T>(parse: () => T): T {
  try {
    return parse()
  } catch (error) {
    if (error instanceof InvalidInputError) {
      throw new InvalidKeyError(`Invalid RSA key encoding: ${error.message}`)
    }

    throw error
  }
}

export function decodePublicKey(input: RsaKeyInput): RsaPublicKey {
  return invalidKey(() => decode(
    input,
    { 'PUBLIC KEY': spkiPublic, 'RSA PUBLIC KEY': pkcs1Public },
    [spkiPublic, pkcs1Public],
    ({ n, e }) => ({ n: jwkInteger(n), e: jwkInteger(e) }),
  ))
}

export function decodePrivateKey(input: RsaKeyInput): RsaPrivateKey {
  return invalidKey(() => decode(
    input,
    { 'PRIVATE KEY': pkcs8Private, 'RSA PRIVATE KEY': pkcs1Private },
    [pkcs8Private, pkcs1Private],
    ({ n, d, p, q }) => p === undefined && q === undefined
      ? { n: jwkInteger(n), d: jwkInteger(d) }
      : { n: jwkInteger(n), d: jwkInteger(d), p: jwkInteger(p), q: jwkInteger(q) },
  ))
}
