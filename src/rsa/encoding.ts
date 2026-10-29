import { bigIntToBytes, bytesToBigInt, decodeBase64, decodeBase64Url, encodeBase64, encodeBase64Url, toBinaryView } from '../bytes.js'
import { DerReader, TAG, derBitString, derInteger, derNull, derOctetString, derOid, derSequence } from '../der.js'
import { InvalidInputError, InvalidKeyError, UnsupportedError } from '../errors.js'
import type { Binary } from '../types.js'
import { math } from '../math.js'
import { inverseMod } from './key.js'
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

export type RsaKeyFormat = 'pem' | 'der' | 'jwk'

export type RsaKeyType = 'spki' | 'pkcs1' | 'pkcs8'

export interface RsaEncodeOptions {
  format: RsaKeyFormat
  type?: RsaKeyType
}

const RSA_ENCRYPTION = '1.2.840.113549.1.1.1'

function pemOf(label: string, der: Uint8Array): string {
  const body = encodeBase64(der).match(/.{1,64}/g) ?? []

  return `-----BEGIN ${label}-----\n${body.join('\n')}\n-----END ${label}-----\n`
}

function algorithmIdentifier(): Uint8Array {
  return derSequence(derOid(RSA_ENCRYPTION), derNull())
}

function privateParts(key: RsaPrivateKey): RsaPrivateKey & { e: bigint, p: bigint, q: bigint } {
  if (key.p === undefined || key.q === undefined) {
    throw new InvalidKeyError('Encoding an RSA private key requires its prime factors')
  }

  const lambda = (key.p - 1n) / math.gcd(key.p - 1n, key.q - 1n) * (key.q - 1n)

  return { ...key, e: inverseMod(key.d, lambda), p: key.p, q: key.q }
}

function jwkOf(key: RsaPublicKey | RsaPrivateKey): RsaJsonWebKey {
  const integer = (value: bigint): string => encodeBase64Url(bigIntToBytes(value))

  if (!('d' in key)) {
    return { kty: 'RSA', n: integer(key.n), e: integer(key.e) }
  }

  const { n, e, d, p, q } = privateParts(key)

  return {
    kty: 'RSA',
    n: integer(n),
    e: integer(e),
    d: integer(d),
    p: integer(p),
    q: integer(q),
    dp: integer(d % (p - 1n)),
    dq: integer(d % (q - 1n)),
    qi: integer(inverseMod(q, p)),
  }
}

function derOf(key: RsaPublicKey | RsaPrivateKey, type: RsaKeyType): { label: string, der: Uint8Array } {
  if (!('d' in key)) {
    const pkcs1 = derSequence(derInteger(key.n), derInteger(key.e))

    switch (type) {
      case 'spki':
        return { label: 'PUBLIC KEY', der: derSequence(algorithmIdentifier(), derBitString(pkcs1)) }
      case 'pkcs1':
        return { label: 'RSA PUBLIC KEY', der: pkcs1 }
      default:
        throw new InvalidInputError('RSA public keys encode as spki or pkcs1')
    }
  }

  const { n, e, d, p, q } = privateParts(key)
  const pkcs1 = derSequence(
    derInteger(0n),
    derInteger(n),
    derInteger(e),
    derInteger(d),
    derInteger(p),
    derInteger(q),
    derInteger(d % (p - 1n)),
    derInteger(d % (q - 1n)),
    derInteger(inverseMod(q, p)),
  )

  switch (type) {
    case 'pkcs8':
      return { label: 'PRIVATE KEY', der: derSequence(derInteger(0n), algorithmIdentifier(), derOctetString(pkcs1)) }
    case 'pkcs1':
      return { label: 'RSA PRIVATE KEY', der: pkcs1 }
    default:
      throw new InvalidInputError('RSA private keys encode as pkcs8 or pkcs1')
  }
}

export function encodeKey(key: RsaPublicKey | RsaPrivateKey, options: RsaEncodeOptions): string | Uint8Array | RsaJsonWebKey {
  if (!options || typeof options !== 'object') {
    throw new InvalidInputError('RSA key encoding requires a format')
  }

  const type = options.type ?? ('d' in key ? 'pkcs8' : 'spki')

  switch (options.format) {
    case 'jwk':
      return jwkOf(key)
    case 'der':
      return derOf(key, type).der
    case 'pem': {
      const { label, der } = derOf(key, type)
      return pemOf(label, der)
    }
    default:
      throw new InvalidInputError('RSA key format must be pem, der or jwk')
  }
}
