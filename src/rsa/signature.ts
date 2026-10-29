import { bytesToBigInt, toBinary, toBytesView } from '../bytes.js'
import { derNull, derOctetString, derOid, derSequence } from '../der.js'
import { InvalidInputError, InvalidKeyError } from '../errors.js'
import type { HashName } from '../kdf.js'
import { nativeRsaSignature } from '../native/web.js'
import { random } from '../random.js'
import type { Binary, Data } from '../types.js'
import { checkKey, digest, mgf1, operate, xorInto } from './core.js'
import type { CheckedKey } from './core.js'
import type { RsaPrivateKey, RsaPublicKey } from './rsa.js'

export type RsaScheme = 'pkcs1' | 'pss'

export interface RsaSignatureOptions {
  hash?: HashName
}

export interface RsaPssOptions extends RsaSignatureOptions {
  saltLength?: number
}

export interface RsaSignature {
  sign(message: Data): Promise<Uint8Array>
  verify(message: Data, signature: Binary): Promise<boolean>
  signSync(message: Data): Uint8Array
  verifySync(message: Data, signature: Binary): boolean
}

const DIGEST_OIDS: Record<HashName, string> = {
  sha1: '1.3.14.3.2.26',
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
}

function bitLength(value: bigint): number {
  return value.toString(2).length
}

function same(a: Uint8Array, b: Uint8Array): boolean {
  let difference = a.length ^ b.length

  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    difference |= a[i] ^ b[i]
  }

  return difference === 0
}

function nativeKey(checked: CheckedKey) {
  return checked.private
    ? { n: checked.n, d: checked.exponent, p: checked.p, q: checked.q }
    : { n: checked.n, e: checked.exponent }
}

export function signature(scheme: RsaScheme, key: RsaPublicKey | RsaPrivateKey, options: RsaPssOptions = {}): RsaSignature {
  if (!options || typeof options !== 'object') {
    throw new InvalidInputError('Invalid RSA signature options')
  }

  const algorithm = scheme === 'pss' ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5'
  const checked = checkKey(key)
  const { name, hash, length: hLength } = digest(options.hash, algorithm)
  const saltLength = options.saltLength ?? hLength
  const modulusBits = bitLength(checked.n)
  const emBits = modulusBits - 1
  const emLength = Math.ceil(emBits / 8)
  const length = checked.length

  if (scheme === 'pss') {
    if (!Number.isSafeInteger(saltLength) || saltLength < 0) {
      throw new InvalidInputError('RSA-PSS saltLength must be a non-negative safe integer')
    }

    if (emLength < hLength + saltLength + 2) {
      throw new InvalidKeyError('RSA modulus is too short for the chosen PSS hash and salt')
    }
  } else if (length < digestInfo(new Uint8Array(hLength)).length + 11) {
    throw new InvalidKeyError('RSA modulus is too short for the chosen PKCS#1 v1.5 hash')
  }

  function digestInfo(messageHash: Uint8Array): Uint8Array {
    return derSequence(derSequence(derOid(DIGEST_OIDS[name]), derNull()), derOctetString(messageHash))
  }

  function pkcs1Encoding(messageHash: Uint8Array): Uint8Array {
    const info = digestInfo(messageHash)
    const encoded = new Uint8Array(length).fill(0xff)

    encoded[0] = 0
    encoded[1] = 1
    encoded[length - info.length - 1] = 0
    encoded.set(info, length - info.length)

    return encoded
  }

  function saltedHash(messageHash: Uint8Array, salt: Uint8Array): Uint8Array {
    const prefixed = new Uint8Array(8 + hLength + salt.length)

    prefixed.set(messageHash, 8)
    prefixed.set(salt, 8 + hLength)

    return hash(prefixed)
  }

  function pssEncoding(messageHash: Uint8Array, salt: Uint8Array): Uint8Array {
    const h = saltedHash(messageHash, salt)
    const encoded = new Uint8Array(emLength)
    const db = encoded.subarray(0, emLength - hLength - 1)

    db[db.length - saltLength - 1] = 1
    db.set(salt, db.length - saltLength)
    xorInto(db, mgf1(hash, h, db.length))
    db[0] &= 0xff >>> (8 * emLength - emBits)
    encoded.set(h, emLength - hLength - 1)
    encoded[emLength - 1] = 0xbc

    return encoded
  }

  function pssVerify(messageHash: Uint8Array, recovered: Uint8Array): boolean {
    if (recovered.length > emLength && recovered[0] !== 0) {
      return false
    }

    const encoded = recovered.subarray(recovered.length - emLength)

    if (encoded[emLength - 1] !== 0xbc) {
      return false
    }

    const db = encoded.slice(0, emLength - hLength - 1)
    const h = encoded.subarray(emLength - hLength - 1, emLength - 1)
    const mask = 0xff >>> (8 * emLength - emBits)

    if (db[0] & ~mask & 0xff) {
      return false
    }

    xorInto(db, mgf1(hash, h, db.length))
    db[0] &= mask

    const separator = db.length - saltLength - 1

    for (let i = 0; i < separator; i++) {
      if (db[i] !== 0) {
        return false
      }
    }

    if (db[separator] !== 1) {
      return false
    }

    return same(h, saltedHash(messageHash, db.subarray(separator + 1)))
  }

  function signJs(message: Uint8Array): Uint8Array {
    const messageHash = hash(message)
    const encoded = scheme === 'pss' ? pssEncoding(messageHash, random(saltLength)) : pkcs1Encoding(messageHash)

    try {
      return operate(checked, bytesToBigInt(encoded))
    } finally {
      encoded.fill(0)
    }
  }

  function verifyJs(message: Uint8Array, signed: Uint8Array): boolean {
    const messageHash = hash(message)
    const recovered = operate(checked, bytesToBigInt(signed))

    return scheme === 'pss' ? pssVerify(messageHash, recovered) : same(recovered, pkcs1Encoding(messageHash))
  }

  function requirePrivate(): void {
    if (!checked.private) {
      throw new InvalidKeyError(`${algorithm} signing requires a private key`)
    }
  }

  function acceptable(signed: Uint8Array): boolean {
    if (checked.private) {
      throw new InvalidKeyError(`${algorithm} verification requires a public key`)
    }

    return signed.length === length && bytesToBigInt(signed) < checked.n
  }

  const native = nativeRsaSignature(nativeKey(checked), scheme, name, saltLength)

  return {
    async sign(message) {
      requirePrivate()

      const data = toBytesView(message)

      return await native.sign(data) ?? signJs(data)
    },

    signSync(message) {
      requirePrivate()

      const data = toBytesView(message)

      return native.signSync?.(data) ?? signJs(data)
    },

    async verify(message, signed) {
      const bytes = toBinary(signed)

      if (!acceptable(bytes)) {
        return false
      }

      const data = toBytesView(message)

      return await native.verify(data, bytes) ?? verifyJs(data, bytes)
    },

    verifySync(message, signed) {
      const bytes = toBinary(signed)

      if (!acceptable(bytes)) {
        return false
      }

      const data = toBytesView(message)

      return native.verifySync?.(data, bytes) ?? verifyJs(data, bytes)
    },
  }
}
