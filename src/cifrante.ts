import { random } from './random.js'
import { bytes } from './bytes.js'
import { md5 } from './hash/md5.js'
import { sha1 } from './hash/sha1.js'
import { sha256 } from './hash/sha256.js'
import { sha512 } from './hash/sha512.js'
import { aes } from './aes/aes.js'
import { hmac } from './hmac.js'
import { kdf } from './kdf.js'
import {
  CifranteError,
  InvalidInputError,
  UnsupportedError,
  InvalidKeyError,
  InvalidIVError,
  InvalidNonceError,
  AuthenticationError,
} from './errors.js'

export { random, bytes, md5, sha1, sha256, sha512, aes, hmac, kdf }

export {
  CifranteError,
  InvalidInputError,
  UnsupportedError,
  InvalidKeyError,
  InvalidIVError,
  InvalidNonceError,
  AuthenticationError,
}

export type { Bytes, Binary, Data } from './types.js'
export type { Random } from './random.js'
export type { Codec, Utf8Codec, BytesAPI } from './bytes.js'
export type { Hash, HashState } from './hash/hash.js'
export type { AES, Cipher, CipherOptions } from './aes/aes.js'
export type { GcmOptions, GcmOperationOptions, Sealed, AeadCipher } from './aes/gcm.js'
export type { Hmac, HmacState, HMAC } from './hmac.js'
export type { HashName, Pbkdf2Options, HkdfOptions, KDF } from './kdf.js'

export default {
  random,
  bytes,
  md5,
  sha1,
  sha256,
  sha512,
  aes,
  hmac,
  kdf,
  CifranteError,
  InvalidInputError,
  UnsupportedError,
  InvalidKeyError,
  InvalidIVError,
  InvalidNonceError,
  AuthenticationError,
}
