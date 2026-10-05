import { random } from './random.js'
import { bytes } from './bytes.js'
import { md5 } from './hash/md5.js'
import { sha1 } from './hash/sha1.js'
import { sha256 } from './hash/sha256.js'
import { sha512 } from './hash/sha512.js'
import {
  CifranteError,
  InvalidInputError,
  UnsupportedError,
  InvalidKeyError,
  InvalidIVError,
  InvalidNonceError,
  AuthenticationError,
} from './errors.js'

export { random, bytes, md5, sha1, sha256, sha512 }

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

export default {
  random,
  bytes,
  md5,
  sha1,
  sha256,
  sha512,
  CifranteError,
  InvalidInputError,
  UnsupportedError,
  InvalidKeyError,
  InvalidIVError,
  InvalidNonceError,
  AuthenticationError,
}
