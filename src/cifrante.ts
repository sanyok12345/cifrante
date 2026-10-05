import { random } from './random.js'
import { bytes } from './bytes.js'
import {
  CifranteError,
  InvalidInputError,
  UnsupportedError,
  InvalidKeyError,
  InvalidIVError,
  InvalidNonceError,
  AuthenticationError,
} from './errors.js'

export { random, bytes }

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

export default {
  random,
  bytes,
  CifranteError,
  InvalidInputError,
  UnsupportedError,
  InvalidKeyError,
  InvalidIVError,
  InvalidNonceError,
  AuthenticationError,
}
