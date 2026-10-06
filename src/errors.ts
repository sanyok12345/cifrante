export class CifranteError extends Error {
  name = 'CifranteError'

  constructor(message: string) {
    super(message)
  }
}

export class InvalidInputError extends CifranteError {
  name = 'InvalidInputError'
}

export class UnsupportedError extends CifranteError {
  name = 'UnsupportedError'
}

export class InvalidKeyError extends CifranteError {
  name = 'InvalidKeyError'
}

export class InvalidIVError extends CifranteError {
  name = 'InvalidIVError'
}

export class InvalidNonceError extends CifranteError {
  name = 'InvalidNonceError'
}

export class AuthenticationError extends CifranteError {
  name = 'AuthenticationError'
}
