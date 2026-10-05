export class CifranteError extends Error {
  constructor(message: string) {
    super(message)
    this.name = new.target.name
  }
}

export class InvalidInputError extends CifranteError {}

export class UnsupportedError extends CifranteError {}

export class InvalidKeyError extends CifranteError {}

export class InvalidIVError extends CifranteError {}

export class InvalidNonceError extends CifranteError {}

export class AuthenticationError extends CifranteError {}
