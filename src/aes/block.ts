import { toBinary } from '../bytes.js'
import { InvalidInputError, InvalidIVError, InvalidKeyError } from '../errors.js'
import type { Binary } from '../types.js'
import type { CipherOptions } from './aes.js'

function multiply(a: number, b: number): number {
  let result = 0

  for (let bit = 0; bit < 8; bit++) {
    result ^= a & -(b & 1)
    a = ((a << 1) ^ (0x11b & -(a >>> 7))) & 255
    b >>>= 1
  }

  return result
}

let sbox: Uint8Array<ArrayBuffer>
let inverseSbox: Uint8Array<ArrayBuffer>

function initializeTables(): void {
  if (sbox !== undefined) {
    return
  }

  const forward = new Uint8Array(256)
  const reverse = new Uint8Array(256)

  for (let value = 0; value < 256; value++) {
    let inverse = 1
    let power = value

    for (let exponent = 254; exponent > 0; exponent >>>= 1) {
      if (exponent & 1) {
        inverse = multiply(inverse, power)
      }

      power = multiply(power, power)
    }

    let substituted = inverse ^ 0x63

    for (let shift = 1; shift <= 4; shift++) {
      substituted ^= ((inverse << shift) | (inverse >>> (8 - shift))) & 255
    }

    forward[value] = substituted
    reverse[substituted] = value
  }

  inverseSbox = reverse
  sbox = forward
}

export function keyBytes(key: Binary): Uint8Array<ArrayBuffer> {
  let bytes: Uint8Array<ArrayBuffer>

  try {
    bytes = toBinary(key)
  } catch (error) {
    if (error instanceof InvalidInputError) {
      throw new InvalidKeyError('AES key must be binary data')
    }

    throw error
  }

  if (bytes.length !== 16 && bytes.length !== 24 && bytes.length !== 32) {
    throw new InvalidKeyError('AES key must contain 16, 24 or 32 bytes')
  }

  return bytes
}

export function ivBytes(options: CipherOptions, length: number): Uint8Array<ArrayBuffer> {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new InvalidInputError('AES operation requires IV options')
  }

  let bytes: Uint8Array<ArrayBuffer>

  try {
    bytes = toBinary(options.iv)
  } catch (error) {
    if (error instanceof InvalidInputError) {
      throw new InvalidIVError('AES IV must be binary data')
    }

    throw error
  }

  if (bytes.length !== length) {
    throw new InvalidIVError(`AES IV must contain ${length} bytes`)
  }

  return bytes
}

export class AesBlock {
  private readonly rounds: number
  private readonly schedule: Uint8Array<ArrayBuffer>

  constructor(key: Uint8Array) {
    initializeTables()

    this.rounds = key.length / 4 + 6
    this.schedule = new Uint8Array((this.rounds + 1) * 16)
    this.schedule.set(key)

    const word = new Uint8Array(4)
    let rcon = 1

    for (let offset = key.length; offset < this.schedule.length; offset += 4) {
      word.set(this.schedule.subarray(offset - 4, offset))

      if (offset % key.length === 0) {
        const first = word[0]
        word[0] = sbox[word[1]] ^ rcon
        word[1] = sbox[word[2]]
        word[2] = sbox[word[3]]
        word[3] = sbox[first]
        rcon = multiply(rcon, 2)
      } else if (key.length === 32 && offset % key.length === 16) {
        for (let i = 0; i < 4; i++) {
          word[i] = sbox[word[i]]
        }
      }

      for (let i = 0; i < 4; i++) {
        this.schedule[offset + i] = this.schedule[offset + i - key.length] ^ word[i]
      }
    }
  }

  encrypt(input: Uint8Array): Uint8Array<ArrayBuffer> {
    const state = new Uint8Array(input)
    this.addRoundKey(state, 0)

    for (let round = 1; round <= this.rounds; round++) {
      for (let i = 0; i < 16; i++) {
        state[i] = sbox[state[i]]
      }

      this.shiftRows(state, false)

      if (round < this.rounds) {
        this.mixColumns(state, false)
      }

      this.addRoundKey(state, round)
    }

    return state
  }

  decrypt(input: Uint8Array): Uint8Array<ArrayBuffer> {
    const state = new Uint8Array(input)
    this.addRoundKey(state, this.rounds)

    for (let round = this.rounds - 1; round >= 0; round--) {
      this.shiftRows(state, true)

      for (let i = 0; i < 16; i++) {
        state[i] = inverseSbox[state[i]]
      }

      this.addRoundKey(state, round)

      if (round > 0) {
        this.mixColumns(state, true)
      }
    }

    return state
  }

  private addRoundKey(state: Uint8Array, round: number): void {
    for (let i = 0; i < 16; i++) {
      state[i] ^= this.schedule[round * 16 + i]
    }
  }

  private shiftRows(state: Uint8Array, inverse: boolean): void {
    const copy = state.slice()

    for (let row = 1; row < 4; row++) {
      for (let column = 0; column < 4; column++) {
        const source = (column + (inverse ? 4 - row : row)) % 4
        state[column * 4 + row] = copy[source * 4 + row]
      }
    }
  }

  private mixColumns(state: Uint8Array, inverse: boolean): void {
    for (let offset = 0; offset < 16; offset += 4) {
      let a = state[offset],
        b = state[offset + 1],
        c = state[offset + 2],
        d = state[offset + 3]

      if (inverse) {
        const ac = multiply(a ^ c, 4)
        const bd = multiply(b ^ d, 4)
        a ^= ac
        c ^= ac
        b ^= bd
        d ^= bd
      }

      const total = a ^ b ^ c ^ d
      state[offset] = a ^ total ^ multiply(a ^ b, 2)
      state[offset + 1] = b ^ total ^ multiply(b ^ c, 2)
      state[offset + 2] = c ^ total ^ multiply(c ^ d, 2)
      state[offset + 3] = d ^ total ^ multiply(d ^ a, 2)
    }
  }
}
