import { toBinary } from '../bytes.js'
import { InvalidKeyError } from '../errors.js'
import { nativeX25519Public, nativeX25519Shared } from '../native/web.js'
import { random } from '../random.js'
import type { Binary } from '../types.js'
import { scalarMultWasm } from '../wasm/x25519.js'
import { scalarMult } from './field.js'

export interface X25519KeyPair {
  privateKey: Uint8Array
  publicKey: Uint8Array
}

export interface X25519 {
  keys(): Promise<X25519KeyPair>
  publicKey(privateKey: Binary): Promise<Uint8Array>
  shared(privateKey: Binary, publicKey: Binary): Promise<Uint8Array>
}

const BASE = /* @__PURE__ */ new Uint8Array(32).fill(9, 0, 1)

function key(value: Binary, name: string): Uint8Array<ArrayBuffer> {
  const bytes = toBinary(value)

  if (bytes.length !== 32) {
    bytes.fill(0)
    throw new InvalidKeyError(`X25519 ${name} key must be 32 bytes`)
  }

  return bytes
}

function multiply(scalar: Uint8Array, point: Uint8Array): Uint8Array {
  return scalarMultWasm(scalar, point) ?? scalarMult(scalar, point)
}

async function publicKey(privateKey: Binary): Promise<Uint8Array> {
  const secret = key(privateKey, 'private')

  try {
    return await nativeX25519Public(secret) ?? multiply(secret, BASE)
  } finally {
    secret.fill(0)
  }
}

async function shared(privateKey: Binary, publicKey: Binary): Promise<Uint8Array> {
  const secret = key(privateKey, 'private')
  const peer = key(publicKey, 'public')

  try {
    const output = await nativeX25519Shared(secret, peer) ?? multiply(secret, peer)
    let difference = 0

    for (const byte of output) {
      difference |= byte
    }

    if (difference === 0) {
      throw new InvalidKeyError('X25519 public key produces an all-zero shared secret')
    }

    return output
  } finally {
    secret.fill(0)
  }
}

async function keys(): Promise<X25519KeyPair> {
  const privateKey = random(32)

  return { privateKey, publicKey: await publicKey(privateKey) }
}

export const x25519: X25519 = { keys, publicKey, shared }
