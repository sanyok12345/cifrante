import { toBinary } from '../bytes.js'
import { InvalidKeyError } from '../errors.js'
import {
  nativeX25519Public,
  nativeX25519PublicSync,
  nativeX25519Shared,
  nativeX25519SharedSync,
} from '../native/web.js'
import { random } from '../random.js'
import type { Binary } from '../types.js'
import { scalarMultWasm } from '../wasm/x25519.js'
import { scalarMult } from './ladder.js'

export interface X25519KeyPair {
  privateKey: Uint8Array
  publicKey: Uint8Array
}

export interface X25519 {
  keys: {
    (): Promise<X25519KeyPair>
    sync(): X25519KeyPair
  }
  publicKey: {
    (privateKey: Binary): Promise<Uint8Array>
    sync(privateKey: Binary): Uint8Array
  }
  shared: {
    (privateKey: Binary, publicKey: Binary): Promise<Uint8Array>
    sync(privateKey: Binary, publicKey: Binary): Uint8Array
  }
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

function nonzero(output: Uint8Array): Uint8Array {
  let difference = 0

  for (const byte of output) {
    difference |= byte
  }

  if (difference === 0) {
    throw new InvalidKeyError('X25519 public key produces an all-zero shared secret')
  }

  return output
}

async function publicKey(privateKey: Binary): Promise<Uint8Array> {
  const secret = key(privateKey, 'private')

  try {
    return await nativeX25519Public(secret) ?? multiply(secret, BASE)
  } finally {
    secret.fill(0)
  }
}

function publicKeySync(privateKey: Binary): Uint8Array {
  const secret = key(privateKey, 'private')

  try {
    return nativeX25519PublicSync(secret) ?? multiply(secret, BASE)
  } finally {
    secret.fill(0)
  }
}

async function shared(privateKey: Binary, publicKey: Binary): Promise<Uint8Array> {
  const secret = key(privateKey, 'private')
  const peer = key(publicKey, 'public')

  try {
    return nonzero(await nativeX25519Shared(secret, peer) ?? multiply(secret, peer))
  } finally {
    secret.fill(0)
  }
}

function sharedSync(privateKey: Binary, publicKey: Binary): Uint8Array {
  const secret = key(privateKey, 'private')
  const peer = key(publicKey, 'public')

  try {
    return nonzero(nativeX25519SharedSync(secret, peer) ?? multiply(secret, peer))
  } finally {
    secret.fill(0)
  }
}

async function keys(): Promise<X25519KeyPair> {
  const privateKey = random(32)

  return { privateKey, publicKey: await publicKey(privateKey) }
}

function keysSync(): X25519KeyPair {
  const privateKey = random(32)

  return { privateKey, publicKey: publicKeySync(privateKey) }
}

export const x25519: X25519 = {
  keys: /* @__PURE__ */ Object.assign(keys, { sync: keysSync }),
  publicKey: /* @__PURE__ */ Object.assign(publicKey, { sync: publicKeySync }),
  shared: /* @__PURE__ */ Object.assign(shared, { sync: sharedSync }),
}
