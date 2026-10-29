import { bytesToBigInt, toBinary, toBytesView } from '../bytes.js'
import { InvalidKeyError } from '../errors.js'
import { lazy } from '../lazy.js'
import {
  nativeEd25519PublicSync,
  nativeEd25519Sign,
  nativeEd25519SignSync,
  nativeEd25519Verify,
  nativeEd25519VerifySync,
} from '../native/web.js'
import { random } from '../random.js'
import type { Binary, Data } from '../types.js'
import { ed25519PublicWasm, ed25519SignWasm, ed25519VerifyWasm } from '../wasm/ed25519.js'
import { publicKeyJs, signJs, verifyJs } from './curve.js'

export interface Ed25519KeyPair {
  privateKey: Uint8Array
  publicKey: Uint8Array
}

export interface Ed25519 {
  keys: {
    (): Promise<Ed25519KeyPair>
    sync(): Ed25519KeyPair
  }
  publicKey: {
    (privateKey: Binary): Promise<Uint8Array>
    sync(privateKey: Binary): Uint8Array
  }
  sign: {
    (privateKey: Binary, message: Data): Promise<Uint8Array>
    sync(privateKey: Binary, message: Data): Uint8Array
  }
  verify: {
    (publicKey: Binary, message: Data, signature: Binary): Promise<boolean>
    sync(publicKey: Binary, message: Data, signature: Binary): boolean
  }
}

const FIELD = (1n << 255n) - 19n
const ORDER = (1n << 252n) + 27742317777372353535851937790883648493n
const TORSION = 0x5fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826n
const SMALL_ORDER = new Set([0n, 1n, FIELD - 1n, TORSION, FIELD - TORSION])

const PROBE = /* @__PURE__ */ new Uint8Array(32).fill(7)

const nativeConforms = /* @__PURE__ */ lazy(async (): Promise<boolean> => {
  const empty = new Uint8Array(0)
  const expected = ed25519SignWasm(PROBE, empty) ?? signJs(PROBE, empty)
  const signed = await nativeEd25519Sign(PROBE, empty)

  if (signed === undefined || signed.length !== 64 || signed.some((byte, i) => byte !== expected[i])) {
    return false
  }

  const publicKey = ed25519PublicWasm(PROBE) ?? publicKeyJs(PROBE)

  return await nativeEd25519Verify(publicKey, empty, expected) === true
})

function key(value: Binary, name: string): Uint8Array<ArrayBuffer> {
  const bytes = toBinary(value)

  if (bytes.length !== 32) {
    bytes.fill(0)
    throw new InvalidKeyError(`Ed25519 ${name} key must be 32 bytes`)
  }

  return bytes
}

function littleEndian(bytes: Uint8Array): bigint {
  return bytesToBigInt(Uint8Array.from(bytes).reverse())
}

function acceptable(publicKey: Uint8Array, signature: Uint8Array): boolean {
  if (signature.length !== 64 || littleEndian(signature.subarray(32)) >= ORDER) {
    return false
  }

  const y = littleEndian(publicKey) & ((1n << 255n) - 1n)

  return y < FIELD && !SMALL_ORDER.has(y)
}

function publicKeySync(privateKey: Binary): Uint8Array {
  const seed = key(privateKey, 'private')

  try {
    return nativeEd25519PublicSync(seed) ?? ed25519PublicWasm(seed) ?? publicKeyJs(seed)
  } finally {
    seed.fill(0)
  }
}

async function publicKey(privateKey: Binary): Promise<Uint8Array> {
  return publicKeySync(privateKey)
}

function signSync(privateKey: Binary, message: Data): Uint8Array {
  const seed = key(privateKey, 'private')
  const data = toBytesView(message)

  try {
    return nativeEd25519SignSync(seed, data) ?? ed25519SignWasm(seed, data) ?? signJs(seed, data)
  } finally {
    seed.fill(0)
  }
}

async function sign(privateKey: Binary, message: Data): Promise<Uint8Array> {
  const seed = key(privateKey, 'private')
  const data = toBytesView(message)

  try {
    const native = await nativeConforms() ? await nativeEd25519Sign(seed, data) : undefined

    return native ?? ed25519SignWasm(seed, data) ?? signJs(seed, data)
  } finally {
    seed.fill(0)
  }
}

function verifySync(publicKey: Binary, message: Data, signature: Binary): boolean {
  const point = key(publicKey, 'public')
  const data = toBytesView(message)
  const bytes = toBinary(signature)

  if (!acceptable(point, bytes)) {
    return false
  }

  return nativeEd25519VerifySync(point, data, bytes) ?? ed25519VerifyWasm(point, data, bytes) ?? verifyJs(point, data, bytes)
}

async function verify(publicKey: Binary, message: Data, signature: Binary): Promise<boolean> {
  const point = key(publicKey, 'public')
  const data = toBytesView(message)
  const bytes = toBinary(signature)

  if (!acceptable(point, bytes)) {
    return false
  }

  const native = await nativeConforms() ? await nativeEd25519Verify(point, data, bytes) : undefined

  return native ?? ed25519VerifyWasm(point, data, bytes) ?? verifyJs(point, data, bytes)
}

function keysSync(): Ed25519KeyPair {
  const privateKey = random(32)

  return { privateKey, publicKey: publicKeySync(privateKey) }
}

async function keys(): Promise<Ed25519KeyPair> {
  return keysSync()
}

export const ed25519: Ed25519 = {
  keys: /* @__PURE__ */ Object.assign(keys, { sync: keysSync }),
  publicKey: /* @__PURE__ */ Object.assign(publicKey, { sync: publicKeySync }),
  sign: /* @__PURE__ */ Object.assign(sign, { sync: signSync }),
  verify: /* @__PURE__ */ Object.assign(verify, { sync: verifySync }),
}
