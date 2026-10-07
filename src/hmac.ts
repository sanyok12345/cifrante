import { encodeHex, equalBinary, toBinary, toBytes, toBytesView } from './bytes.js'
import { AsyncDigest, SyncDigest } from './hash/hash.js'
import type { DigestState, SyncHash, SyncHashState } from './hash/hash.js'
import { sha256Sync } from './hash/sha256.js'
import { sha512Sync } from './hash/sha512.js'
import { nativeHmac, nativeMac, nativeMacAvailable } from './native/web.js'
import type { Binary, Data } from './types.js'
import { SLICE, forEachSlice } from './yield.js'

export interface Hmac {
  (key: Binary, data: Data): Promise<Uint8Array>
  verify(key: Binary, data: Data, mac: Binary): Promise<boolean>
  hex(key: Binary, data: Data): Promise<string>
  create(key: Binary): HmacState
  sync: SyncHmac
}

export interface HmacState {
  update(data: Data): this
  digest(): Promise<Uint8Array>
  verify(mac: Binary): Promise<boolean>
}

export interface HMAC {
  sha256: Hmac
  sha512: Hmac
}

export interface SyncHmac {
  (key: Binary, data: Data): Uint8Array
  create(key: Binary): SyncHashState
}

class State extends AsyncDigest implements HmacState {
  async verify(mac: Binary): Promise<boolean> {
    const signature = toBinary(mac)

    return equalBinary(await this.digest(), signature)
  }
}

class JsHmac implements DigestState {
  private readonly inner: SyncHashState
  private readonly outer: SyncHashState

  constructor(hash: SyncHash, key: Uint8Array, blockSize: number) {
    const reduced = key.length > blockSize ? hash(key) : key
    const pad = new Uint8Array(blockSize)

    pad.set(reduced)

    for (let i = 0; i < blockSize; i++) {
      pad[i] ^= 0x36
    }

    this.inner = hash.create().update(pad)

    for (let i = 0; i < blockSize; i++) {
      pad[i] ^= 0x36 ^ 0x5c
    }

    this.outer = hash.create().update(pad)

    pad.fill(0)

    if (reduced !== key) {
      reduced.fill(0)
    }
  }

  update(data: Uint8Array): void {
    this.inner.update(data)
  }

  digest(): Uint8Array {
    const inner = this.inner.digest()

    this.outer.update(inner)
    inner.fill(0)

    return this.outer.digest()
  }
}

export function createSyncHmac(name: string, hash: SyncHash, blockSize: number): SyncHmac {
  const create = (key: Binary): SyncHashState => {
    const value = toBinary(key)

    try {
      return new SyncDigest(nativeHmac(name, value) ?? new JsHmac(hash, value, blockSize), 'HMAC')
    } finally {
      value.fill(0)
    }
  }

  const mac = (key: Binary, data: Data): Uint8Array => create(key).update(data).digest()

  return Object.assign(mac, { create })
}

export async function macAsync(
  sync: SyncHmac,
  key: Uint8Array,
  input: Uint8Array,
): Promise<Uint8Array> {
  if (input.length <= SLICE) {
    return sync(key, input)
  }

  const state = sync.create(key)

  await forEachSlice(input, SLICE, (slice) => {
    state.update(slice)
  })

  return state.digest()
}

function createHmac(name: string, sync: SyncHmac): Hmac {
  const create = (key: Binary): HmacState => new State(sync.create(key))
  const mac = async (key: Binary, data: Data): Promise<Uint8Array> => {
    const value = toBinary(key)

    try {
      if (!nativeMacAvailable(name, value)) {
        const input = toBytesView(data)

        return await macAsync(sync, value, input)
      }

      const input = toBytes(data)
      const native = await nativeMac(name, value, input)

      return native === undefined ? await macAsync(sync, value, input) : native
    } finally {
      value.fill(0)
    }
  }

  return Object.assign(mac, {
    verify: async (key: Binary, data: Data, signature: Binary): Promise<boolean> => {
      const expected = toBinary(signature)

      return equalBinary(await mac(key, data), expected)
    },
    hex: async (key: Binary, data: Data): Promise<string> => encodeHex(await mac(key, data)),
    create,
    sync,
  })
}

export const hmacSha256Sync = /* @__PURE__ */ createSyncHmac('sha256', sha256Sync, 64)
export const hmacSha512Sync = /* @__PURE__ */ createSyncHmac('sha512', sha512Sync, 128)

export const hmac: HMAC = {
  sha256: /* @__PURE__ */ createHmac('sha256', hmacSha256Sync),
  sha512: /* @__PURE__ */ createHmac('sha512', hmacSha512Sync),
}
