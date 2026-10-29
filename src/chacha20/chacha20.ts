import type { AeadCipher, AeadOptions, Sealed } from '../aead.js'
import { DISPOSE, disposable, lifecycle } from '../aes/block.js'
import { toBinary, toBinaryView, toBytesView } from '../bytes.js'
import { AuthenticationError, InvalidInputError, InvalidKeyError, InvalidNonceError } from '../errors.js'
import { nativeChacha20Poly1305, nativeChacha20Poly1305Available } from '../native/web.js'
import type { Binary, Data, Disposal } from '../types.js'
import { chacha20Poly1305Wasm, chacha20WasmAvailable } from '../wasm/chacha20.js'
import { pacer, watch } from '../yield.js'
import { chacha20Poly1305Js, hchacha20 } from './core.js'
import type { Session } from './core.js'

export interface ChaCha20 {
  poly1305(key: Binary): AeadCipher & Disposal
  xpoly1305(key: Binary): AeadCipher & Disposal
}

const CHUNK = 1 << 20
const LIMIT = (2 ** 32 - 1) * 64

function create(name: string, nonceLength: number, key: Binary): AeadCipher & Disposal {
  let secret: Uint8Array<ArrayBuffer>

  try {
    secret = toBinary(key)
  } catch (error) {
    if (error instanceof InvalidInputError) {
      throw new InvalidKeyError(`${name} key must be binary data`)
    }

    throw error
  }

  if (secret.length !== 32) {
    secret.fill(0)
    throw new InvalidKeyError(`${name} key must contain 32 bytes`)
  }

  const life = lifecycle(`${name} cipher`, () => secret.fill(0))

  function parse(options: AeadOptions): { nonce: Uint8Array, aad: Uint8Array } {
    if (!options || typeof options !== 'object' || Array.isArray(options)) {
      throw new InvalidInputError(`${name} operation requires nonce options`)
    }

    let nonce: Uint8Array

    try {
      nonce = toBinaryView(options.nonce)
    } catch (error) {
      if (error instanceof InvalidInputError) {
        throw new InvalidNonceError(`${name} nonce must be binary data`)
      }

      throw error
    }

    if (nonce.length !== nonceLength) {
      throw new InvalidNonceError(`${name} nonce must contain ${nonceLength} bytes`)
    }

    return { nonce, aad: options.aad === undefined ? new Uint8Array(0) : toBytesView(options.aad) }
  }

  function session(nonce: Uint8Array, aad: Uint8Array, decrypting: boolean): Session {
    let subkey: Uint8Array = secret
    let subnonce = nonce

    if (nonceLength === 24) {
      subkey = hchacha20(secret, nonce.subarray(0, 16))
      subnonce = new Uint8Array(12)
      subnonce.set(nonce.subarray(16), 4)
    }

    try {
      return nativeChacha20Poly1305(subkey, subnonce, aad, decrypting)
        ?? chacha20Poly1305Wasm(subkey, subnonce, aad, decrypting)
        ?? chacha20Poly1305Js(subkey, subnonce, aad, decrypting)
    } finally {
      if (subkey !== secret) {
        subkey.fill(0)
      }
    }
  }

  function input(data: Data | Binary): Uint8Array {
    const bytes = toBytesView(data)

    if (bytes.length > LIMIT) {
      throw new InvalidInputError(`${name} input exceeds the 256 GiB limit`)
    }

    return bytes
  }

  function sealed(data: Sealed): { ciphertext: Uint8Array, tag: Uint8Array } {
    if (data === null || typeof data !== 'object') {
      throw new InvalidInputError(`${name} requires ciphertext and tag`)
    }

    return { ciphertext: input(toBinaryView(data.ciphertext)), tag: toBinary(data.tag) }
  }

  function run(state: Session, source: Uint8Array, target: Uint8Array): void {
    for (let offset = 0; offset < source.length; offset += CHUNK) {
      state.update(source.subarray(offset, offset + CHUNK), target.subarray(offset, offset + CHUNK))
    }
  }

  async function runAsync(state: Session, source: Uint8Array, target: Uint8Array, guard: () => void): Promise<void> {
    const pace = pacer(guard)

    for (let offset = 0; offset < source.length; offset += CHUNK) {
      state.update(source.subarray(offset, offset + CHUNK), target.subarray(offset, offset + CHUNK))

      if (offset + CHUNK < source.length && pace.due()) {
        await pace.pause()
      }
    }
  }

  function verified(state: Session, tag: Uint8Array, output: Uint8Array): Uint8Array {
    const valid = state.open(tag.length === 16 ? tag : new Uint8Array(16))

    if (!valid || tag.length !== 16) {
      output.fill(0)
      throw new AuthenticationError(`${name} authentication failed`)
    }

    return output
  }

  return disposable<AeadCipher>({
    encryptSync(data, options) {
      life.check()

      const { nonce, aad } = parse(options)
      const source = input(data)
      const ciphertext = new Uint8Array(source.length)
      const state = session(nonce, aad, false)

      run(state, source, ciphertext)

      return { ciphertext, tag: state.seal() }
    },

    decryptSync(data, options) {
      life.check()

      const { nonce, aad } = parse(options)
      const { ciphertext, tag } = sealed(data)
      const plaintext = new Uint8Array(ciphertext.length)
      const state = session(nonce, aad, true)

      run(state, ciphertext, plaintext)

      return verified(state, tag, plaintext)
    },

    async encrypt(data, options) {
      const guard = watch(options, life.check)

      guard()

      const { nonce, aad } = parse(options)
      const source = input(data)
      const ciphertext = new Uint8Array(source.length)
      const state = session(nonce, aad, false)

      try {
        await runAsync(state, source, ciphertext, guard)
      } catch (error) {
        state.seal()
        ciphertext.fill(0)
        throw error
      }

      return { ciphertext, tag: state.seal() }
    },

    async decrypt(data, options) {
      const guard = watch(options, life.check)

      guard()

      const { nonce, aad } = parse(options)
      const { ciphertext, tag } = sealed(data)
      const plaintext = new Uint8Array(ciphertext.length)
      const state = session(nonce, aad, true)

      try {
        await runAsync(state, ciphertext, plaintext, guard)
      } catch (error) {
        state.open(new Uint8Array(16))
        plaintext.fill(0)
        throw error
      }

      return verified(state, tag, plaintext)
    },

    dispose: life.dispose,
    [DISPOSE]: life.dispose,
    backend: nativeChacha20Poly1305Available() ? 'native' : chacha20WasmAvailable() ? 'wasm' : 'js',
  })
}

export const chacha20: ChaCha20 = {
  poly1305: key => create('ChaCha20-Poly1305', 12, key),
  xpoly1305: key => create('XChaCha20-Poly1305', 24, key),
}
