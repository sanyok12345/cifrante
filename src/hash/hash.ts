import { encodeBase64, encodeHex, toBytesView } from '../bytes.js'
import { InvalidInputError } from '../errors.js'
import { nativeDigest, nativeDigestAvailable, nativeDigestSync, nativeHash } from '../native/web.js'
import type { WasmHashFactory } from '../wasm/hash.js'
import { SLICE, forEachSlice } from '../yield.js'
import type { Data } from '../types.js'

export interface Hash {
  (data: Data): Promise<Uint8Array>
  hex(data: Data): Promise<string>
  base64(data: Data): Promise<string>
  create(): HashState
  sync: SyncHash
}

export interface HashState {
  update(data: Data): this
  digest(): Promise<Uint8Array>
  hex(): Promise<string>
  base64(): Promise<string>
}

export interface DigestState {
  update(data: Uint8Array): void
  digest(): Uint8Array
}

export interface SyncHash {
  (data: Data): Uint8Array
  create(): SyncHashState
}

export interface SyncHashState {
  update(data: Data): this
  digest(): Uint8Array
}

export class SyncDigest implements SyncHashState {
  private result?: Uint8Array
  private failed = false
  private error?: unknown

  constructor(
    private engine: DigestState | undefined,
    private readonly name: string,
  ) {}

  update(data: Data): this {
    if (!this.engine) {
      throw new InvalidInputError(`${this.name} has already been finalized`)
    }

    try {
      this.engine.update(toBytesView(data))
    } catch (error) {
      this.engine = undefined
      this.failed = true
      this.error = error
      throw error
    }

    return this
  }

  digest(): Uint8Array {
    if (this.failed) {
      throw this.error
    }

    if (this.result) {
      return Uint8Array.from(this.result)
    }

    const engine = this.engine!

    this.engine = undefined

    try {
      this.result = engine.digest()
    } catch (error) {
      this.failed = true
      this.error = error
      throw error
    }

    return this.result.slice()
  }
}

export class AsyncDigest {
  constructor(private readonly state: SyncHashState) {}

  update(data: Data): this {
    this.state.update(data)

    return this
  }

  async digest(): Promise<Uint8Array> {
    return this.state.digest()
  }
}

class State extends AsyncDigest implements HashState {
  async hex(): Promise<string> {
    return encodeHex(await this.digest())
  }

  async base64(): Promise<string> {
    return encodeBase64(await this.digest())
  }
}

export function createSyncHash(
  name: string,
  createJS: () => DigestState,
  createWasm?: WasmHashFactory,
): SyncHash {
  const create = (): SyncHashState => new SyncDigest(
    nativeHash(name) ?? createWasm?.() ?? createJS(),
    'Hash',
  )
  const hash = (data: Data): Uint8Array => {
    const bytes = toBytesView(data)
    const native = nativeDigestSync(name, bytes)

    if (native !== undefined) {
      return native
    }

    if (createWasm && nativeHash(name) === undefined) {
      const output = createWasm.once(bytes)

      if (output) {
        return output
      }
    }

    return create().update(bytes).digest()
  }

  return Object.assign(hash, { create })
}

export async function digestAsync(sync: SyncHash, input: Uint8Array): Promise<Uint8Array> {
  if (input.length <= SLICE) {
    return sync(input)
  }

  const state = sync.create()

  await forEachSlice(input, SLICE, (slice) => {
    state.update(slice)
  })

  return state.digest()
}

export function createHash(name: string, sync: SyncHash): Hash {
  const create = (): HashState => new State(sync.create())
  const hash = async (data: Data): Promise<Uint8Array> => {
    const input = toBytesView(data)

    if (!nativeDigestAvailable(name)) {
      return digestAsync(sync, input)
    }

    const copy = typeof data === 'string' ? input : Uint8Array.from(input)
    const native = await nativeDigest(name, copy)

    return native === undefined ? digestAsync(sync, copy) : native
  }

  return Object.assign(hash, {
    hex: async (data: Data): Promise<string> => encodeHex(await hash(data)),
    base64: async (data: Data): Promise<string> => encodeBase64(await hash(data)),
    create,
    sync,
  })
}

export abstract class BlockHash implements DigestState {
  protected abstract readonly state: Uint32Array
  protected abstract readonly words: Uint32Array

  private readonly buffer: Uint8Array<ArrayBuffer>
  private readonly view: DataView<ArrayBuffer>
  private position = 0
  private length = 0n
  private finalized = false

  protected constructor(
    private readonly blockSize: number,
    private readonly lengthSize: number,
    private readonly littleEndian = false,
  ) {
    this.buffer = new Uint8Array(blockSize)
    this.view = new DataView(this.buffer.buffer)
  }

  update(data: Uint8Array): void {
    if (this.finalized) {
      throw new InvalidInputError('Hash has already been finalized')
    }

    const length = this.length + BigInt(data.length)

    if (!this.littleEndian && length >= (1n << BigInt(this.lengthSize * 8 - 3))) {
      throw new InvalidInputError('Message is too long for this hash')
    }

    this.length = length
    let offset = 0

    if (this.position) {
      const count = Math.min(data.length, this.blockSize - this.position)

      this.buffer.set(data.subarray(0, count), this.position)
      this.position += count
      offset = count

      if (this.position === this.blockSize) {
        this.process(this.view, 0)
        this.position = 0
      }
    }

    const view = new DataView(data.buffer, data.byteOffset, data.byteLength)

    while (offset + this.blockSize <= data.length) {
      this.process(view, offset)
      offset += this.blockSize
    }

    if (offset < data.length) {
      this.buffer.set(data.subarray(offset), this.position)
      this.position += data.length - offset
    }
  }

  digest(): Uint8Array {
    if (this.finalized) {
      throw new InvalidInputError('Hash has already been finalized')
    }

    this.finalized = true
    this.buffer[this.position++] = 0x80
    this.buffer.fill(0, this.position)

    if (this.position > this.blockSize - this.lengthSize) {
      this.process(this.view, 0)
      this.buffer.fill(0)
    }

    let bits = this.length * 8n

    for (let i = 0; i < this.lengthSize; i++) {
      const offset = this.littleEndian
        ? this.blockSize - this.lengthSize + i
        : this.blockSize - 1 - i

      this.buffer[offset] = Number(bits & 0xffn)
      bits >>= 8n
    }

    this.process(this.view, 0)
    const result = this.output()

    this.buffer.fill(0)
    this.clear()
    this.length = 0n
    this.position = 0

    return result
  }

  protected abstract process(view: DataView, offset: number): void

  protected output(): Uint8Array {
    return wordsToBytes(this.state, this.littleEndian)
  }

  protected clear(): void {
    this.state.fill(0)
    this.words.fill(0)
  }
}

export function wordsToBytes(
  words: Uint32Array,
  littleEndian = false,
): Uint8Array {
  const result = new Uint8Array(words.length * 4)
  const view = new DataView(result.buffer)

  for (let i = 0; i < words.length; i++) {
    view.setUint32(i * 4, words[i], littleEndian)
  }

  return result
}
