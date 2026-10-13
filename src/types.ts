export type Bytes = Uint8Array

export type Binary = Uint8Array | ArrayBuffer | ArrayBufferView

export type Data = Binary | string

export interface AbortSignalLike {
  readonly aborted: boolean
  readonly reason?: unknown
  throwIfAborted(): void
}

export interface AbortOptions {
  signal?: AbortSignalLike
}

type DisposeKey = SymbolConstructor extends { readonly dispose: infer K extends symbol } ? K : never

export type Disposal = { [K in DisposeKey]: () => void }
