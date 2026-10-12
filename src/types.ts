export type Bytes = Uint8Array

export type Binary = Uint8Array | ArrayBuffer | ArrayBufferView

export type Data = Binary | string

type DisposeKey = SymbolConstructor extends { readonly dispose: infer K extends symbol } ? K : never

export type Disposal = { [K in DisposeKey]: () => void }
