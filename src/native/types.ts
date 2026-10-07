export interface NativeHash {
  update(data: Uint8Array): void
  digest(): Uint8Array
}

export interface NativeSealed {
  ciphertext: Uint8Array
  tag: Uint8Array
}

export interface NativeCipher {
  available(): boolean
  encrypt(iv: Uint8Array, data: Uint8Array): Promise<Uint8Array | undefined>
  decrypt(iv: Uint8Array, data: Uint8Array): Promise<Uint8Array | undefined>
}

export interface NativeAead {
  available(nonce: Uint8Array): boolean
  encrypt(
    nonce: Uint8Array,
    data: Uint8Array,
    aad: Uint8Array,
    tagLength: number,
  ): Promise<NativeSealed | undefined>
  decrypt(
    nonce: Uint8Array,
    data: Uint8Array,
    aad: Uint8Array,
    tag: Uint8Array,
  ): Promise<Uint8Array | undefined>
}

export interface NativeRsaKey {
  n: bigint
  e?: bigint
  d?: bigint
  p?: bigint
  q?: bigint
}

export interface NativeOaep {
  encrypt(data: Uint8Array): Promise<Uint8Array | undefined>
  decrypt(data: Uint8Array): Promise<Uint8Array | undefined>
}
