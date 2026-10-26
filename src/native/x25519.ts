const PKCS8_PREFIX = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]
const SPKI_PREFIX = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00]

function wrap(prefix: number[], key: Uint8Array): Uint8Array<ArrayBuffer> {
  const der = new Uint8Array(prefix.length + key.length)

  der.set(prefix)
  der.set(key, prefix.length)

  return der
}

export function x25519Pkcs8(privateKey: Uint8Array): Uint8Array<ArrayBuffer> {
  return wrap(PKCS8_PREFIX, privateKey)
}

export function x25519Spki(publicKey: Uint8Array): Uint8Array<ArrayBuffer> {
  return wrap(SPKI_PREFIX, publicKey)
}
