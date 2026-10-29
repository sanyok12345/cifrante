export type Curve = 'X25519' | 'Ed25519'

const OIDS: Record<Curve, number> = { X25519: 0x6e, Ed25519: 0x70 }

function wrap(prefix: number[], key: Uint8Array): Uint8Array<ArrayBuffer> {
  const der = new Uint8Array(prefix.length + key.length)

  der.set(prefix)
  der.set(key, prefix.length)

  return der
}

export function curvePkcs8(curve: Curve, privateKey: Uint8Array): Uint8Array<ArrayBuffer> {
  return wrap([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, OIDS[curve], 0x04, 0x22, 0x04, 0x20], privateKey)
}

export function curveSpki(curve: Curve, publicKey: Uint8Array): Uint8Array<ArrayBuffer> {
  return wrap([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, OIDS[curve], 0x03, 0x21, 0x00], publicKey)
}
