import { fillRandom } from './native/web.js'
import { assertLength, encodeHex, encodeBase64 } from './bytes.js'

export interface Random {
  (length: number): Uint8Array
  hex(length: number): string
  base64(length: number): string
  uint32(): number
  uuid(): string
}

function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  assertLength(length, 'Random byte length')

  const bytes = new Uint8Array(length)
  fillRandom(bytes)
  return bytes
}

export const random: Random = /* @__PURE__ */ Object.assign(randomBytes, {
  hex(length: number): string {
    return encodeHex(randomBytes(length))
  },

  base64(length: number): string {
    return encodeBase64(randomBytes(length))
  },

  uint32(): number {
    return new DataView(randomBytes(4).buffer).getUint32(0)
  },

  uuid(): string {
    const value = randomBytes(16)
    value[6] = (value[6] & 0x0f) | 0x40
    value[8] = (value[8] & 0x3f) | 0x80

    const hex = encodeHex(value)
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
  },
})
