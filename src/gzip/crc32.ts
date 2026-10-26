import { lazy } from '../lazy.js'

const table = /* @__PURE__ */ lazy(() => {
  const result = new Int32Array(256)

  for (let n = 0; n < 256; n++) {
    let c = n

    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    }

    result[n] = c
  }

  return result
})

export function crc32(data: Uint8Array): number {
  const t = table()
  let crc = -1

  for (let i = 0; i < data.length; i++) {
    crc = t[(crc ^ data[i]) & 0xff] ^ (crc >>> 8)
  }

  return (crc ^ -1) >>> 0
}
