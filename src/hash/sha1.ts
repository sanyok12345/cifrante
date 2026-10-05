import { BlockHash, createHash, createSyncHash } from './hash.js'

class Sha1 extends BlockHash {
  protected readonly state = new Uint32Array([
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
  ])
  protected readonly words = new Uint32Array(80)

  constructor() {
    super(64, 8)
  }

  protected process(view: DataView, offset: number): void {
    const w = this.words

    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4)
    }

    for (let i = 16; i < 80; i++) {
      const x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
      w[i] = (x << 1) | (x >>> 31)
    }

    let [a, b, c, d, e] = this.state

    for (let i = 0; i < 80; i++) {
      let f: number
      let k: number

      if (i < 20) {
        f = (b & c) | (~b & d)
        k = 0x5a827999
      } else if (i < 40) {
        f = b ^ c ^ d
        k = 0x6ed9eba1
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d)
        k = 0x8f1bbcdc
      } else {
        f = b ^ c ^ d
        k = 0xca62c1d6
      }

      const temp = (((a << 5) | (a >>> 27)) + f + e + k + w[i]) | 0

      e = d
      d = c
      c = (b << 30) | (b >>> 2)
      b = a
      a = temp
    }

    this.state[0] += a
    this.state[1] += b
    this.state[2] += c
    this.state[3] += d
    this.state[4] += e
  }
}

export const sha1Sync = /* @__PURE__ */ createSyncHash('sha1', () => new Sha1())
export const sha1 = /* @__PURE__ */ createHash('sha1', sha1Sync)
