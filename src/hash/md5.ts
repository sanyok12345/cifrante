import { BlockHash, createHash, createSyncHash } from './hash.js'

const K = /* @__PURE__ */ new Uint32Array([
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
  0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
  0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
  0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
  0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
  0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
])

const SHIFT = [
  7, 12, 17, 22,
  5, 9, 14, 20,
  4, 11, 16, 23,
  6, 10, 15, 21,
]

class Md5 extends BlockHash {
  protected readonly state = new Uint32Array([
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476,
  ])
  protected readonly words = new Uint32Array(16)

  constructor() {
    super(64, 8, true)
  }

  protected process(view: DataView, offset: number): void {
    const w = this.words

    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4, true)
    }

    let [a, b, c, d] = this.state

    for (let i = 0; i < 64; i++) {
      let f: number
      let g: number

      if (i < 16) {
        f = (b & c) | (~b & d)
        g = i
      } else if (i < 32) {
        f = (d & b) | (~d & c)
        g = (5 * i + 1) & 15
      } else if (i < 48) {
        f = b ^ c ^ d
        g = (3 * i + 5) & 15
      } else {
        f = c ^ (b | ~d)
        g = (7 * i) & 15
      }

      const shift = SHIFT[(i >>> 4) * 4 + (i & 3)]
      const sum = (a + f + K[i] + w[g]) | 0

      a = d
      d = c
      c = b
      b = (b + ((sum << shift) | (sum >>> (32 - shift)))) | 0
    }

    this.state[0] += a
    this.state[1] += b
    this.state[2] += c
    this.state[3] += d
  }
}

export const md5Sync = /* @__PURE__ */ createSyncHash('md5', () => new Md5())
export const md5 = /* @__PURE__ */ createHash('md5', md5Sync)
