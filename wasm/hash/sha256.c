/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "buffer.h"

const uint32_t sha256_initial[8] = {
  0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
  0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

static const uint32_t K[64] = {
  0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
  0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
  0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
  0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
  0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
  0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
  0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
  0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
  0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
  0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
  0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
  0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
  0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
  0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
  0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
  0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32u - (n))))
#define S0(x) (ROR(x, 7) ^ ROR(x, 18) ^ ((x) >> 3))
#define S1(x) (ROR(x, 17) ^ ROR(x, 19) ^ ((x) >> 10))
#define E0(x) (ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22))
#define E1(x) (ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25))
#define CH(e, f, g) ((g) ^ ((e) & ((f) ^ (g))))
#define MAJ(a, b, c) (((a) & (b)) | ((c) & ((a) | (b))))

#define ROUND(a, b, c, d, e, f, g, h, i, w) \
  do { \
    uint32_t t1 = h + E1(e) + CH(e, f, g) + K[i] + (w); \
    uint32_t t2 = E0(a) + MAJ(a, b, c); \
    d += t1; \
    h = t1 + t2; \
  } while (0)

#define EXPAND(w0, w1, w9, w14) (w0 += S1(w14) + w9 + S0(w1))

#define ROUNDS16(i, a, b, c, d, e, f, g, h) \
  ROUND(a, b, c, d, e, f, g, h, i + 0, w0); \
  ROUND(h, a, b, c, d, e, f, g, i + 1, w1); \
  ROUND(g, h, a, b, c, d, e, f, i + 2, w2); \
  ROUND(f, g, h, a, b, c, d, e, i + 3, w3); \
  ROUND(e, f, g, h, a, b, c, d, i + 4, w4); \
  ROUND(d, e, f, g, h, a, b, c, i + 5, w5); \
  ROUND(c, d, e, f, g, h, a, b, i + 6, w6); \
  ROUND(b, c, d, e, f, g, h, a, i + 7, w7); \
  ROUND(a, b, c, d, e, f, g, h, i + 8, w8); \
  ROUND(h, a, b, c, d, e, f, g, i + 9, w9); \
  ROUND(g, h, a, b, c, d, e, f, i + 10, w10); \
  ROUND(f, g, h, a, b, c, d, e, i + 11, w11); \
  ROUND(e, f, g, h, a, b, c, d, i + 12, w12); \
  ROUND(d, e, f, g, h, a, b, c, i + 13, w13); \
  ROUND(c, d, e, f, g, h, a, b, i + 14, w14); \
  ROUND(b, c, d, e, f, g, h, a, i + 15, w15)

#define EXPAND16() \
  EXPAND(w0, w1, w9, w14); \
  EXPAND(w1, w2, w10, w15); \
  EXPAND(w2, w3, w11, w0); \
  EXPAND(w3, w4, w12, w1); \
  EXPAND(w4, w5, w13, w2); \
  EXPAND(w5, w6, w14, w3); \
  EXPAND(w6, w7, w15, w4); \
  EXPAND(w7, w8, w0, w5); \
  EXPAND(w8, w9, w1, w6); \
  EXPAND(w9, w10, w2, w7); \
  EXPAND(w10, w11, w3, w8); \
  EXPAND(w11, w12, w4, w9); \
  EXPAND(w12, w13, w5, w10); \
  EXPAND(w13, w14, w6, w11); \
  EXPAND(w14, w15, w7, w12); \
  EXPAND(w15, w0, w8, w13)

void sha256_compress(uint32_t *state, const uint32_t *message) {
  uint32_t w0 = message[0], w1 = message[1], w2 = message[2], w3 = message[3];
  uint32_t w4 = message[4], w5 = message[5], w6 = message[6], w7 = message[7];
  uint32_t w8 = message[8], w9 = message[9], w10 = message[10], w11 = message[11];
  uint32_t w12 = message[12], w13 = message[13], w14 = message[14], w15 = message[15];
  uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
  uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

#pragma clang loop unroll(disable)
  for (unsigned int i = 0;; i += 16) {
    ROUNDS16(i, a, b, c, d, e, f, g, h);

    if (i == 48) {
      break;
    }

    EXPAND16();
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

static void compress(void *context, const uint8_t *block) {
  uint32_t message[16];

  for (unsigned int i = 0; i < 16; i++) {
    message[i] = wasm_load32_be(block + i * 4);
  }

  sha256_compress(((Sha256 *)context)->words, message);
  wasm_clear(message, sizeof(message));
}

void sha256_init(Sha256 *state) {
  wasm_clear(state, sizeof(*state));

  for (unsigned int i = 0; i < 8; i++) {
    state->words[i] = sha256_initial[i];
  }
}

uint32_t sha256_update(Sha256 *state, const uint8_t *input, size_t length) {
  return hash32_update(state, input, length, compress);
}

uint32_t sha256_finalize(Sha256 *state, uint8_t *output) {
  return hash32_finalize(state, output, 8, compress);
}
