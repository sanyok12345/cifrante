/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "buffer.h"

const uint32_t sha1_initial[5] = {
  0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u,
};

#define ROL(x, n) (((x) << (n)) | ((x) >> (32u - (n))))
#define F1(b, c, d) ((d) ^ ((b) & ((c) ^ (d))))
#define F2(b, c, d) ((b) ^ (c) ^ (d))
#define F3(b, c, d) (((b) & (c)) | ((d) & ((b) | (c))))

#define ROUND(f, k, a, b, c, d, e, w) \
  do { \
    e += ROL(a, 5) + f(b, c, d) + (k) + (w); \
    b = ROL(b, 30); \
  } while (0)

#define EXPAND(w0, w2, w8, w13) (w0 = ROL(w13 ^ w8 ^ w2 ^ w0, 1))

void sha1_compress(uint32_t *state, const uint32_t *message) {
  uint32_t w0 = message[0], w1 = message[1], w2 = message[2], w3 = message[3];
  uint32_t w4 = message[4], w5 = message[5], w6 = message[6], w7 = message[7];
  uint32_t w8 = message[8], w9 = message[9], w10 = message[10], w11 = message[11];
  uint32_t w12 = message[12], w13 = message[13], w14 = message[14], w15 = message[15];
  uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];

  ROUND(F1, 0x5a827999u, a, b, c, d, e, w0);
  ROUND(F1, 0x5a827999u, e, a, b, c, d, w1);
  ROUND(F1, 0x5a827999u, d, e, a, b, c, w2);
  ROUND(F1, 0x5a827999u, c, d, e, a, b, w3);
  ROUND(F1, 0x5a827999u, b, c, d, e, a, w4);
  ROUND(F1, 0x5a827999u, a, b, c, d, e, w5);
  ROUND(F1, 0x5a827999u, e, a, b, c, d, w6);
  ROUND(F1, 0x5a827999u, d, e, a, b, c, w7);
  ROUND(F1, 0x5a827999u, c, d, e, a, b, w8);
  ROUND(F1, 0x5a827999u, b, c, d, e, a, w9);
  ROUND(F1, 0x5a827999u, a, b, c, d, e, w10);
  ROUND(F1, 0x5a827999u, e, a, b, c, d, w11);
  ROUND(F1, 0x5a827999u, d, e, a, b, c, w12);
  ROUND(F1, 0x5a827999u, c, d, e, a, b, w13);
  ROUND(F1, 0x5a827999u, b, c, d, e, a, w14);
  ROUND(F1, 0x5a827999u, a, b, c, d, e, w15);
  EXPAND(w0, w2, w8, w13);
  ROUND(F1, 0x5a827999u, e, a, b, c, d, w0);
  EXPAND(w1, w3, w9, w14);
  ROUND(F1, 0x5a827999u, d, e, a, b, c, w1);
  EXPAND(w2, w4, w10, w15);
  ROUND(F1, 0x5a827999u, c, d, e, a, b, w2);
  EXPAND(w3, w5, w11, w0);
  ROUND(F1, 0x5a827999u, b, c, d, e, a, w3);
  EXPAND(w4, w6, w12, w1);
  ROUND(F2, 0x6ed9eba1u, a, b, c, d, e, w4);
  EXPAND(w5, w7, w13, w2);
  ROUND(F2, 0x6ed9eba1u, e, a, b, c, d, w5);
  EXPAND(w6, w8, w14, w3);
  ROUND(F2, 0x6ed9eba1u, d, e, a, b, c, w6);
  EXPAND(w7, w9, w15, w4);
  ROUND(F2, 0x6ed9eba1u, c, d, e, a, b, w7);
  EXPAND(w8, w10, w0, w5);
  ROUND(F2, 0x6ed9eba1u, b, c, d, e, a, w8);
  EXPAND(w9, w11, w1, w6);
  ROUND(F2, 0x6ed9eba1u, a, b, c, d, e, w9);
  EXPAND(w10, w12, w2, w7);
  ROUND(F2, 0x6ed9eba1u, e, a, b, c, d, w10);
  EXPAND(w11, w13, w3, w8);
  ROUND(F2, 0x6ed9eba1u, d, e, a, b, c, w11);
  EXPAND(w12, w14, w4, w9);
  ROUND(F2, 0x6ed9eba1u, c, d, e, a, b, w12);
  EXPAND(w13, w15, w5, w10);
  ROUND(F2, 0x6ed9eba1u, b, c, d, e, a, w13);
  EXPAND(w14, w0, w6, w11);
  ROUND(F2, 0x6ed9eba1u, a, b, c, d, e, w14);
  EXPAND(w15, w1, w7, w12);
  ROUND(F2, 0x6ed9eba1u, e, a, b, c, d, w15);
  EXPAND(w0, w2, w8, w13);
  ROUND(F2, 0x6ed9eba1u, d, e, a, b, c, w0);
  EXPAND(w1, w3, w9, w14);
  ROUND(F2, 0x6ed9eba1u, c, d, e, a, b, w1);
  EXPAND(w2, w4, w10, w15);
  ROUND(F2, 0x6ed9eba1u, b, c, d, e, a, w2);
  EXPAND(w3, w5, w11, w0);
  ROUND(F2, 0x6ed9eba1u, a, b, c, d, e, w3);
  EXPAND(w4, w6, w12, w1);
  ROUND(F2, 0x6ed9eba1u, e, a, b, c, d, w4);
  EXPAND(w5, w7, w13, w2);
  ROUND(F2, 0x6ed9eba1u, d, e, a, b, c, w5);
  EXPAND(w6, w8, w14, w3);
  ROUND(F2, 0x6ed9eba1u, c, d, e, a, b, w6);
  EXPAND(w7, w9, w15, w4);
  ROUND(F2, 0x6ed9eba1u, b, c, d, e, a, w7);
  EXPAND(w8, w10, w0, w5);
  ROUND(F3, 0x8f1bbcdcu, a, b, c, d, e, w8);
  EXPAND(w9, w11, w1, w6);
  ROUND(F3, 0x8f1bbcdcu, e, a, b, c, d, w9);
  EXPAND(w10, w12, w2, w7);
  ROUND(F3, 0x8f1bbcdcu, d, e, a, b, c, w10);
  EXPAND(w11, w13, w3, w8);
  ROUND(F3, 0x8f1bbcdcu, c, d, e, a, b, w11);
  EXPAND(w12, w14, w4, w9);
  ROUND(F3, 0x8f1bbcdcu, b, c, d, e, a, w12);
  EXPAND(w13, w15, w5, w10);
  ROUND(F3, 0x8f1bbcdcu, a, b, c, d, e, w13);
  EXPAND(w14, w0, w6, w11);
  ROUND(F3, 0x8f1bbcdcu, e, a, b, c, d, w14);
  EXPAND(w15, w1, w7, w12);
  ROUND(F3, 0x8f1bbcdcu, d, e, a, b, c, w15);
  EXPAND(w0, w2, w8, w13);
  ROUND(F3, 0x8f1bbcdcu, c, d, e, a, b, w0);
  EXPAND(w1, w3, w9, w14);
  ROUND(F3, 0x8f1bbcdcu, b, c, d, e, a, w1);
  EXPAND(w2, w4, w10, w15);
  ROUND(F3, 0x8f1bbcdcu, a, b, c, d, e, w2);
  EXPAND(w3, w5, w11, w0);
  ROUND(F3, 0x8f1bbcdcu, e, a, b, c, d, w3);
  EXPAND(w4, w6, w12, w1);
  ROUND(F3, 0x8f1bbcdcu, d, e, a, b, c, w4);
  EXPAND(w5, w7, w13, w2);
  ROUND(F3, 0x8f1bbcdcu, c, d, e, a, b, w5);
  EXPAND(w6, w8, w14, w3);
  ROUND(F3, 0x8f1bbcdcu, b, c, d, e, a, w6);
  EXPAND(w7, w9, w15, w4);
  ROUND(F3, 0x8f1bbcdcu, a, b, c, d, e, w7);
  EXPAND(w8, w10, w0, w5);
  ROUND(F3, 0x8f1bbcdcu, e, a, b, c, d, w8);
  EXPAND(w9, w11, w1, w6);
  ROUND(F3, 0x8f1bbcdcu, d, e, a, b, c, w9);
  EXPAND(w10, w12, w2, w7);
  ROUND(F3, 0x8f1bbcdcu, c, d, e, a, b, w10);
  EXPAND(w11, w13, w3, w8);
  ROUND(F3, 0x8f1bbcdcu, b, c, d, e, a, w11);
  EXPAND(w12, w14, w4, w9);
  ROUND(F2, 0xca62c1d6u, a, b, c, d, e, w12);
  EXPAND(w13, w15, w5, w10);
  ROUND(F2, 0xca62c1d6u, e, a, b, c, d, w13);
  EXPAND(w14, w0, w6, w11);
  ROUND(F2, 0xca62c1d6u, d, e, a, b, c, w14);
  EXPAND(w15, w1, w7, w12);
  ROUND(F2, 0xca62c1d6u, c, d, e, a, b, w15);
  EXPAND(w0, w2, w8, w13);
  ROUND(F2, 0xca62c1d6u, b, c, d, e, a, w0);
  EXPAND(w1, w3, w9, w14);
  ROUND(F2, 0xca62c1d6u, a, b, c, d, e, w1);
  EXPAND(w2, w4, w10, w15);
  ROUND(F2, 0xca62c1d6u, e, a, b, c, d, w2);
  EXPAND(w3, w5, w11, w0);
  ROUND(F2, 0xca62c1d6u, d, e, a, b, c, w3);
  EXPAND(w4, w6, w12, w1);
  ROUND(F2, 0xca62c1d6u, c, d, e, a, b, w4);
  EXPAND(w5, w7, w13, w2);
  ROUND(F2, 0xca62c1d6u, b, c, d, e, a, w5);
  EXPAND(w6, w8, w14, w3);
  ROUND(F2, 0xca62c1d6u, a, b, c, d, e, w6);
  EXPAND(w7, w9, w15, w4);
  ROUND(F2, 0xca62c1d6u, e, a, b, c, d, w7);
  EXPAND(w8, w10, w0, w5);
  ROUND(F2, 0xca62c1d6u, d, e, a, b, c, w8);
  EXPAND(w9, w11, w1, w6);
  ROUND(F2, 0xca62c1d6u, c, d, e, a, b, w9);
  EXPAND(w10, w12, w2, w7);
  ROUND(F2, 0xca62c1d6u, b, c, d, e, a, w10);
  EXPAND(w11, w13, w3, w8);
  ROUND(F2, 0xca62c1d6u, a, b, c, d, e, w11);
  EXPAND(w12, w14, w4, w9);
  ROUND(F2, 0xca62c1d6u, e, a, b, c, d, w12);
  EXPAND(w13, w15, w5, w10);
  ROUND(F2, 0xca62c1d6u, d, e, a, b, c, w13);
  EXPAND(w14, w0, w6, w11);
  ROUND(F2, 0xca62c1d6u, c, d, e, a, b, w14);
  EXPAND(w15, w1, w7, w12);
  ROUND(F2, 0xca62c1d6u, b, c, d, e, a, w15);

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
}

static void compress(void *context, const uint8_t *block) {
  uint32_t message[16];

  for (unsigned int i = 0; i < 16; i++) {
    message[i] = wasm_load32_be(block + i * 4);
  }

  sha1_compress(((Sha1 *)context)->words, message);
  wasm_clear(message, sizeof(message));
}

void sha1_init(Sha1 *state) {
  wasm_clear(state, sizeof(*state));

  for (unsigned int i = 0; i < 5; i++) {
    state->words[i] = sha1_initial[i];
  }
}

uint32_t sha1_update(Sha1 *state, const uint8_t *input, size_t length) {
  return hash32_update(state, input, length, compress);
}

uint32_t sha1_finalize(Sha1 *state, uint8_t *output) {
  return hash32_finalize(state, output, 5, compress);
}
