/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "buffer.h"

const uint64_t sha512_initial[8] = {
  0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull,
  0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
  0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
  0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull,
};

static const uint64_t K[80] = {
  0x428a2f98d728ae22ull, 0x7137449123ef65cdull,
  0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
  0x3956c25bf348b538ull, 0x59f111f1b605d019ull,
  0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
  0xd807aa98a3030242ull, 0x12835b0145706fbeull,
  0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
  0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull,
  0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
  0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull,
  0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
  0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull,
  0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
  0x983e5152ee66dfabull, 0xa831c66d2db43210ull,
  0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
  0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull,
  0x06ca6351e003826full, 0x142929670a0e6e70ull,
  0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull,
  0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
  0x650a73548baf63deull, 0x766a0abb3c77b2a8ull,
  0x81c2c92e47edaee6ull, 0x92722c851482353bull,
  0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull,
  0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
  0xd192e819d6ef5218ull, 0xd69906245565a910ull,
  0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
  0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull,
  0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
  0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull,
  0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
  0x748f82ee5defb2fcull, 0x78a5636f43172f60ull,
  0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
  0x90befffa23631e28ull, 0xa4506cebde82bde9ull,
  0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
  0xca273eceea26619cull, 0xd186b8c721c0c207ull,
  0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
  0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull,
  0x113f9804bef90daeull, 0x1b710b35131c471bull,
  0x28db77f523047d84ull, 0x32caab7b40c72493ull,
  0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
  0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull,
  0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull,
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (64u - (n))))
#define S0(x) (ROR(x, 1) ^ ROR(x, 8) ^ ((x) >> 7))
#define S1(x) (ROR(x, 19) ^ ROR(x, 61) ^ ((x) >> 6))
#define E0(x) (ROR(x, 28) ^ ROR(x, 34) ^ ROR(x, 39))
#define E1(x) (ROR(x, 14) ^ ROR(x, 18) ^ ROR(x, 41))
#define CH(e, f, g) ((g) ^ ((e) & ((f) ^ (g))))
#define MAJ(a, b, c) (((a) & (b)) | ((c) & ((a) | (b))))

#define ROUND(a, b, c, d, e, f, g, h, i, w) \
  do { \
    uint64_t t1 = h + E1(e) + CH(e, f, g) + K[i] + (w); \
    uint64_t t2 = E0(a) + MAJ(a, b, c); \
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

void sha512_compress(uint64_t *state, const uint64_t *message) {
  uint64_t w0 = message[0], w1 = message[1], w2 = message[2], w3 = message[3];
  uint64_t w4 = message[4], w5 = message[5], w6 = message[6], w7 = message[7];
  uint64_t w8 = message[8], w9 = message[9], w10 = message[10], w11 = message[11];
  uint64_t w12 = message[12], w13 = message[13], w14 = message[14], w15 = message[15];
  uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
  uint64_t e = state[4], f = state[5], g = state[6], h = state[7];

#pragma clang loop unroll(disable)
  for (unsigned int i = 0;; i += 16) {
    ROUNDS16(i, a, b, c, d, e, f, g, h);

    if (i == 64) {
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
  uint64_t message[16];

  for (unsigned int i = 0; i < 16; i++) {
    message[i] = wasm_load64_be(block + i * 8);
  }

  sha512_compress(((Sha512 *)context)->words, message);
  wasm_clear(message, sizeof(message));
}

void sha512_init(Sha512 *state) {
  wasm_clear(state, sizeof(*state));

  for (unsigned int i = 0; i < 8; i++) {
    state->words[i] = sha512_initial[i];
  }
}

uint32_t sha512_update(Sha512 *state, const uint8_t *input, size_t length) {
  if (state->finalized || state->buffered >= 128 || (!input && length)) {
    return 2;
  }

  uint64_t low = state->length_low + length;
  uint64_t carry = low < state->length_low;

  if (state->length_high > HASH_MAX_LENGTH - carry) {
    return 1;
  }

  state->length_low = low;
  state->length_high += carry;
  hash_blocks(state, state->block, &state->buffered, 128, input, length, compress);
  return 0;
}

uint32_t sha512_finalize(Sha512 *state, uint8_t *output) {
  if (state->finalized || state->buffered >= 128 || !output) {
    return 2;
  }

  if (state->length_high > HASH_MAX_LENGTH) {
    return 1;
  }

  hash_pad(state, state->block, state->buffered, 128, 16, compress);
  wasm_store64_be(state->block + 112, (state->length_high << 3) | (state->length_low >> 61));
  wasm_store64_be(state->block + 120, state->length_low << 3);
  compress(state, state->block);

  for (unsigned int i = 0; i < 8; i++) {
    wasm_store64_be(output + i * 8, state->words[i]);
  }

  wasm_clear(state, sizeof(*state));
  state->finalized = 1;
  return 0;
}
