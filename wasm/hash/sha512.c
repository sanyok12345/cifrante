/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "buffer.h"

static const uint64_t initial[8] = {
  0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull,
  0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
  0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
  0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull,
};

static const uint64_t constants[80] = {
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

static uint64_t rotate(uint64_t value, unsigned int bits) {
  return (value >> bits) | (value << (64u - bits));
}

static void compress(void *context, const uint8_t *block) {
  Sha512 *state = context;
  uint64_t words[80];

  for (unsigned int i = 0; i < 16; i++) {
    words[i] = ((uint64_t)hash_read32(block + i * 8) << 32)
      | hash_read32(block + i * 8 + 4);
  }

  for (unsigned int i = 16; i < 80; i++) {
    uint64_t x = words[i - 15];
    uint64_t y = words[i - 2];
    uint64_t s0 = rotate(x, 1) ^ rotate(x, 8) ^ (x >> 7);
    uint64_t s1 = rotate(y, 19) ^ rotate(y, 61) ^ (y >> 6);

    words[i] = words[i - 16] + s0 + words[i - 7] + s1;
  }

  uint64_t a = state->words[0];
  uint64_t b = state->words[1];
  uint64_t c = state->words[2];
  uint64_t d = state->words[3];
  uint64_t e = state->words[4];
  uint64_t f = state->words[5];
  uint64_t g = state->words[6];
  uint64_t h = state->words[7];

  for (unsigned int i = 0; i < 80; i++) {
    uint64_t s1 = rotate(e, 14) ^ rotate(e, 18) ^ rotate(e, 41);
    uint64_t choice = (e & f) ^ (~e & g);
    uint64_t t1 = h + s1 + choice + constants[i] + words[i];
    uint64_t s0 = rotate(a, 28) ^ rotate(a, 34) ^ rotate(a, 39);
    uint64_t majority = (a & b) ^ (a & c) ^ (b & c);
    uint64_t t2 = s0 + majority;

    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  state->words[0] += a;
  state->words[1] += b;
  state->words[2] += c;
  state->words[3] += d;
  state->words[4] += e;
  state->words[5] += f;
  state->words[6] += g;
  state->words[7] += h;
  wasm_clear(words, sizeof(words));
}

void sha512_init(Sha512 *state) {
  wasm_clear(state, sizeof(*state));

  for (unsigned int i = 0; i < 8; i++) {
    state->words[i] = initial[i];
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
  hash_write64(state->block + 112, (state->length_high << 3) | (state->length_low >> 61));
  hash_write64(state->block + 120, state->length_low << 3);
  compress(state, state->block);

  for (unsigned int i = 0; i < 8; i++) {
    hash_write64(output + i * 8, state->words[i]);
  }

  wasm_clear(state, sizeof(*state));
  state->finalized = 1;
  return 0;
}
