/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "buffer.h"

static const uint32_t initial[8] = {
  0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
  0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

static const uint32_t constants[64] = {
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

static uint32_t rotate(uint32_t value, unsigned int bits) {
  return (value >> bits) | (value << (32u - bits));
}

static void compress(void *context, const uint8_t *block) {
  Sha256 *state = context;
  uint32_t words[64];

  for (unsigned int i = 0; i < 16; i++) {
    words[i] = hash_read32(block + i * 4);
  }

  for (unsigned int i = 16; i < 64; i++) {
    uint32_t x = words[i - 15];
    uint32_t y = words[i - 2];
    uint32_t s0 = rotate(x, 7) ^ rotate(x, 18) ^ (x >> 3);
    uint32_t s1 = rotate(y, 17) ^ rotate(y, 19) ^ (y >> 10);

    words[i] = words[i - 16] + s0 + words[i - 7] + s1;
  }

  uint32_t a = state->words[0];
  uint32_t b = state->words[1];
  uint32_t c = state->words[2];
  uint32_t d = state->words[3];
  uint32_t e = state->words[4];
  uint32_t f = state->words[5];
  uint32_t g = state->words[6];
  uint32_t h = state->words[7];

  for (unsigned int i = 0; i < 64; i++) {
    uint32_t s1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25);
    uint32_t choice = (e & f) ^ (~e & g);
    uint32_t t1 = h + s1 + choice + constants[i] + words[i];
    uint32_t s0 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22);
    uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    uint32_t t2 = s0 + majority;

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

void sha256_init(Sha256 *state) {
  wasm_clear(state, sizeof(*state));

  for (unsigned int i = 0; i < 8; i++) {
    state->words[i] = initial[i];
  }
}

uint32_t sha256_update(Sha256 *state, const uint8_t *input, size_t length) {
  return hash32_update(state, input, length, compress);
}

uint32_t sha256_finalize(Sha256 *state, uint8_t *output) {
  return hash32_finalize(state, output, 8, compress);
}
