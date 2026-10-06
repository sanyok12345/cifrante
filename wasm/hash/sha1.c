/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "buffer.h"

static uint32_t rotate(uint32_t value, unsigned int bits) {
  return (value << bits) | (value >> (32u - bits));
}

static void compress(void *context, const uint8_t *block) {
  Sha1 *state = context;
  uint32_t words[80];

  for (unsigned int i = 0; i < 16; i++) {
    words[i] = hash_read32(block + i * 4);
  }

  for (unsigned int i = 16; i < 80; i++) {
    words[i] = rotate(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);
  }

  uint32_t a = state->words[0];
  uint32_t b = state->words[1];
  uint32_t c = state->words[2];
  uint32_t d = state->words[3];
  uint32_t e = state->words[4];

  for (unsigned int i = 0; i < 80; i++) {
    uint32_t function;
    uint32_t constant;

    if (i < 20) {
      function = (b & c) ^ (~b & d);
      constant = 0x5a827999u;
    } else if (i < 40) {
      function = b ^ c ^ d;
      constant = 0x6ed9eba1u;
    } else if (i < 60) {
      function = (b & c) ^ (b & d) ^ (c & d);
      constant = 0x8f1bbcdcu;
    } else {
      function = b ^ c ^ d;
      constant = 0xca62c1d6u;
    }

    uint32_t next = rotate(a, 5) + function + e + constant + words[i];

    e = d;
    d = c;
    c = rotate(b, 30);
    b = a;
    a = next;
  }

  state->words[0] += a;
  state->words[1] += b;
  state->words[2] += c;
  state->words[3] += d;
  state->words[4] += e;
  wasm_clear(words, sizeof(words));
}

void sha1_init(Sha1 *state) {
  wasm_clear(state, sizeof(*state));
  state->words[0] = 0x67452301u;
  state->words[1] = 0xefcdab89u;
  state->words[2] = 0x98badcfeu;
  state->words[3] = 0x10325476u;
  state->words[4] = 0xc3d2e1f0u;
}

uint32_t sha1_update(Sha1 *state, const uint8_t *input, size_t length) {
  return hash32_update(state, input, length, compress);
}

uint32_t sha1_finalize(Sha1 *state, uint8_t *output) {
  return hash32_finalize(state, output, 5, compress);
}
