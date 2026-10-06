/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "aes.h"

typedef struct {
  uint32_t x0, x1, x2, x3;
} Nibble;

static inline Nibble multiply(Nibble a, Nibble b) {
  uint32_t l0 = a.x0 & b.x0;
  uint32_t l2 = a.x1 & b.x1;
  uint32_t l1 = ((a.x0 ^ a.x1) & (b.x0 ^ b.x1)) ^ l0 ^ l2;
  uint32_t h0 = a.x2 & b.x2;
  uint32_t h2 = a.x3 & b.x3;
  uint32_t h1 = ((a.x2 ^ a.x3) & (b.x2 ^ b.x3)) ^ h0 ^ h2;
  uint32_t m0 = (a.x0 ^ a.x2) & (b.x0 ^ b.x2);
  uint32_t m2 = (a.x1 ^ a.x3) & (b.x1 ^ b.x3);
  uint32_t m1 = ((a.x0 ^ a.x1 ^ a.x2 ^ a.x3)
    & (b.x0 ^ b.x1 ^ b.x2 ^ b.x3)) ^ m0 ^ m2;
  uint32_t t = h0 ^ h2 ^ l2;

  return (Nibble){
    l0 ^ m2 ^ t,
    l1 ^ m2 ^ t ^ h1,
    m0 ^ l0 ^ t ^ h1,
    m1 ^ l1 ^ h1 ^ h2,
  };
}

static inline Nibble inverse(Nibble a) {
  uint32_t p01 = a.x0 & a.x1;
  uint32_t p02 = a.x0 & a.x2;
  uint32_t p12 = a.x1 & a.x2;
  uint32_t p03 = a.x0 & a.x3;
  uint32_t p13 = a.x1 & a.x3;
  uint32_t p23 = a.x2 & a.x3;
  uint32_t p012 = p01 & a.x2;
  uint32_t p013 = p01 & a.x3;
  uint32_t p023 = p02 & a.x3;
  uint32_t p123 = p12 & a.x3;

  return (Nibble){
    a.x0 ^ a.x1 ^ a.x2 ^ p02 ^ p12 ^ p012 ^ a.x3 ^ p123,
    p01 ^ p02 ^ p12 ^ a.x3 ^ p13 ^ p013,
    p01 ^ a.x2 ^ p02 ^ a.x3 ^ p03 ^ p023,
    a.x1 ^ a.x2 ^ a.x3 ^ p03 ^ p13 ^ p23 ^ p123,
  };
}

static void invert_tower(uint32_t *p) {
  Nibble a = {p[0], p[1], p[2], p[3]};
  Nibble b = {p[4], p[5], p[6], p[7]};
  Nibble product = multiply(a, b);
  Nibble norm = {
    product.x0 ^ a.x0 ^ a.x2 ^ b.x2,
    product.x1 ^ a.x2 ^ b.x2 ^ b.x1 ^ b.x3,
    product.x2 ^ a.x1 ^ a.x3 ^ b.x1,
    product.x3 ^ a.x3 ^ b.x0 ^ b.x2 ^ b.x3,
  };
  Nibble reciprocal = inverse(norm);
  Nibble sum = {a.x0 ^ b.x0, a.x1 ^ b.x1, a.x2 ^ b.x2, a.x3 ^ b.x3};
  Nibble low = multiply(sum, reciprocal);
  Nibble high = multiply(b, reciprocal);

  p[0] = low.x0;
  p[1] = low.x1;
  p[2] = low.x2;
  p[3] = low.x3;
  p[4] = high.x0;
  p[5] = high.x1;
  p[6] = high.x2;
  p[7] = high.x3;
}

static void substitute(uint32_t *p) {
  uint32_t x0 = p[0], x1 = p[1], x2 = p[2], x3 = p[3];
  uint32_t x4 = p[4], x5 = p[5], x6 = p[6], x7 = p[7];

  p[0] = x0 ^ x5 ^ x7;
  p[1] = x2;
  p[2] = x2 ^ x3 ^ x4 ^ x5 ^ x6 ^ x7;
  p[3] = x3 ^ x4;
  p[4] = x4 ^ x5 ^ x6;
  p[5] = x1 ^ x4 ^ x6 ^ x7;
  p[6] = x2 ^ x3 ^ x5 ^ x7;
  p[7] = x5 ^ x7;
  invert_tower(p);

  x0 = p[0]; x1 = p[1]; x2 = p[2]; x3 = p[3];
  x4 = p[4]; x5 = p[5]; x6 = p[6]; x7 = p[7];

  p[0] = x0 ^ x2 ^ x6 ^ 0xffffu;
  p[1] = x0 ^ x1 ^ x2 ^ x3 ^ x4 ^ x5 ^ 0xffffu;
  p[2] = x0 ^ x3 ^ x5 ^ x6;
  p[3] = x0 ^ x2 ^ x5;
  p[4] = x0 ^ x1 ^ x3 ^ x4 ^ x5;
  p[5] = x1 ^ x2 ^ x3 ^ x5 ^ x6 ^ x7 ^ 0xffffu;
  p[6] = x4 ^ x6 ^ x7 ^ 0xffffu;
  p[7] = x1 ^ x2;
}

static void inverse_substitute(uint32_t *p) {
  uint32_t x0 = p[0], x1 = p[1], x2 = p[2], x3 = p[3];
  uint32_t x4 = p[4], x5 = p[5], x6 = p[6], x7 = p[7];

  p[0] = x1 ^ x5 ^ x6 ^ 0xffffu;
  p[1] = x1 ^ x4 ^ x7 ^ 0xffffu;
  p[2] = x1 ^ x4 ^ 0xffffu;
  p[3] = x0 ^ x1 ^ x2 ^ x3 ^ x5 ^ x6;
  p[4] = x0 ^ x1 ^ x2 ^ x4 ^ x5 ^ x6 ^ x7;
  p[5] = x3 ^ x4 ^ x5 ^ x6;
  p[6] = x0 ^ x4 ^ x5 ^ x6 ^ 0xffffu;
  p[7] = x1 ^ x2 ^ x6 ^ x7;
  invert_tower(p);

  x0 = p[0]; x1 = p[1]; x2 = p[2]; x3 = p[3];
  x4 = p[4]; x5 = p[5]; x6 = p[6]; x7 = p[7];

  p[0] = x0 ^ x7;
  p[1] = x4 ^ x5 ^ x7;
  p[2] = x1;
  p[3] = x1 ^ x6 ^ x7;
  p[4] = x1 ^ x3 ^ x6 ^ x7;
  p[5] = x2 ^ x4 ^ x6;
  p[6] = x1 ^ x2 ^ x3 ^ x7;
  p[7] = x2 ^ x4 ^ x6 ^ x7;
}

static void pack(uint32_t *planes, const uint8_t *bytes, unsigned count) {
  for (unsigned bit = 0; bit < 8; bit++) {
    uint32_t plane = 0;

    for (unsigned lane = 0; lane < count; lane++) {
      plane |= ((uint32_t)(bytes[lane] >> bit) & 1u) << lane;
    }

    planes[bit] = plane;
  }
}

static void unpack(uint8_t *bytes, const uint32_t *planes, unsigned count) {
  for (unsigned lane = 0; lane < count; lane++) {
    uint32_t byte = 0;

    for (unsigned bit = 0; bit < 8; bit++) {
      byte |= ((planes[bit] >> lane) & 1u) << bit;
    }

    bytes[lane] = (uint8_t)byte;
  }
}

static uint32_t rotate_rows(uint32_t plane, unsigned count) {
  uint32_t lower = 0x1111u * ((1u << (4u - count)) - 1u);
  uint32_t upper = 0xffffu ^ lower;

  return ((plane >> count) & lower) | ((plane << (4u - count)) & upper);
}

static void shift_rows(uint32_t *p, int inverse) {
  unsigned first = inverse ? 12 : 4;
  unsigned third = inverse ? 4 : 12;

  for (unsigned bit = 0; bit < 8; bit++) {
    uint32_t x = p[bit];

    p[bit] = (x & 0x1111u)
      | (((x >> first) | (x << (16u - first))) & 0x2222u)
      | (((x >> 8) | (x << 8)) & 0x4444u)
      | (((x >> third) | (x << (16u - third))) & 0x8888u);
  }
}

static void twice(uint32_t *p) {
  uint32_t top = p[7];

  p[7] = p[6];
  p[6] = p[5];
  p[5] = p[4];
  p[4] = p[3] ^ top;
  p[3] = p[2] ^ top;
  p[2] = p[1];
  p[1] = p[0] ^ top;
  p[0] = top;
}

static void mix_columns(uint32_t *p, int inverse) {
  uint32_t difference[8];

  if (inverse) {
    for (unsigned bit = 0; bit < 8; bit++) {
      difference[bit] = p[bit] ^ rotate_rows(p[bit], 2);
    }

    twice(difference);
    twice(difference);

    for (unsigned bit = 0; bit < 8; bit++) {
      p[bit] ^= difference[bit];
    }
  }

  for (unsigned bit = 0; bit < 8; bit++) {
    uint32_t x = p[bit];
    uint32_t next = rotate_rows(x, 1);

    difference[bit] = x ^ next;
    p[bit] = next ^ rotate_rows(x, 2) ^ rotate_rows(x, 3);
  }

  twice(difference);

  for (unsigned bit = 0; bit < 8; bit++) {
    p[bit] ^= difference[bit];
  }

  wasm_clear(difference, sizeof(difference));
}

static void add_key(uint32_t *p, const uint32_t *key) {
  for (unsigned bit = 0; bit < 8; bit++) {
    p[bit] ^= key[bit];
  }
}

uint32_t aes_init(Aes *aes, const uint8_t *key, size_t key_length) {
  wasm_clear(aes, sizeof(*aes));

  if (key_length != 16 && key_length != 24 && key_length != 32) {
    return 1;
  }

  uint8_t expanded[240];
  uint8_t word[4];
  uint32_t planes[8];
  uint32_t round_constant = 1;

  aes->rounds = (uint32_t)(key_length / 4) + 6;

  for (size_t i = 0; i < key_length; i++) {
    expanded[i] = key[i];
  }

  for (size_t offset = key_length; offset < (aes->rounds + 1) * 16; offset += 4) {
    for (unsigned i = 0; i < 4; i++) {
      word[i] = expanded[offset - 4 + i];
    }

    if (offset % key_length == 0) {
      uint8_t first = word[0];

      word[0] = word[1];
      word[1] = word[2];
      word[2] = word[3];
      word[3] = first;
    }

    if (offset % key_length == 0 || (key_length == 32 && offset % key_length == 16)) {
      pack(planes, word, 4);
      substitute(planes);
      unpack(word, planes, 4);
    }

    if (offset % key_length == 0) {
      word[0] ^= (uint8_t)round_constant;
      round_constant = (round_constant << 1) ^ ((round_constant >> 7) * 0x11bu);
    }

    for (unsigned i = 0; i < 4; i++) {
      expanded[offset + i] = expanded[offset - key_length + i] ^ word[i];
    }
  }

  for (uint32_t round = 0; round <= aes->rounds; round++) {
    pack(aes->keys[round], expanded + round * 16, 16);
  }

  wasm_clear(expanded, sizeof(expanded));
  wasm_clear(word, sizeof(word));
  wasm_clear(planes, sizeof(planes));
  return 0;
}

void aes_encrypt(const Aes *aes, uint8_t *block) {
  uint32_t planes[8];

  pack(planes, block, 16);
  add_key(planes, aes->keys[0]);

  for (uint32_t round = 1; round < aes->rounds; round++) {
    substitute(planes);
    shift_rows(planes, 0);
    mix_columns(planes, 0);
    add_key(planes, aes->keys[round]);
  }

  substitute(planes);
  shift_rows(planes, 0);
  add_key(planes, aes->keys[aes->rounds]);
  unpack(block, planes, 16);
  wasm_clear(planes, sizeof(planes));
}

void aes_decrypt(const Aes *aes, uint8_t *block) {
  uint32_t planes[8];

  pack(planes, block, 16);
  add_key(planes, aes->keys[aes->rounds]);

  for (uint32_t round = aes->rounds - 1; round > 0; round--) {
    shift_rows(planes, 1);
    inverse_substitute(planes);
    add_key(planes, aes->keys[round]);
    mix_columns(planes, 1);
  }

  shift_rows(planes, 1);
  inverse_substitute(planes);
  add_key(planes, aes->keys[0]);
  unpack(block, planes, 16);
  wasm_clear(planes, sizeof(planes));
}
