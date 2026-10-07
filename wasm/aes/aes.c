/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "aes.h"

typedef struct {
  uint32_t x0, x1, x2, x3;
} Nibble;

typedef struct {
  uint32_t p[8];
} Planes;

#define EACH(op) op(0) op(1) op(2) op(3) op(4) op(5) op(6) op(7)

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

static inline void invert_tower(Planes *s) {
  Nibble a = {s->p[0], s->p[1], s->p[2], s->p[3]};
  Nibble b = {s->p[4], s->p[5], s->p[6], s->p[7]};
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

  s->p[0] = low.x0;
  s->p[1] = low.x1;
  s->p[2] = low.x2;
  s->p[3] = low.x3;
  s->p[4] = high.x0;
  s->p[5] = high.x1;
  s->p[6] = high.x2;
  s->p[7] = high.x3;
}

static inline void substitute(Planes *s) {
  uint32_t x0 = s->p[0], x1 = s->p[1], x2 = s->p[2], x3 = s->p[3];
  uint32_t x4 = s->p[4], x5 = s->p[5], x6 = s->p[6], x7 = s->p[7];

  s->p[0] = x0 ^ x5 ^ x7;
  s->p[1] = x2;
  s->p[2] = x2 ^ x3 ^ x4 ^ x5 ^ x6 ^ x7;
  s->p[3] = x3 ^ x4;
  s->p[4] = x4 ^ x5 ^ x6;
  s->p[5] = x1 ^ x4 ^ x6 ^ x7;
  s->p[6] = x2 ^ x3 ^ x5 ^ x7;
  s->p[7] = x5 ^ x7;
  invert_tower(s);

  x0 = s->p[0]; x1 = s->p[1]; x2 = s->p[2]; x3 = s->p[3];
  x4 = s->p[4]; x5 = s->p[5]; x6 = s->p[6]; x7 = s->p[7];

  s->p[0] = ~(x0 ^ x2 ^ x6);
  s->p[1] = ~(x0 ^ x1 ^ x2 ^ x3 ^ x4 ^ x5);
  s->p[2] = x0 ^ x3 ^ x5 ^ x6;
  s->p[3] = x0 ^ x2 ^ x5;
  s->p[4] = x0 ^ x1 ^ x3 ^ x4 ^ x5;
  s->p[5] = ~(x1 ^ x2 ^ x3 ^ x5 ^ x6 ^ x7);
  s->p[6] = ~(x4 ^ x6 ^ x7);
  s->p[7] = x1 ^ x2;
}

static inline void inverse_substitute(Planes *s) {
  uint32_t x0 = s->p[0], x1 = s->p[1], x2 = s->p[2], x3 = s->p[3];
  uint32_t x4 = s->p[4], x5 = s->p[5], x6 = s->p[6], x7 = s->p[7];

  s->p[0] = ~(x1 ^ x5 ^ x6);
  s->p[1] = ~(x1 ^ x4 ^ x7);
  s->p[2] = ~(x1 ^ x4);
  s->p[3] = x0 ^ x1 ^ x2 ^ x3 ^ x5 ^ x6;
  s->p[4] = x0 ^ x1 ^ x2 ^ x4 ^ x5 ^ x6 ^ x7;
  s->p[5] = x3 ^ x4 ^ x5 ^ x6;
  s->p[6] = ~(x0 ^ x4 ^ x5 ^ x6);
  s->p[7] = x1 ^ x2 ^ x6 ^ x7;
  invert_tower(s);

  x0 = s->p[0]; x1 = s->p[1]; x2 = s->p[2]; x3 = s->p[3];
  x4 = s->p[4]; x5 = s->p[5]; x6 = s->p[6]; x7 = s->p[7];

  s->p[0] = x0 ^ x7;
  s->p[1] = x4 ^ x5 ^ x7;
  s->p[2] = x1;
  s->p[3] = x1 ^ x6 ^ x7;
  s->p[4] = x1 ^ x3 ^ x6 ^ x7;
  s->p[5] = x2 ^ x4 ^ x6;
  s->p[6] = x1 ^ x2 ^ x3 ^ x7;
  s->p[7] = x2 ^ x4 ^ x6 ^ x7;
}

static inline uint32_t rotr(uint32_t x, unsigned n) {
  return (x >> n) | (x << (32u - n));
}

static inline uint32_t rotl(uint32_t x, unsigned n) {
  return (x << n) | (x >> (32u - n));
}

static inline void shift_rows(Planes *s) {
#define SHIFT(i) \
  s->p[i] = (s->p[i] & 0x03030303u) | rotr(s->p[i] & 0x0c0c0c0cu, 8) \
    | rotr(s->p[i] & 0x30303030u, 16) | rotr(s->p[i] & 0xc0c0c0c0u, 24);
  EACH(SHIFT)
#undef SHIFT
}

static inline void inverse_shift_rows(Planes *s) {
#define SHIFT(i) \
  s->p[i] = (s->p[i] & 0x03030303u) | rotl(s->p[i] & 0x0c0c0c0cu, 8) \
    | rotl(s->p[i] & 0x30303030u, 16) | rotl(s->p[i] & 0xc0c0c0c0u, 24);
  EACH(SHIFT)
#undef SHIFT
}

static inline uint32_t rows1(uint32_t x) {
  return ((x >> 2) & 0x3f3f3f3fu) | ((x << 6) & 0xc0c0c0c0u);
}

static inline uint32_t rows2(uint32_t x) {
  return ((x >> 4) & 0x0f0f0f0fu) | ((x << 4) & 0xf0f0f0f0u);
}

static inline void twice(Planes *s) {
  uint32_t top = s->p[7];

  s->p[7] = s->p[6];
  s->p[6] = s->p[5];
  s->p[5] = s->p[4];
  s->p[4] = s->p[3] ^ top;
  s->p[3] = s->p[2] ^ top;
  s->p[2] = s->p[1];
  s->p[1] = s->p[0] ^ top;
  s->p[0] = top;
}

static inline void mix_columns(Planes *s) {
  Planes sum;
  Planes next;

#define PREPARE(i) next.p[i] = rows1(s->p[i]); sum.p[i] = s->p[i] ^ next.p[i];
  EACH(PREPARE)
#undef PREPARE

  Planes doubled = sum;

  twice(&doubled);

#define COMBINE(i) s->p[i] = doubled.p[i] ^ next.p[i] ^ rows2(sum.p[i]);
  EACH(COMBINE)
#undef COMBINE
}

static inline void inverse_mix_columns(Planes *s) {
  Planes difference;

#define DIFFERENCE(i) difference.p[i] = s->p[i] ^ rows2(s->p[i]);
  EACH(DIFFERENCE)
#undef DIFFERENCE

  twice(&difference);
  twice(&difference);

#define APPLY(i) s->p[i] ^= difference.p[i];
  EACH(APPLY)
#undef APPLY

  mix_columns(s);
}

static inline void add_key(Planes *s, const uint32_t *key) {
#define ADD(i) s->p[i] ^= key[i];
  EACH(ADD)
#undef ADD
}

static inline uint64_t spread(uint32_t x) {
  uint64_t v = x;

  v = (v | (v << 16)) & 0x0000ffff0000ffffull;
  v = (v | (v << 8)) & 0x00ff00ff00ff00ffull;
  return v;
}

static inline uint32_t gather(uint64_t v) {
  v &= 0x00ff00ff00ff00ffull;
  v = (v | (v >> 8)) & 0x0000ffff0000ffffull;
  v = (v | (v >> 16)) & 0x00000000ffffffffull;
  return (uint32_t)v;
}

static inline uint64_t transpose8(uint64_t x) {
  uint64_t t;

  t = (x ^ (x >> 7)) & 0x00aa00aa00aa00aaull;
  x ^= t ^ (t << 7);
  t = (x ^ (x >> 14)) & 0x0000cccc0000ccccull;
  x ^= t ^ (t << 14);
  t = (x ^ (x >> 28)) & 0x00000000f0f0f0f0ull;
  x ^= t ^ (t << 28);
  return x;
}

static inline void swap_bytes(uint64_t *a, uint64_t *b, unsigned shift, uint64_t mask) {
  uint64_t t = ((*a >> shift) ^ *b) & mask;

  *b ^= t;
  *a ^= t << shift;
}

static void pack(Planes *s, const uint8_t *first, const uint8_t *second) {
  uint64_t m[4];

  for (unsigned q = 0; q < 4; q++) {
    m[q] = spread(*(const wasm_u32 *)(first + q * 4))
      | (spread(*(const wasm_u32 *)(second + q * 4)) << 8);
    m[q] = transpose8(m[q]);
  }

  swap_bytes(&m[0], &m[1], 8, 0x00ff00ff00ff00ffull);
  swap_bytes(&m[2], &m[3], 8, 0x00ff00ff00ff00ffull);
  swap_bytes(&m[0], &m[2], 16, 0x0000ffff0000ffffull);
  swap_bytes(&m[1], &m[3], 16, 0x0000ffff0000ffffull);

  s->p[0] = (uint32_t)m[0];
  s->p[4] = (uint32_t)(m[0] >> 32);
  s->p[1] = (uint32_t)m[1];
  s->p[5] = (uint32_t)(m[1] >> 32);
  s->p[2] = (uint32_t)m[2];
  s->p[6] = (uint32_t)(m[2] >> 32);
  s->p[3] = (uint32_t)m[3];
  s->p[7] = (uint32_t)(m[3] >> 32);
}

static void unpack(const Planes *s, uint8_t *first, uint8_t *second) {
  uint64_t m[4];

  m[0] = s->p[0] | ((uint64_t)s->p[4] << 32);
  m[1] = s->p[1] | ((uint64_t)s->p[5] << 32);
  m[2] = s->p[2] | ((uint64_t)s->p[6] << 32);
  m[3] = s->p[3] | ((uint64_t)s->p[7] << 32);

  swap_bytes(&m[0], &m[2], 16, 0x0000ffff0000ffffull);
  swap_bytes(&m[1], &m[3], 16, 0x0000ffff0000ffffull);
  swap_bytes(&m[0], &m[1], 8, 0x00ff00ff00ff00ffull);
  swap_bytes(&m[2], &m[3], 8, 0x00ff00ff00ff00ffull);

  for (unsigned q = 0; q < 4; q++) {
    m[q] = transpose8(m[q]);
    *(wasm_u32 *)(first + q * 4) = gather(m[q]);

    if (second) {
      *(wasm_u32 *)(second + q * 4) = gather(m[q] >> 8);
    }
  }
}

static void encrypt_planes(const Aes *aes, Planes *s) {
  add_key(s, aes->keys[0]);

  for (uint32_t round = 1; round < aes->rounds; round++) {
    substitute(s);
    shift_rows(s);
    mix_columns(s);
    add_key(s, aes->keys[round]);
  }

  substitute(s);
  shift_rows(s);
  add_key(s, aes->keys[aes->rounds]);
}

static void decrypt_planes(const Aes *aes, Planes *s) {
  add_key(s, aes->keys[aes->rounds]);

  for (uint32_t round = aes->rounds - 1; round > 0; round--) {
    inverse_shift_rows(s);
    inverse_substitute(s);
    add_key(s, aes->keys[round]);
    inverse_mix_columns(s);
  }

  inverse_shift_rows(s);
  inverse_substitute(s);
  add_key(s, aes->keys[0]);
}

uint32_t aes_init(Aes *aes, const uint8_t *key, size_t key_length) {
  wasm_clear(aes, sizeof(*aes));

  if (key_length != 16 && key_length != 24 && key_length != 32) {
    return 1;
  }

  uint8_t expanded[240];
  uint8_t word[16];
  Planes planes;
  uint32_t round_constant = 1;

  aes->rounds = (uint32_t)(key_length / 4) + 6;

  for (size_t i = 0; i < key_length; i++) {
    expanded[i] = key[i];
  }

  for (unsigned i = 4; i < 16; i++) {
    word[i] = 0;
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
      pack(&planes, word, word);
      substitute(&planes);
      unpack(&planes, word, 0);
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
    pack(&planes, expanded + round * 16, expanded + round * 16);

    for (unsigned i = 0; i < 8; i++) {
      aes->keys[round][i] = planes.p[i];
    }
  }

  wasm_clear(expanded, sizeof(expanded));
  wasm_clear(word, sizeof(word));
  wasm_clear(&planes, sizeof(planes));
  return 0;
}

void aes_encrypt(const Aes *aes, uint8_t *block) {
  Planes planes;

  pack(&planes, block, block);
  encrypt_planes(aes, &planes);
  unpack(&planes, block, 0);
  wasm_clear(&planes, sizeof(planes));
}

void aes_decrypt(const Aes *aes, uint8_t *block) {
  Planes planes;

  pack(&planes, block, block);
  decrypt_planes(aes, &planes);
  unpack(&planes, block, 0);
  wasm_clear(&planes, sizeof(planes));
}

void aes_encrypt_blocks(const Aes *aes, uint8_t *blocks, size_t count) {
  Planes planes;

  for (; count >= 2; count -= 2, blocks += 32) {
    pack(&planes, blocks, blocks + 16);
    encrypt_planes(aes, &planes);
    unpack(&planes, blocks, blocks + 16);
  }

  if (count) {
    pack(&planes, blocks, blocks);
    encrypt_planes(aes, &planes);
    unpack(&planes, blocks, 0);
  }

  wasm_clear(&planes, sizeof(planes));
}

void aes_decrypt_blocks(const Aes *aes, uint8_t *blocks, size_t count) {
  Planes planes;

  for (; count >= 2; count -= 2, blocks += 32) {
    pack(&planes, blocks, blocks + 16);
    decrypt_planes(aes, &planes);
    unpack(&planes, blocks, blocks + 16);
  }

  if (count) {
    pack(&planes, blocks, blocks);
    decrypt_planes(aes, &planes);
    unpack(&planes, blocks, 0);
  }

  wasm_clear(&planes, sizeof(planes));
}
