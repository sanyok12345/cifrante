/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "aes.h"
#include "tables.h"

#define TABLE(name) wasm_v128_load(AES_##name)
#define SHUFFLE(x, ...) wasm_i8x16_shuffle(x, x, __VA_ARGS__)

#define SIGMA1 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11
#define SIGMA2 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7
#define SIGMA3 0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3

#define RHO1_0 1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12
#define RHO1_1 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12, 1, 2, 3, 0
#define RHO1_2 9, 10, 11, 8, 13, 14, 15, 12, 1, 2, 3, 0, 5, 6, 7, 4
#define RHO1_3 13, 14, 15, 12, 1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8
#define RHO2_0 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13
#define RHO2_1 10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5
#define RHO2_2 RHO2_0
#define RHO2_3 RHO2_1
#define RHO3_0 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14
#define RHO3_1 15, 12, 13, 14, 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10
#define RHO3_2 11, 8, 9, 10, 15, 12, 13, 14, 3, 0, 1, 2, 7, 4, 5, 6
#define RHO3_3 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14, 3, 0, 1, 2

static inline v128_t lookup(v128_t table, v128_t index) {
#if defined(__wasm_relaxed_simd__)
  return wasm_i8x16_relaxed_swizzle(table, index);
#else
  return wasm_i8x16_swizzle(table, index);
#endif
}

static inline v128_t low_nibbles(v128_t x) {
  return wasm_v128_and(x, wasm_i8x16_const_splat(0x0f));
}

static inline v128_t high_nibbles(v128_t x) {
  return wasm_u8x16_shr(x, 4);
}

static inline v128_t transform(v128_t x, v128_t low, v128_t high) {
  return wasm_v128_xor(lookup(low, low_nibbles(x)), lookup(high, high_nibbles(x)));
}

static inline void invert(v128_t x, v128_t *io, v128_t *jo) {
  v128_t inv = TABLE(INV);
  v128_t inva = TABLE(INVA);
  v128_t k = low_nibbles(x);
  v128_t i = high_nibbles(x);
  v128_t j = wasm_v128_xor(i, k);
  v128_t ak = lookup(inv, k);
  v128_t iak = wasm_v128_xor(lookup(inva, i), ak);
  v128_t jak = wasm_v128_xor(lookup(inva, j), ak);

  *io = wasm_v128_xor(lookup(inva, iak), j);
  *jo = wasm_v128_xor(lookup(inva, jak), i);
}

static inline v128_t pair(v128_t io, v128_t jo, v128_t table_io, v128_t table_jo) {
  return wasm_v128_xor(lookup(table_io, io), lookup(table_jo, jo));
}

static inline v128_t sigma(v128_t x, unsigned power) {
  switch (power & 3) {
    case 1:
      return SHUFFLE(x, SIGMA1);
    case 2:
      return SHUFFLE(x, SIGMA2);
    case 3:
      return SHUFFLE(x, SIGMA3);
    default:
      return x;
  }
}

#define ENCRYPT_ROUND(j) \
  static inline v128_t encrypt_round_##j(v128_t x, v128_t key) { \
    v128_t io, jo; \
    invert(x, &io, &jo); \
    v128_t a = pair(io, jo, TABLE(SB1_IO), TABLE(SB1_JO)); \
    v128_t b = wasm_v128_xor(pair(io, jo, TABLE(SB2_IO), TABLE(SB2_JO)), key); \
    v128_t c = SHUFFLE(pair(io, jo, TABLE(SB3_IO), TABLE(SB3_JO)), RHO1_##j); \
    v128_t d = wasm_v128_xor(SHUFFLE(a, RHO2_##j), SHUFFLE(a, RHO3_##j)); \
    return wasm_v128_xor(wasm_v128_xor(b, c), d); \
  }

#define ENCRYPT_ROUND_WIDE(j) \
  static inline v128_t encrypt_wide_##j(v128_t x, v128_t key) { \
    v128_t io, jo; \
    invert(x, &io, &jo); \
    v128_t a = pair(io, jo, TABLE(SB1_IO), TABLE(SB1_JO)); \
    v128_t b = pair(io, jo, TABLE(SB2_IO), TABLE(SB2_JO)); \
    v128_t t = SHUFFLE(wasm_v128_xor(a, SHUFFLE(a, RHO1_##j)), RHO2_##j); \
    v128_t u = wasm_v128_xor(wasm_v128_xor(b, key), SHUFFLE(wasm_v128_xor(a, b), RHO1_##j)); \
    return wasm_v128_xor(t, u); \
  }

#define DECRYPT_ROUND(j) \
  static inline v128_t decrypt_round_##j(v128_t x, v128_t key) { \
    v128_t io, jo; \
    invert(x, &io, &jo); \
    v128_t e = wasm_v128_xor(pair(io, jo, TABLE(D14_IO), TABLE(D14_JO)), key); \
    v128_t b = SHUFFLE(pair(io, jo, TABLE(D11_IO), TABLE(D11_JO)), RHO1_##j); \
    v128_t d = SHUFFLE(pair(io, jo, TABLE(D13_IO), TABLE(D13_JO)), RHO2_##j); \
    v128_t n = SHUFFLE(pair(io, jo, TABLE(D9_IO), TABLE(D9_JO)), RHO3_##j); \
    return wasm_v128_xor(wasm_v128_xor(e, b), wasm_v128_xor(d, n)); \
  }

ENCRYPT_ROUND(0)
ENCRYPT_ROUND(1)
ENCRYPT_ROUND(2)
ENCRYPT_ROUND(3)
DECRYPT_ROUND(0)
DECRYPT_ROUND(1)
DECRYPT_ROUND(2)
DECRYPT_ROUND(3)

static inline v128_t encrypt_final(v128_t x) {
  v128_t io, jo;

  invert(x, &io, &jo);
  return pair(io, jo, TABLE(SBO_IO), TABLE(SBO_JO));
}

static inline v128_t decrypt_final(v128_t x) {
  v128_t io, jo;

  invert(x, &io, &jo);
  return pair(io, jo, TABLE(D1_IO), TABLE(D1_JO));
}

static inline v128_t encrypt_plain(v128_t x, v128_t key) {
  v128_t io, jo;

  invert(SHUFFLE(x, SIGMA1), &io, &jo);

  v128_t a = pair(io, jo, TABLE(SB1_IO), TABLE(SB1_JO));
  v128_t b = pair(io, jo, TABLE(SB2_IO), TABLE(SB2_JO));
  v128_t t = SHUFFLE(wasm_v128_xor(a, SHUFFLE(a, RHO1_0)), RHO2_0);
  v128_t u = wasm_v128_xor(wasm_v128_xor(b, key), SHUFFLE(wasm_v128_xor(a, b), RHO1_0));

  return wasm_v128_xor(t, u);
}

static inline v128_t finish(v128_t x, uint32_t rounds) {
  return rounds == 12 ? x : SHUFFLE(x, SIGMA2);
}

#define ENCRYPT_START(s) s = transform(wasm_v128_xor(s, key[0]), TABLE(IPT_LO), TABLE(IPT_HI));
#define ENCRYPT_END(s) s = wasm_v128_xor(finish(encrypt_final(s), rounds), key[rounds]);
#define DECRYPT_START(s) s = transform(wasm_v128_xor(s, key[rounds]), TABLE(DIPT_LO), TABLE(DIPT_HI));
#define DECRYPT_END(s) s = wasm_v128_xor(finish(decrypt_final(s), rounds), key[0]);

#define ENCRYPT_ROUNDS(ROUND, f) \
  uint32_t round = 1; \
  for (; round + 3 < rounds; round += 4) { \
    ROUND(f##_1, key[round]) \
    ROUND(f##_2, key[round + 1]) \
    ROUND(f##_3, key[round + 2]) \
    ROUND(f##_0, key[round + 3]) \
  } \
  if (round < rounds) { ROUND(f##_1, key[round]) round++; } \
  if (round < rounds) { ROUND(f##_2, key[round]) round++; } \
  if (round < rounds) { ROUND(f##_3, key[round]) }

#define DECRYPT_ROUNDS(ROUND) \
  uint32_t round = rounds - 1; \
  for (; round >= 4; round -= 4) { \
    ROUND(decrypt_round_3, key[round]) \
    ROUND(decrypt_round_2, key[round - 1]) \
    ROUND(decrypt_round_1, key[round - 2]) \
    ROUND(decrypt_round_0, key[round - 3]) \
  } \
  if (round >= 1) { ROUND(decrypt_round_3, key[round]) round--; } \
  if (round >= 1) { ROUND(decrypt_round_2, key[round]) round--; } \
  if (round >= 1) { ROUND(decrypt_round_1, key[round]) }

v128_t aes_encrypt_vector(const Aes *aes, v128_t s0) {
  const v128_t *key = aes->encrypt;
  uint32_t rounds = aes->rounds;

#define ROUND(f, k) s0 = f(s0, k);
  ENCRYPT_START(s0)
  ENCRYPT_ROUNDS(ROUND, encrypt_round)
  ENCRYPT_END(s0)
#undef ROUND
  return s0;
}

v128_t aes_decrypt_vector(const Aes *aes, v128_t s0) {
  const v128_t *key = aes->decrypt;
  uint32_t rounds = aes->rounds;

#define ROUND(f, k) s0 = f(s0, k);
  DECRYPT_START(s0)
  DECRYPT_ROUNDS(ROUND)
  DECRYPT_END(s0)
#undef ROUND
  return s0;
}

static void encrypt_four(const Aes *aes, uint8_t *blocks) {
  const v128_t *key = aes->encrypt;
  uint32_t rounds = aes->rounds;
  v128_t s0 = wasm_v128_load(blocks);
  v128_t s1 = wasm_v128_load(blocks + 16);
  v128_t s2 = wasm_v128_load(blocks + 32);
  v128_t s3 = wasm_v128_load(blocks + 48);

  ENCRYPT_START(s0) ENCRYPT_START(s1) ENCRYPT_START(s2) ENCRYPT_START(s3)

  for (uint32_t round = 1; round < rounds; round++) {
    v128_t rk = sigma(key[round], round);

    s0 = encrypt_plain(s0, rk);
    s1 = encrypt_plain(s1, rk);
    s2 = encrypt_plain(s2, rk);
    s3 = encrypt_plain(s3, rk);
  }

  s0 = wasm_v128_xor(SHUFFLE(encrypt_final(s0), SIGMA1), key[rounds]);
  s1 = wasm_v128_xor(SHUFFLE(encrypt_final(s1), SIGMA1), key[rounds]);
  s2 = wasm_v128_xor(SHUFFLE(encrypt_final(s2), SIGMA1), key[rounds]);
  s3 = wasm_v128_xor(SHUFFLE(encrypt_final(s3), SIGMA1), key[rounds]);

  wasm_v128_store(blocks, s0);
  wasm_v128_store(blocks + 16, s1);
  wasm_v128_store(blocks + 32, s2);
  wasm_v128_store(blocks + 48, s3);
}

static void decrypt_four(const Aes *aes, uint8_t *blocks) {
  const v128_t *key = aes->decrypt;
  uint32_t rounds = aes->rounds;
  v128_t s0 = wasm_v128_load(blocks);
  v128_t s1 = wasm_v128_load(blocks + 16);
  v128_t s2 = wasm_v128_load(blocks + 32);
  v128_t s3 = wasm_v128_load(blocks + 48);

#define ROUND(f, k) { v128_t rk = k; s0 = f(s0, rk); s1 = f(s1, rk); s2 = f(s2, rk); s3 = f(s3, rk); }
  DECRYPT_START(s0) DECRYPT_START(s1) DECRYPT_START(s2) DECRYPT_START(s3)
  DECRYPT_ROUNDS(ROUND)
  DECRYPT_END(s0) DECRYPT_END(s1) DECRYPT_END(s2) DECRYPT_END(s3)
#undef ROUND

  wasm_v128_store(blocks, s0);
  wasm_v128_store(blocks + 16, s1);
  wasm_v128_store(blocks + 32, s2);
  wasm_v128_store(blocks + 48, s3);
}

void aes_encrypt(const Aes *aes, uint8_t *block) {
  wasm_v128_store(block, aes_encrypt_vector(aes, wasm_v128_load(block)));
}

void aes_decrypt(const Aes *aes, uint8_t *block) {
  wasm_v128_store(block, aes_decrypt_vector(aes, wasm_v128_load(block)));
}

void aes_encrypt_blocks(const Aes *aes, uint8_t *blocks, size_t count) {
  for (; count >= 4; count -= 4, blocks += 64) {
    encrypt_four(aes, blocks);
  }

  for (; count > 0; count--, blocks += 16) {
    aes_encrypt(aes, blocks);
  }
}

void aes_decrypt_blocks(const Aes *aes, uint8_t *blocks, size_t count) {
  for (; count >= 4; count -= 4, blocks += 64) {
    decrypt_four(aes, blocks);
  }

  for (; count > 0; count--, blocks += 16) {
    aes_decrypt(aes, blocks);
  }
}

static inline v128_t twice(v128_t x) {
  v128_t carry = wasm_v128_and(wasm_i8x16_shr(x, 7), wasm_i8x16_const_splat(0x1b));

  return wasm_v128_xor(wasm_i8x16_shl(x, 1), carry);
}

static inline v128_t inverse_mix_columns(v128_t x) {
  v128_t x2 = twice(x);
  v128_t x4 = twice(x2);
  v128_t x8 = twice(x4);
  v128_t x9 = wasm_v128_xor(x8, x);
  v128_t r = wasm_v128_xor(x8, wasm_v128_xor(x4, x2));

  r = wasm_v128_xor(r, SHUFFLE(wasm_v128_xor(x9, x2), RHO1_0));
  r = wasm_v128_xor(r, SHUFFLE(wasm_v128_xor(x9, x4), RHO2_0));
  return wasm_v128_xor(r, SHUFFLE(x9, RHO3_0));
}

static inline v128_t substitute(v128_t x) {
  v128_t io, jo;

  invert(transform(x, TABLE(IPT_LO), TABLE(IPT_HI)), &io, &jo);
  return wasm_v128_xor(
    pair(io, jo, TABLE(SBO_IO), TABLE(SBO_JO)),
    wasm_i8x16_const_splat(AES_FINAL_CONSTANT)
  );
}

uint32_t aes_init(Aes *aes, const uint8_t *key, size_t key_length) {
  wasm_clear(aes, sizeof(*aes));

  if (key_length != 16 && key_length != 24 && key_length != 32) {
    return 1;
  }

  uint8_t expanded[240];
  uint8_t word[16];
  uint32_t round_constant = 1;
  uint32_t rounds = (uint32_t)(key_length / 4) + 6;

  aes->rounds = rounds;

  for (size_t i = 0; i < key_length; i++) {
    expanded[i] = key[i];
  }

  for (size_t offset = key_length; offset < (rounds + 1) * 16; offset += 4) {
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
      wasm_v128_store32_lane(word, substitute(wasm_v128_load32_zero(word)), 0);
    }

    if (offset % key_length == 0) {
      word[0] ^= (uint8_t)round_constant;
      round_constant = (round_constant << 1) ^ ((round_constant >> 7) * 0x11bu);
    }

    for (unsigned i = 0; i < 4; i++) {
      expanded[offset + i] = expanded[offset - key_length + i] ^ word[i];
    }
  }

  aes->encrypt[0] = wasm_v128_load(expanded);
  aes->decrypt[0] = aes->encrypt[0];
  aes->decrypt[rounds] = wasm_v128_load(expanded + rounds * 16);
  aes->encrypt[rounds] = wasm_v128_xor(
    aes->decrypt[rounds],
    wasm_i8x16_const_splat(AES_FINAL_CONSTANT)
  );

  for (uint32_t round = 1; round < rounds; round++) {
    v128_t round_key = wasm_v128_load(expanded + round * 16);
    v128_t encrypt_key = wasm_v128_xor(
      transform(round_key, TABLE(IPT_LO), TABLE(IPT_HI)),
      wasm_i8x16_const_splat(AES_ROUND_CONSTANT)
    );
    v128_t decrypt_key = transform(
      inverse_mix_columns(round_key), TABLE(DIPT_LO), TABLE(DIPT_HI)
    );

    aes->encrypt[round] = sigma(encrypt_key, 4 - (round & 3));
    aes->decrypt[round] = sigma(decrypt_key, rounds - round);
  }

  wasm_clear(expanded, sizeof(expanded));
  wasm_clear(word, sizeof(word));
  return 0;
}
