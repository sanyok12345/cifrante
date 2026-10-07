/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#ifndef CIFRANTE_AES_X86_H
#define CIFRANTE_AES_X86_H

#include <cpuid.h>
#include <stdint.h>
#include <wmmintrin.h>

typedef __m128i Block;

static inline int aes_supported(void) {
  unsigned int a, b, c, d;

  return __get_cpuid(1, &a, &b, &c, &d) && (c & bit_AES) != 0;
}

static inline Block block_load(const uint8_t *bytes) {
  return _mm_loadu_si128((const Block *)bytes);
}

static inline void block_store(uint8_t *bytes, Block value) {
  _mm_storeu_si128((Block *)bytes, value);
}

static inline Block block_xor(Block a, Block b) {
  return _mm_xor_si128(a, b);
}

static inline uint32_t aes_subword(uint32_t word) {
  Block value = _mm_aesenclast_si128(_mm_set1_epi32((int)word), _mm_setzero_si128());

  return (uint32_t)_mm_cvtsi128_si32(value);
}

static inline Block aes_inverse_key(Block key) {
  return _mm_aesimc_si128(key);
}

static inline Block aes_encrypt_first(Block state, Block key) {
  return _mm_xor_si128(state, key);
}

static inline Block aes_encrypt_round(Block state, Block key) {
  return _mm_aesenc_si128(state, key);
}

static inline Block aes_encrypt_last(Block state, Block key, Block final) {
  return _mm_aesenclast_si128(_mm_aesenc_si128(state, key), final);
}

static inline Block aes_decrypt_first(Block state, Block key) {
  return _mm_xor_si128(state, key);
}

static inline Block aes_decrypt_round(Block state, Block key) {
  return _mm_aesdec_si128(state, key);
}

static inline Block aes_decrypt_last(Block state, Block key, Block final) {
  return _mm_aesdeclast_si128(_mm_aesdec_si128(state, key), final);
}

#endif
