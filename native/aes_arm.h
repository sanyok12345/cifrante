/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#ifndef CIFRANTE_AES_ARM_H
#define CIFRANTE_AES_ARM_H

#include <arm_neon.h>
#include <stdint.h>

typedef uint8x16_t Block;

#if defined(__APPLE__)

static inline int aes_supported(void) {
  return 1;
}

#elif defined(_WIN32)

#include <windows.h>

static inline int aes_supported(void) {
  return IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) != 0;
}

#else

#include <sys/auxv.h>

#ifndef HWCAP_AES
#define HWCAP_AES (1 << 3)
#endif

static inline int aes_supported(void) {
  return (getauxval(AT_HWCAP) & HWCAP_AES) != 0;
}

#endif

static inline Block block_load(const uint8_t *bytes) {
  return vld1q_u8(bytes);
}

static inline void block_store(uint8_t *bytes, Block value) {
  vst1q_u8(bytes, value);
}

static inline Block block_xor(Block a, Block b) {
  return veorq_u8(a, b);
}

static inline uint32_t aes_subword(uint32_t word) {
  Block value = vaeseq_u8(vreinterpretq_u8_u32(vdupq_n_u32(word)), vdupq_n_u8(0));

  return vgetq_lane_u32(vreinterpretq_u32_u8(value), 0);
}

static inline Block aes_inverse_key(Block key) {
  return vaesimcq_u8(key);
}

static inline Block aes_encrypt_first(Block state, Block key) {
  return vaesmcq_u8(vaeseq_u8(state, key));
}

static inline Block aes_encrypt_round(Block state, Block key) {
  return vaesmcq_u8(vaeseq_u8(state, key));
}

static inline Block aes_encrypt_last(Block state, Block key, Block final) {
  return veorq_u8(vaeseq_u8(state, key), final);
}

static inline Block aes_decrypt_first(Block state, Block key) {
  return vaesimcq_u8(vaesdq_u8(state, key));
}

static inline Block aes_decrypt_round(Block state, Block key) {
  return vaesimcq_u8(vaesdq_u8(state, key));
}

static inline Block aes_decrypt_last(Block state, Block key, Block final) {
  return veorq_u8(vaesdq_u8(state, key), final);
}

#endif
