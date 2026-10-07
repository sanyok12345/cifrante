/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#ifndef CIFRANTE_AES_H
#define CIFRANTE_AES_H

#include <stddef.h>
#include <stdint.h>

#if defined(__x86_64__)
#include "aes_x86.h"
#elif defined(__aarch64__)
#include "aes_arm.h"
#else
#error "Hardware AES requires x86-64 or AArch64"
#endif

typedef struct {
  Block keys[15];
  unsigned int rounds;
} Aes;

static inline void aes_clear(void *memory, size_t length) {
  volatile uint8_t *bytes = (volatile uint8_t *)memory;

  for (size_t i = 0; i < length; i++) {
    bytes[i] = 0;
  }
}

static inline uint32_t aes_word(const uint8_t *bytes) {
  return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8
    | (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}

static inline int aes_expand(Aes *aes, const uint8_t *key, size_t length, int decrypting) {
  if (length != 16 && length != 24 && length != 32) {
    return 1;
  }

  unsigned int count = (unsigned int)length / 4;
  unsigned int rounds = count + 6;
  unsigned int total = 4 * (rounds + 1);
  uint32_t words[60];
  uint32_t rcon = 1;

  for (unsigned int i = 0; i < count; i++) {
    words[i] = aes_word(key + i * 4);
  }

  for (unsigned int i = count; i < total; i++) {
    uint32_t t = words[i - 1];

    if (i % count == 0) {
      t = aes_subword((t >> 8) | (t << 24)) ^ rcon;
      rcon = (rcon << 1) ^ ((rcon >> 7) * 0x11bu);
    } else if (count == 8 && i % count == 4) {
      t = aes_subword(t);
    }

    words[i] = words[i - count] ^ t;
  }

  aes->rounds = rounds;

  for (unsigned int round = 0; round <= rounds; round++) {
    unsigned int source = decrypting ? rounds - round : round;

    aes->keys[round] = block_load((const uint8_t *)&words[4 * source]);
  }

  if (decrypting) {
    for (unsigned int round = 1; round < rounds; round++) {
      aes->keys[round] = aes_inverse_key(aes->keys[round]);
    }
  }

  aes_clear(words, sizeof(words));
  return 0;
}

static inline Block aes_encrypt_block(const Aes *aes, Block state) {
  state = aes_encrypt_first(state, aes->keys[0]);

  for (unsigned int round = 1; round < aes->rounds - 1; round++) {
    state = aes_encrypt_round(state, aes->keys[round]);
  }

  return aes_encrypt_last(state, aes->keys[aes->rounds - 1], aes->keys[aes->rounds]);
}

static inline Block aes_decrypt_block(const Aes *aes, Block state) {
  state = aes_decrypt_first(state, aes->keys[0]);

  for (unsigned int round = 1; round < aes->rounds - 1; round++) {
    state = aes_decrypt_round(state, aes->keys[round]);
  }

  return aes_decrypt_last(state, aes->keys[aes->rounds - 1], aes->keys[aes->rounds]);
}

#endif
