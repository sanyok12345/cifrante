/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#ifndef CIFRANTE_AES_MODES_H
#define CIFRANTE_AES_MODES_H

#include "aes.h"

#if defined(AES_SIMD)
typedef v128_t GhashKey[4];
#else
typedef uint64_t GhashKey[4];
#endif

typedef struct {
  GhashKey key[9];
  uint32_t prepared;
  uint32_t reserved;
  uint64_t hash[2];
  uint64_t nonce_length;
  uint64_t aad_length;
  uint64_t text_length;
  uint8_t counter[16];
  uint8_t mask[16];
  uint8_t buffer[16];
  uint8_t stream[16];
  uint8_t tag[16];
  uint32_t buffered;
  uint32_t used;
  uint32_t stage;
} Gcm;

typedef struct {
  Aes aes;
  uint8_t iv[32];
  uint8_t stream[16];
  uint8_t scratch[64];
  uint32_t used;
  Gcm gcm;
} State;

extern State state;
extern uint8_t input[WASM_INPUT_CAPACITY];

uint32_t aes_ready(uint32_t length, uint32_t alignment);
void aes_increment(uint8_t *counter, unsigned first);
void aes_stream(
  uint8_t *counter,
  uint8_t *stream,
  uint32_t *used,
  uint32_t length,
  unsigned first
);

#endif
