/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#ifndef CIFRANTE_HASH_H
#define CIFRANTE_HASH_H

#include "../wasm.h"

typedef struct {
  uint32_t words[8];
  uint64_t length;
  uint8_t block[64];
  uint32_t buffered;
  uint32_t finalized;
} Sha256;

typedef Sha256 Sha1;

typedef struct {
  uint64_t words[8];
  uint64_t length_low;
  uint64_t length_high;
  uint8_t block[128];
  uint32_t buffered;
  uint32_t finalized;
} Sha512;

void sha1_init(Sha1 *state);
uint32_t sha1_update(Sha1 *state, const uint8_t *input, size_t length);
uint32_t sha1_finalize(Sha1 *state, uint8_t *output);

void sha256_init(Sha256 *state);
uint32_t sha256_update(Sha256 *state, const uint8_t *input, size_t length);
uint32_t sha256_finalize(Sha256 *state, uint8_t *output);

void sha512_init(Sha512 *state);
uint32_t sha512_update(Sha512 *state, const uint8_t *input, size_t length);
uint32_t sha512_finalize(Sha512 *state, uint8_t *output);

#endif
