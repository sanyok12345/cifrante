/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#ifndef CIFRANTE_HASH_BUFFER_H
#define CIFRANTE_HASH_BUFFER_H

#include "hash.h"

#define HASH_MAX_LENGTH (UINT64_MAX >> 3)

typedef void (*HashCompress)(void *, const uint8_t *);

static inline uint32_t hash_read32(const uint8_t *bytes) {
  return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16)
    | ((uint32_t)bytes[2] << 8) | bytes[3];
}

static inline void hash_write64(uint8_t *bytes, uint64_t value) {
  for (unsigned int i = 0; i < 8; i++) {
    bytes[7 - i] = (uint8_t)(value >> (i * 8));
  }
}

static inline void hash_blocks(
  void *state, uint8_t *block, uint32_t *buffered, uint32_t block_size,
  const uint8_t *input, size_t length, HashCompress compress
) {
  size_t position = 0;

  if (*buffered) {
    size_t count = block_size - *buffered;

    if (count > length) {
      count = length;
    }

    for (size_t i = 0; i < count; i++) {
      block[*buffered + i] = input[i];
    }

    *buffered += (uint32_t)count;
    position = count;

    if (*buffered == block_size) {
      compress(state, block);
      *buffered = 0;
    }
  }

  while (length - position >= block_size) {
    compress(state, input + position);
    position += block_size;
  }

  if (position < length) {
    size_t count = length - position;

    for (size_t i = 0; i < count; i++) {
      block[i] = input[position + i];
    }

    *buffered = (uint32_t)count;
  }
}

static inline void hash_pad(
  void *state, uint8_t *block, uint32_t buffered, uint32_t block_size,
  uint32_t length_size, HashCompress compress
) {
  block[buffered] = 0x80;

  for (uint32_t i = buffered + 1; i < block_size; i++) {
    block[i] = 0;
  }

  if (buffered >= block_size - length_size) {
    compress(state, block);
    wasm_clear(block, block_size);
  }
}

static inline uint32_t hash32_update(
  Sha256 *state, const uint8_t *input, size_t length, HashCompress compress
) {
  if (state->finalized || state->buffered >= 64 || (!input && length)) {
    return 2;
  }

  if (state->length > HASH_MAX_LENGTH || length > HASH_MAX_LENGTH - state->length) {
    return 1;
  }

  state->length += length;
  hash_blocks(state, state->block, &state->buffered, 64, input, length, compress);
  return 0;
}

static inline uint32_t hash32_finalize(
  Sha256 *state, uint8_t *output, unsigned int words, HashCompress compress
) {
  if (state->finalized || state->buffered >= 64 || !output) {
    return 2;
  }

  if (state->length > HASH_MAX_LENGTH) {
    return 1;
  }

  hash_pad(state, state->block, state->buffered, 64, 8, compress);
  hash_write64(state->block + 56, state->length << 3);
  compress(state, state->block);

  for (unsigned int i = 0; i < words; i++) {
    output[i * 4] = (uint8_t)(state->words[i] >> 24);
    output[i * 4 + 1] = (uint8_t)(state->words[i] >> 16);
    output[i * 4 + 2] = (uint8_t)(state->words[i] >> 8);
    output[i * 4 + 3] = (uint8_t)state->words[i];
  }

  wasm_clear(state, sizeof(*state));
  state->finalized = 1;
  return 0;
}

#endif
