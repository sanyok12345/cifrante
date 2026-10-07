/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#ifndef CIFRANTE_HASH_BUFFER_H
#define CIFRANTE_HASH_BUFFER_H

#include "hash.h"

#define HASH_MAX_LENGTH (UINT64_MAX >> 3)

typedef void (*HashCompress)(void *, const uint8_t *);

static inline void hash_copy(uint8_t *destination, const uint8_t *source, size_t length) {
  size_t i = 0;

  for (; i + 8 <= length; i += 8) {
    *(wasm_u64 *)(destination + i) = *(const wasm_u64 *)(source + i);
  }

  for (; i < length; i++) {
    destination[i] = source[i];
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

    hash_copy(block + *buffered, input, count);
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

    hash_copy(block, input + position, count);
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
  wasm_store64_be(state->block + 56, state->length << 3);
  compress(state, state->block);

  for (unsigned int i = 0; i < words; i++) {
    wasm_store32_be(output + i * 4, state->words[i]);
  }

  wasm_clear(state, sizeof(*state));
  state->finalized = 1;
  return 0;
}

#endif
