/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "../hash/hash.h"

typedef union {
  Sha1 sha1;
  Sha256 sha256;
  Sha512 sha512;
  uint64_t words[sizeof(Sha512) / sizeof(uint64_t)];
} Hash;

typedef struct {
  Hash inner;
  Hash outer;
  Hash salted;
  Hash work;
  uint8_t key[128];
  uint8_t previous[64];
  uint32_t algorithm;
  uint32_t block_size;
  uint32_t digest_size;
  uint32_t key_length;
  uint32_t hash_password;
  uint32_t phase;
} State;

static State state;
static uint8_t input[WASM_INPUT_CAPACITY];
static uint8_t output[64];

static void hash_copy(Hash *destination, const Hash *source) {
  for (size_t i = 0; i < sizeof(Hash) / sizeof(uint64_t); i++) {
    destination->words[i] = source->words[i];
  }
}

static void hash_init(Hash *hash) {
  switch (state.algorithm) {
    case 1:
      sha1_init(&hash->sha1);
      break;
    case 256:
      sha256_init(&hash->sha256);
      break;
    case 512:
      sha512_init(&hash->sha512);
      break;
  }
}

static uint32_t hash_update(Hash *hash, const uint8_t *data, size_t length) {
  switch (state.algorithm) {
    case 1:
      return sha1_update(&hash->sha1, data, length);
    case 256:
      return sha256_update(&hash->sha256, data, length);
    case 512:
      return sha512_update(&hash->sha512, data, length);
    default:
      return 2;
  }
}

static uint32_t hash_finalize(Hash *hash, uint8_t *digest) {
  switch (state.algorithm) {
    case 1:
      return sha1_finalize(&hash->sha1, digest);
    case 256:
      return sha256_finalize(&hash->sha256, digest);
    case 512:
      return sha512_finalize(&hash->sha512, digest);
    default:
      return 2;
  }
}

static uint32_t hmac_finalize(void) {
  uint32_t status = hash_finalize(&state.work, state.previous);

  if (status != 0) {
    return status;
  }

  hash_copy(&state.work, &state.outer);
  status = hash_update(&state.work, state.previous, state.digest_size);

  if (status != 0) {
    return status;
  }

  return hash_finalize(&state.work, state.previous);
}

WASM_EXPORT("input_ptr") uint8_t *input_ptr(void) {
  return input;
}

WASM_EXPORT("input_capacity") uint32_t input_capacity(void) {
  return sizeof(input);
}

WASM_EXPORT("output_ptr") uint8_t *output_ptr(void) {
  return output;
}

WASM_EXPORT("clear") void clear(void) {
  wasm_clear(&state, sizeof(state));
  wasm_clear(input, sizeof(input));
  wasm_clear(output, sizeof(output));
}

WASM_EXPORT("init") uint32_t init(uint32_t algorithm, uint32_t hash_password) {
  clear();

  if ((algorithm != 1 && algorithm != 256 && algorithm != 512) || hash_password > 1) {
    return 2;
  }

  state.algorithm = algorithm;
  state.block_size = algorithm == 512 ? 128 : 64;
  state.digest_size = algorithm == 1 ? 20 : algorithm == 256 ? 32 : 64;
  state.hash_password = hash_password;
  state.phase = 1;

  if (hash_password != 0) {
    hash_init(&state.work);
  }

  return 0;
}

WASM_EXPORT("password_update") uint32_t password_update(uint32_t length) {
  if (state.phase != 1 || length > sizeof(input)) {
    return 2;
  }

  if (state.hash_password != 0) {
    return hash_update(&state.work, input, length);
  }

  if (length > state.block_size - state.key_length) {
    return 2;
  }

  for (uint32_t i = 0; i < length; i++) {
    state.key[state.key_length + i] = input[i];
  }

  state.key_length += length;
  return 0;
}

WASM_EXPORT("password_finalize") uint32_t password_finalize(void) {
  if (state.phase != 1) {
    return 2;
  }

  uint32_t status = 0;

  if (state.hash_password != 0) {
    status = hash_finalize(&state.work, state.key);

    if (status != 0) {
      return status;
    }
  }

  for (uint32_t i = 0; i < state.block_size; i++) {
    state.key[i] ^= 0x36;
  }

  hash_init(&state.inner);
  status = hash_update(&state.inner, state.key, state.block_size);

  if (status != 0) {
    return status;
  }

  for (uint32_t i = 0; i < state.block_size; i++) {
    state.key[i] ^= 0x36 ^ 0x5c;
  }

  hash_init(&state.outer);
  status = hash_update(&state.outer, state.key, state.block_size);
  wasm_clear(state.key, sizeof(state.key));
  wasm_clear(&state.work, sizeof(state.work));

  if (status != 0) {
    return status;
  }

  hash_copy(&state.salted, &state.inner);
  state.phase = 2;
  return 0;
}

WASM_EXPORT("salt_update") uint32_t salt_update(uint32_t length) {
  if (state.phase != 2 || length > sizeof(input)) {
    return 2;
  }

  return hash_update(&state.salted, input, length);
}

WASM_EXPORT("derive") uint32_t derive(uint32_t index, uint32_t iterations_low, uint32_t iterations_high) {
  uint64_t iterations = ((uint64_t)iterations_high << 32) | iterations_low;

  if ((state.phase != 2 && state.phase != 3) || index == 0 || iterations == 0) {
    return 2;
  }

  state.phase = 3;
  hash_copy(&state.work, &state.salted);
  uint8_t counter[4] = {
    (uint8_t)(index >> 24),
    (uint8_t)(index >> 16),
    (uint8_t)(index >> 8),
    (uint8_t)index,
  };
  uint32_t status = hash_update(&state.work, counter, sizeof(counter));

  if (status != 0) {
    return status;
  }

  status = hmac_finalize();

  if (status != 0) {
    return status;
  }

  for (uint32_t i = 0; i < state.digest_size; i++) {
    output[i] = state.previous[i];
  }

  for (uint64_t round = 1; round < iterations; round++) {
    hash_copy(&state.work, &state.inner);
    status = hash_update(&state.work, state.previous, state.digest_size);

    if (status != 0) {
      return status;
    }

    status = hmac_finalize();

    if (status != 0) {
      return status;
    }

    for (uint32_t i = 0; i < state.digest_size; i++) {
      output[i] ^= state.previous[i];
    }
  }

  wasm_clear(&state.work, sizeof(state.work));
  wasm_clear(state.previous, sizeof(state.previous));
  return 0;
}
