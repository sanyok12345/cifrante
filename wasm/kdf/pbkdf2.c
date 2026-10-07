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

typedef union {
  uint32_t words32[8];
  uint64_t words64[8];
} DigestWords;

typedef struct {
  Hash inner;
  Hash outer;
  Hash salted;
  Hash work;
  union {
    uint32_t words32[16];
    uint64_t words64[16];
  } message;
  DigestWords chain;
  DigestWords accumulator;
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

static void begin32(unsigned int words) {
  uint32_t *message = state.message.words32;
  uint32_t *accumulator = state.accumulator.words32;

  for (unsigned int i = 0; i < 16; i++) {
    message[i] = 0;
  }

  message[words] = 0x80000000u;
  message[15] = (64u + words * 4u) * 8u;

  for (unsigned int i = 0; i < words; i++) {
    accumulator[i] = wasm_load32_be(state.previous + i * 4);
    message[i] = accumulator[i];
  }
}

static void rounds32(
  uint64_t count, unsigned int words, void (*compress)(uint32_t *, const uint32_t *)
) {
  uint32_t *message = state.message.words32;
  uint32_t *chain = state.chain.words32;
  uint32_t *accumulator = state.accumulator.words32;
  const uint32_t *inner = state.inner.sha256.words;
  const uint32_t *outer = state.outer.sha256.words;

  for (uint64_t round = 0; round < count; round++) {
    for (unsigned int i = 0; i < 8; i++) {
      chain[i] = inner[i];
    }

    compress(chain, message);

    for (unsigned int i = 0; i < words; i++) {
      message[i] = chain[i];
      chain[i] = outer[i];
    }

    for (unsigned int i = words; i < 8; i++) {
      chain[i] = outer[i];
    }

    compress(chain, message);

    for (unsigned int i = 0; i < words; i++) {
      message[i] = chain[i];
      accumulator[i] ^= chain[i];
    }
  }
}

static void end32(unsigned int words) {
  const uint32_t *accumulator = state.accumulator.words32;

  for (unsigned int i = 0; i < words; i++) {
    wasm_store32_be(output + i * 4, accumulator[i]);
  }
}

static void begin64(void) {
  uint64_t *message = state.message.words64;
  uint64_t *accumulator = state.accumulator.words64;

  for (unsigned int i = 8; i < 16; i++) {
    message[i] = 0;
  }

  message[8] = 0x80ull << 56;
  message[15] = (128u + 64u) * 8u;

  for (unsigned int i = 0; i < 8; i++) {
    accumulator[i] = wasm_load64_be(state.previous + i * 8);
    message[i] = accumulator[i];
  }
}

static void rounds64(uint64_t count) {
  uint64_t *message = state.message.words64;
  uint64_t *chain = state.chain.words64;
  uint64_t *accumulator = state.accumulator.words64;
  const uint64_t *inner = state.inner.sha512.words;
  const uint64_t *outer = state.outer.sha512.words;

  for (uint64_t round = 0; round < count; round++) {
    for (unsigned int i = 0; i < 8; i++) {
      chain[i] = inner[i];
    }

    sha512_compress(chain, message);

    for (unsigned int i = 0; i < 8; i++) {
      message[i] = chain[i];
      chain[i] = outer[i];
    }

    sha512_compress(chain, message);

    for (unsigned int i = 0; i < 8; i++) {
      message[i] = chain[i];
      accumulator[i] ^= chain[i];
    }
  }
}

static void end64(void) {
  for (unsigned int i = 0; i < 8; i++) {
    wasm_store64_be(output + i * 8, state.accumulator.words64[i]);
  }
}

static void iterate_begin(void) {
  switch (state.algorithm) {
    case 1:
      begin32(5);
      break;
    case 256:
      begin32(8);
      break;
    default:
      begin64();
      break;
  }
}

static void iterate_rounds(uint64_t count) {
  switch (state.algorithm) {
    case 1:
      rounds32(count, 5, sha1_compress);
      break;
    case 256:
      rounds32(count, 8, sha256_compress);
      break;
    default:
      rounds64(count);
      break;
  }
}

static void iterate_end(void) {
  switch (state.algorithm) {
    case 1:
      end32(5);
      break;
    case 256:
      end32(8);
      break;
    default:
      end64();
      break;
  }
}

WASM_EXPORT("state_ptr") uint8_t *state_ptr(void) {
  return (uint8_t *)&state;
}

WASM_EXPORT("state_size") uint32_t state_size(void) {
  return sizeof(state);
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

WASM_EXPORT("derive_begin") uint32_t derive_begin(uint32_t index) {
  if ((state.phase != 2 && state.phase != 3) || index == 0) {
    return 2;
  }

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

  iterate_begin();
  state.phase = 4;
  return 0;
}

WASM_EXPORT("derive_rounds") uint32_t derive_rounds(uint32_t count_low, uint32_t count_high) {
  if (state.phase != 4) {
    return 2;
  }

  iterate_rounds(((uint64_t)count_high << 32) | count_low);
  return 0;
}

WASM_EXPORT("derive_end") uint32_t derive_end(void) {
  if (state.phase != 4) {
    return 2;
  }

  iterate_end();
  wasm_clear(&state.work, sizeof(state.work));
  wasm_clear(state.previous, sizeof(state.previous));
  wasm_clear(&state.message, sizeof(state.message));
  wasm_clear(&state.chain, sizeof(state.chain));
  wasm_clear(&state.accumulator, sizeof(state.accumulator));
  state.phase = 3;
  return 0;
}

WASM_EXPORT("derive") uint32_t derive(uint32_t index, uint32_t iterations_low, uint32_t iterations_high) {
  uint64_t iterations = ((uint64_t)iterations_high << 32) | iterations_low;

  if (iterations == 0) {
    return 2;
  }

  uint32_t status = derive_begin(index);

  if (status != 0) {
    return status;
  }

  iterations--;
  status = derive_rounds((uint32_t)iterations, (uint32_t)(iterations >> 32));

  if (status != 0) {
    return status;
  }

  return derive_end();
}
