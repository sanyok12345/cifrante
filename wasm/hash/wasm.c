/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "hash.h"

#if defined(HASH_SHA256)
  typedef Sha256 State;
  #define HASH_INIT sha256_init
  #define HASH_UPDATE sha256_update
  #define HASH_FINALIZE sha256_finalize
  #define HASH_OUTPUT_SIZE 32
#elif defined(HASH_SHA512)
  typedef Sha512 State;
  #define HASH_INIT sha512_init
  #define HASH_UPDATE sha512_update
  #define HASH_FINALIZE sha512_finalize
  #define HASH_OUTPUT_SIZE 64
#elif defined(HASH_SHA1)
  typedef Sha1 State;
  #define HASH_INIT sha1_init
  #define HASH_UPDATE sha1_update
  #define HASH_FINALIZE sha1_finalize
  #define HASH_OUTPUT_SIZE 20
#else
  #error "Select a hash algorithm"
#endif

static State state;
static uint8_t input[WASM_INPUT_CAPACITY];
static uint8_t output[HASH_OUTPUT_SIZE];

WASM_EXPORT("state_ptr")
uint32_t state_ptr(void) {
  return (uint32_t)(uintptr_t)&state;
}

WASM_EXPORT("state_size")
uint32_t state_size(void) {
  return sizeof(state);
}

WASM_EXPORT("input_ptr")
uint32_t input_ptr(void) {
  return (uint32_t)(uintptr_t)input;
}

WASM_EXPORT("input_capacity")
uint32_t input_capacity(void) {
  return WASM_INPUT_CAPACITY;
}

WASM_EXPORT("output_ptr")
uint32_t output_ptr(void) {
  return (uint32_t)(uintptr_t)output;
}

WASM_EXPORT("init")
void init(void) {
  HASH_INIT(&state);
  wasm_clear(output, sizeof(output));
}

WASM_EXPORT("update")
uint32_t update(uint32_t length) {
  if (length > WASM_INPUT_CAPACITY) {
    return 2;
  }

  return HASH_UPDATE(&state, input, length);
}

WASM_EXPORT("finalize")
uint32_t finalize(void) {
  return HASH_FINALIZE(&state, output);
}
