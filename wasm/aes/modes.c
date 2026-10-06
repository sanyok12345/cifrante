/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "modes.h"

State state;
uint8_t input[WASM_INPUT_CAPACITY];
static uint8_t key[32];

WASM_EXPORT("state_ptr")
uint8_t *state_ptr(void) { return (uint8_t *)&state; }

WASM_EXPORT("state_size")
uint32_t state_size(void) { return sizeof(state); }

WASM_EXPORT("key_ptr")
uint8_t *key_ptr(void) { return key; }

WASM_EXPORT("iv_ptr")
uint8_t *iv_ptr(void) { return state.iv; }

WASM_EXPORT("tag_ptr")
uint8_t *tag_ptr(void) { return state.gcm.tag; }

WASM_EXPORT("input_ptr")
uint8_t *input_ptr(void) { return input; }

WASM_EXPORT("input_capacity")
uint32_t input_capacity(void) { return sizeof(input); }

WASM_EXPORT("init")
uint32_t init(uint32_t key_length) {
  wasm_clear(&state, sizeof(state));
  uint32_t status = aes_init(&state.aes, key, key_length);
  state.used = 16;
  wasm_clear(key, sizeof(key));
  return status;
}

uint32_t aes_ready(uint32_t length, uint32_t alignment) {
  if (length > sizeof(input) || length % alignment != 0) {
    return 2;
  }

  if (state.aes.rounds != 10 && state.aes.rounds != 12 && state.aes.rounds != 14) {
    return 3;
  }

  return 0;
}

void aes_increment(uint8_t *counter, unsigned first) {
  uint32_t carry = 1;

  for (unsigned i = 16; i > first; i--) {
    carry += counter[i - 1];
    counter[i - 1] = (uint8_t)carry;
    carry >>= 8;
  }
}

void aes_stream(
  uint8_t *counter,
  uint8_t *stream,
  uint32_t *used,
  uint32_t length,
  unsigned first
) {
  for (uint32_t offset = 0; offset < length;) {
    if (*used == 16) {
      for (unsigned i = 0; i < 16; i++) {
        stream[i] = counter[i];
      }

      aes_encrypt(&state.aes, stream);
      aes_increment(counter, first);
      *used = 0;
    }

    uint32_t count = 16 - *used;

    if (count > length - offset) {
      count = length - offset;
    }

    for (uint32_t i = 0; i < count; i++) {
      input[offset + i] ^= stream[*used + i];
    }

    *used += count;
    offset += count;
  }
}
