/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#ifndef CIFRANTE_WASM_H
#define CIFRANTE_WASM_H

#include <stddef.h>
#include <stdint.h>

#define WASM_EXPORT(name) __attribute__((export_name(name)))
#define WASM_INPUT_CAPACITY 65536u

static inline void wasm_clear(void *memory, size_t length) {
  volatile uint8_t *bytes = (volatile uint8_t *)memory;

  for (size_t i = 0; i < length; i++) {
    bytes[i] = 0;
  }
}

#endif
