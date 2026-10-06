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

typedef uint32_t __attribute__((aligned(1), may_alias)) wasm_u32;
typedef uint64_t __attribute__((aligned(1), may_alias)) wasm_u64;

static inline void wasm_clear(void *memory, size_t length) {
  volatile wasm_u64 *words = (volatile wasm_u64 *)memory;
  volatile uint8_t *bytes = (volatile uint8_t *)memory;
  size_t i = 0;

  for (; i + 8 <= length; i += 8) {
    words[i / 8] = 0;
  }

  for (; i < length; i++) {
    bytes[i] = 0;
  }
}

static inline uint32_t wasm_load32_be(const uint8_t *bytes) {
  return __builtin_bswap32(*(const wasm_u32 *)bytes);
}

static inline uint64_t wasm_load64_be(const uint8_t *bytes) {
  return __builtin_bswap64(*(const wasm_u64 *)bytes);
}

static inline void wasm_store32_be(uint8_t *bytes, uint32_t value) {
  *(wasm_u32 *)bytes = __builtin_bswap32(value);
}

static inline void wasm_store64_be(uint8_t *bytes, uint64_t value) {
  *(wasm_u64 *)bytes = __builtin_bswap64(value);
}

#endif
