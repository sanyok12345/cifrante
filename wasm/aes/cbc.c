/*
 * Copyright (c) 2026 sanyok12345
 * SPDX-License-Identifier: MIT
 */

#include "modes.h"

static uint32_t transform(uint32_t length, int decrypting) {
  uint32_t status = aes_ready(length, 16);

  if (status != 0) {
    return status;
  }

  uint8_t previous[16];

  for (uint32_t offset = 0; offset < length; offset += 16) {
    uint8_t *block = input + offset;

    if (decrypting) {
      for (unsigned i = 0; i < 16; i++) {
        previous[i] = block[i];
      }

      aes_decrypt(&state.aes, block);

      for (unsigned i = 0; i < 16; i++) {
        block[i] ^= state.iv[i];
        state.iv[i] = previous[i];
      }
    } else {
      for (unsigned i = 0; i < 16; i++) {
        block[i] ^= state.iv[i];
      }

      aes_encrypt(&state.aes, block);

      for (unsigned i = 0; i < 16; i++) {
        state.iv[i] = block[i];
      }
    }
  }

  wasm_clear(previous, sizeof(previous));
  return 0;
}

WASM_EXPORT("cbc_encrypt")
uint32_t cbc_encrypt(uint32_t length) { return transform(length, 0); }

WASM_EXPORT("cbc_decrypt")
uint32_t cbc_decrypt(uint32_t length) { return transform(length, 1); }
