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

  uint8_t block[16];
  uint8_t previous[16];
  uint8_t *ciphertext = state.iv;
  uint8_t *plaintext = state.iv + 16;

  for (uint32_t offset = 0; offset < length; offset += 16) {
    for (unsigned i = 0; i < 16; i++) {
      previous[i] = input[offset + i];
      block[i] = previous[i] ^ (decrypting ? plaintext[i] : ciphertext[i]);
    }

    if (decrypting) {
      aes_decrypt(&state.aes, block);
    } else {
      aes_encrypt(&state.aes, block);
    }

    for (unsigned i = 0; i < 16; i++) {
      uint8_t value = block[i] ^ (decrypting ? ciphertext[i] : plaintext[i]);
      input[offset + i] = value;
      ciphertext[i] = decrypting ? previous[i] : value;
      plaintext[i] = decrypting ? value : previous[i];
    }
  }

  wasm_clear(block, sizeof(block));
  wasm_clear(previous, sizeof(previous));
  return 0;
}

WASM_EXPORT("ige_encrypt")
uint32_t ige_encrypt(uint32_t length) { return transform(length, 0); }

WASM_EXPORT("ige_decrypt")
uint32_t ige_decrypt(uint32_t length) { return transform(length, 1); }
